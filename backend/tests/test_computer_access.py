"""
tests/test_computer_access.py
------------------------------
Comprehensive test suite for safe controlled local-computer access system.

Verifies:
1. Computer access disabled by default.
2. Enable computer access.
3. Disable computer access.
4. Unauthorized user cannot access another user's workspace.
5. Valid workspace path accepted.
6. ../ traversal rejected.
7. ..\\ traversal rejected.
8. Absolute Windows path rejected.
9. UNC path rejected.
10. Symlink escape rejected where practical.
11. Unknown action rejected.
12. Arbitrary shell command rejected.
13. Arbitrary Python execution rejected.
14. Read action works.
15. Write action works only when permitted.
16. Approval required for write action.
17. Missing approval rejected.
18. User cannot approve another user's action.
19. Audit event created.
20. Sensitive information is not written to logs.
21. Disabled computer access cannot be bypassed through API.
22. Vault isolation works correctly.
23. Invalid action parameters rejected.
24. Executor only runs registered actions.
"""

import os
import shutil
import uuid
from pathlib import Path

import pytest
from fastapi import status
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.config import settings
from app.core.exceptions import (
    ActionNotAllowedError,
    ComputerAccessDisabledError,
    PathGuardError,
)
from app.database import get_db
from app.database.models import Base, ComputerAccessAuditLog, User, Vault
from app.main import create_app
from app.services.auth_service import AuthService
from app.services.computer_access import (
    ActionRegistry,
    ComputerAccessExecutor,
    PathGuard,
    PermissionService,
)

# ---------------------------------------------------------------------------
# Test Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="function")
def in_memory_engine():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    with engine.connect() as conn:
        conn.execute(text("PRAGMA foreign_keys=ON"))
        conn.commit()
    Base.metadata.create_all(engine)
    return engine


@pytest.fixture(scope="function")
def db_session(in_memory_engine):
    factory = sessionmaker(
        bind=in_memory_engine, autocommit=False, autoflush=False, expire_on_commit=False
    )
    session = factory()
    try:
        yield session
    finally:
        session.rollback()
        session.close()


@pytest.fixture(scope="function")
def client(db_session: Session):
    app = create_app()

    def _override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = _override_get_db
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c


@pytest.fixture(scope="function")
def auth_headers(client: TestClient):
    username = f"user_{uuid.uuid4().hex[:8]}"
    password = "SecurePassword123!"
    reg_resp = client.post(
        "/api/v1/auth/register",
        json={"username": username, "password": password},
    )
    assert reg_resp.status_code == status.HTTP_201_CREATED
    user_id = reg_resp.json()["id"]

    login_resp = client.post(
        "/api/v1/auth/login",
        json={"username": username, "password": password},
    )
    assert login_resp.status_code == status.HTTP_200_OK
    token = login_resp.json()["access_token"]
    return {"Authorization": f"Bearer {token}", "user_id": user_id, "username": username}


@pytest.fixture(scope="function")
def auth_headers_b(client: TestClient):
    username = f"user_b_{uuid.uuid4().hex[:8]}"
    password = "SecurePassword123!"
    reg_resp = client.post(
        "/api/v1/auth/register",
        json={"username": username, "password": password},
    )
    assert reg_resp.status_code == status.HTTP_201_CREATED
    user_id = reg_resp.json()["id"]

    login_resp = client.post(
        "/api/v1/auth/login",
        json={"username": username, "password": password},
    )
    assert login_resp.status_code == status.HTTP_200_OK
    token = login_resp.json()["access_token"]
    return {"Authorization": f"Bearer {token}", "user_id": user_id, "username": username}


# ---------------------------------------------------------------------------
# Test Cases
# ---------------------------------------------------------------------------


def test_1_computer_access_disabled_by_default(client: TestClient, auth_headers: dict):
    headers = {"Authorization": auth_headers["Authorization"]}
    resp = client.get("/api/v1/computer-access/status", headers=headers)
    assert resp.status_code == status.HTTP_200_OK
    assert resp.json()["enabled"] is False


def test_2_enable_computer_access(client: TestClient, auth_headers: dict):
    headers = {"Authorization": auth_headers["Authorization"]}
    resp = client.post(
        "/api/v1/computer-access/toggle",
        headers=headers,
        json={"enabled": True},
    )
    assert resp.status_code == status.HTTP_200_OK
    assert resp.json()["enabled"] is True

    # Verify status endpoint reflects change
    resp_status = client.get("/api/v1/computer-access/status", headers=headers)
    assert resp_status.json()["enabled"] is True


def test_3_disable_computer_access(client: TestClient, auth_headers: dict):
    headers = {"Authorization": auth_headers["Authorization"]}
    # Enable first
    client.post(
        "/api/v1/computer-access/toggle",
        headers=headers,
        json={"enabled": True},
    )
    # Disable
    resp = client.post(
        "/api/v1/computer-access/toggle",
        headers=headers,
        json={"enabled": False},
    )
    assert resp.status_code == status.HTTP_200_OK
    assert resp.json()["enabled"] is False


def test_4_unauthorized_user_cannot_access_another_users_workspace(
    client: TestClient, auth_headers: dict, auth_headers_b: dict
):
    headers_a = {"Authorization": auth_headers["Authorization"]}
    headers_b = {"Authorization": auth_headers_b["Authorization"]}

    # Enable for both
    client.post("/api/v1/computer-access/toggle", headers=headers_a, json={"enabled": True})
    client.post("/api/v1/computer-access/toggle", headers=headers_b, json={"enabled": True})

    # User A creates file
    create_resp = client.post(
        "/api/v1/computer-access/action",
        headers=headers_a,
        json={
            "action": "create_text_file",
            "parameters": {"path": "secret.txt", "content": "user_a_data"},
            "approved": True,
        },
    )
    assert create_resp.status_code == status.HTTP_200_OK

    # User B tries to read user A's relative path in their workspace -> does not exist in User B workspace
    read_resp_b = client.post(
        "/api/v1/computer-access/action",
        headers=headers_b,
        json={
            "action": "read_text_file",
            "parameters": {"path": "secret.txt"},
        },
    )
    # B cannot find secret.txt in B's workspace
    assert read_resp_b.status_code == status.HTTP_400_BAD_REQUEST


def test_5_valid_workspace_path_accepted(tmp_path: Path):
    guard = PathGuard(tmp_path)
    resolved = guard.validate_and_resolve("subfolder/file.txt")
    assert resolved.is_relative_to(tmp_path)
    assert resolved.name == "file.txt"


def test_6_dot_dot_slash_traversal_rejected(tmp_path: Path):
    guard = PathGuard(tmp_path)
    with pytest.raises(PathGuardError):
        guard.validate_and_resolve("../outside.txt")

    with pytest.raises(PathGuardError):
        guard.validate_and_resolve("folder/../../outside.txt")


def test_7_dot_dot_backslash_traversal_rejected(tmp_path: Path):
    guard = PathGuard(tmp_path)
    with pytest.raises(PathGuardError):
        guard.validate_and_resolve("..\\outside.txt")

    with pytest.raises(PathGuardError):
        guard.validate_and_resolve("folder\\..\\..\\outside.txt")


def test_8_absolute_windows_path_rejected(tmp_path: Path):
    guard = PathGuard(tmp_path)
    with pytest.raises(PathGuardError):
        guard.validate_and_resolve("C:\\Windows\\System32\\cmd.exe")

    with pytest.raises(PathGuardError):
        guard.validate_and_resolve("C:/Windows/System32/cmd.exe")


def test_9_unc_path_rejected(tmp_path: Path):
    guard = PathGuard(tmp_path)
    with pytest.raises(PathGuardError):
        guard.validate_and_resolve("\\\\server\\share\\file.txt")

    with pytest.raises(PathGuardError):
        guard.validate_and_resolve("//server/share/file.txt")


def test_10_symlink_escape_rejected(tmp_path: Path):
    outside_dir = tmp_path / "outside"
    outside_dir.mkdir()
    outside_file = outside_dir / "target.txt"
    outside_file.write_text("secret")

    inside_dir = tmp_path / "inside"
    inside_dir.mkdir()
    symlink_path = inside_dir / "link.txt"

    try:
        symlink_path.symlink_to(outside_file)
        guard = PathGuard(inside_dir)
        with pytest.raises(PathGuardError):
            guard.validate_and_resolve("link.txt")
    except OSError:
        # Symlink creation requires developer mode or privileges on Windows; skip if OS prohibits symlink creation
        pytest.skip("Symlink creation not supported in current environment.")


def test_11_unknown_action_rejected(client: TestClient, auth_headers: dict):
    headers = {"Authorization": auth_headers["Authorization"]}
    client.post("/api/v1/computer-access/toggle", headers=headers, json={"enabled": True})

    resp = client.post(
        "/api/v1/computer-access/action",
        headers=headers,
        json={"action": "unregistered_custom_action", "parameters": {}},
    )
    assert resp.status_code == status.HTTP_400_BAD_REQUEST
    assert "not allowed or not registered" in resp.json()["detail"]


def test_12_arbitrary_shell_command_rejected(client: TestClient, auth_headers: dict):
    headers = {"Authorization": auth_headers["Authorization"]}
    client.post("/api/v1/computer-access/toggle", headers=headers, json={"enabled": True})

    # Attempt execute shell command endpoint or action
    resp = client.post(
        "/api/v1/computer-access/action",
        headers=headers,
        json={"action": "execute_shell", "parameters": {"command": "whoami"}},
    )
    assert resp.status_code == status.HTTP_400_BAD_REQUEST


def test_13_arbitrary_python_execution_rejected(client: TestClient, auth_headers: dict):
    headers = {"Authorization": auth_headers["Authorization"]}
    client.post("/api/v1/computer-access/toggle", headers=headers, json={"enabled": True})

    resp = client.post(
        "/api/v1/computer-access/action",
        headers=headers,
        json={"action": "run_python", "parameters": {"code": "import os; os.system('calc')"}},
    )
    assert resp.status_code == status.HTTP_400_BAD_REQUEST


def test_14_read_action_works(client: TestClient, auth_headers: dict):
    headers = {"Authorization": auth_headers["Authorization"]}
    client.post("/api/v1/computer-access/toggle", headers=headers, json={"enabled": True})

    # Create file first
    client.post(
        "/api/v1/computer-access/action",
        headers=headers,
        json={
            "action": "create_text_file",
            "parameters": {"path": "notes/todo.txt", "content": "Hello Cipherix"},
            "approved": True,
        },
    )

    # Read action does not require approval
    read_resp = client.post(
        "/api/v1/computer-access/action",
        headers=headers,
        json={
            "action": "read_text_file",
            "parameters": {"path": "notes/todo.txt"},
        },
    )
    assert read_resp.status_code == status.HTTP_200_OK
    assert read_resp.json()["result"]["content"] == "Hello Cipherix"


def test_15_write_action_works_only_when_permitted(client: TestClient, auth_headers: dict):
    headers = {"Authorization": auth_headers["Authorization"]}
    # Disabled by default -> write action rejected with 403
    resp_disabled = client.post(
        "/api/v1/computer-access/action",
        headers=headers,
        json={
            "action": "create_text_file",
            "parameters": {"path": "test.txt", "content": "data"},
            "approved": True,
        },
    )
    assert resp_disabled.status_code == status.HTTP_403_FORBIDDEN

    # Enable computer access
    client.post("/api/v1/computer-access/toggle", headers=headers, json={"enabled": True})

    # Write action with approved=True works
    resp_enabled = client.post(
        "/api/v1/computer-access/action",
        headers=headers,
        json={
            "action": "create_text_file",
            "parameters": {"path": "test.txt", "content": "data"},
            "approved": True,
        },
    )
    assert resp_enabled.status_code == status.HTTP_200_OK
    assert resp_enabled.json()["result"]["status"] == "created"


def test_16_approval_required_for_write_action(client: TestClient, auth_headers: dict):
    headers = {"Authorization": auth_headers["Authorization"]}
    client.post("/api/v1/computer-access/toggle", headers=headers, json={"enabled": True})

    # Write action without approved=True returns status=approval_required
    resp = client.post(
        "/api/v1/computer-access/action",
        headers=headers,
        json={
            "action": "write_text_file",
            "parameters": {"path": "doc.txt", "content": "new text"},
            "approved": False,
        },
    )
    assert resp.status_code == status.HTTP_200_OK
    data = resp.json()
    assert data["status"] == "approval_required"
    assert data["requires_approval"] is True
    assert data["approval_id"] is not None


def test_17_missing_approval_rejected(client: TestClient, auth_headers: dict):
    headers = {"Authorization": auth_headers["Authorization"]}
    client.post("/api/v1/computer-access/toggle", headers=headers, json={"enabled": True})

    # Propose write without approval flag -> returns approval_required challenge
    resp = client.post(
        "/api/v1/computer-access/action",
        headers=headers,
        json={
            "action": "create_directory",
            "parameters": {"path": "my_folder"},
        },
    )
    assert resp.status_code == status.HTTP_200_OK
    assert resp.json()["status"] == "approval_required"
    assert resp.json()["result"] is None


def test_18_user_cannot_approve_another_users_action(
    client: TestClient, auth_headers: dict, auth_headers_b: dict
):
    headers_a = {"Authorization": auth_headers["Authorization"]}
    headers_b = {"Authorization": auth_headers_b["Authorization"]}

    client.post("/api/v1/computer-access/toggle", headers=headers_a, json={"enabled": True})

    # User A generates approval request
    resp_a = client.post(
        "/api/v1/computer-access/action",
        headers=headers_a,
        json={
            "action": "create_directory",
            "parameters": {"path": "folder_a"},
        },
    )
    approval_id = resp_a.json()["approval_id"]

    # User B tries to approve User A's approval_id -> 403 Forbidden
    approve_b = client.post(
        "/api/v1/computer-access/approve",
        headers=headers_b,
        json={"approval_id": approval_id},
    )
    assert approve_b.status_code == status.HTTP_403_FORBIDDEN


def test_19_audit_event_created(client: TestClient, auth_headers: dict, db_session: Session):
    headers = {"Authorization": auth_headers["Authorization"]}
    client.post("/api/v1/computer-access/toggle", headers=headers, json={"enabled": True})

    # Execute an action
    client.post(
        "/api/v1/computer-access/action",
        headers=headers,
        json={
            "action": "create_text_file",
            "parameters": {"path": "audit_test.txt", "content": "audit data"},
            "approved": True,
        },
    )

    # Check audit log endpoint
    logs_resp = client.get("/api/v1/computer-access/audit-logs", headers=headers)
    assert logs_resp.status_code == status.HTTP_200_OK
    logs = logs_resp.json()
    assert len(logs) >= 1
    action_names = [l["action"] for l in logs]
    assert "create_text_file" in action_names


def test_20_sensitive_information_is_not_written_to_logs(
    client: TestClient, auth_headers: dict
):
    headers = {"Authorization": auth_headers["Authorization"]}
    client.post("/api/v1/computer-access/toggle", headers=headers, json={"enabled": True})

    secret_content = "SUPER_SECRET_PASSWORD_12345"
    client.post(
        "/api/v1/computer-access/action",
        headers=headers,
        json={
            "action": "create_text_file",
            "parameters": {"path": "secret_file.txt", "content": secret_content},
            "approved": True,
        },
    )

    logs_resp = client.get("/api/v1/computer-access/audit-logs", headers=headers)
    logs = logs_resp.json()
    for entry in logs:
        details = entry.get("details_json") or ""
        assert secret_content not in details


def test_21_disabled_computer_access_cannot_be_bypassed_through_api(
    client: TestClient, auth_headers: dict
):
    headers = {"Authorization": auth_headers["Authorization"]}
    # Ensure disabled
    client.post("/api/v1/computer-access/toggle", headers=headers, json={"enabled": False})

    # Try read
    resp_read = client.post(
        "/api/v1/computer-access/action",
        headers=headers,
        json={"action": "read_text_file", "parameters": {"path": "any.txt"}},
    )
    assert resp_read.status_code == status.HTTP_403_FORBIDDEN

    # Try write with approved=True
    resp_write = client.post(
        "/api/v1/computer-access/action",
        headers=headers,
        json={
            "action": "write_text_file",
            "parameters": {"path": "any.txt", "content": "test"},
            "approved": True,
        },
    )
    assert resp_write.status_code == status.HTTP_403_FORBIDDEN


def test_22_vault_isolation_works_correctly(
    client: TestClient, auth_headers: dict, auth_headers_b: dict
):
    headers_a = {"Authorization": auth_headers["Authorization"]}
    headers_b = {"Authorization": auth_headers_b["Authorization"]}

    client.post("/api/v1/computer-access/toggle", headers=headers_a, json={"enabled": True})
    client.post("/api/v1/computer-access/toggle", headers=headers_b, json={"enabled": True})

    # User A creates a vault
    vault_resp_a = client.post(
        "/api/v1/vaults/",
        headers=headers_a,
        json={"name": "Vault User A", "password": "vaultpassword123"},
    )
    assert vault_resp_a.status_code == status.HTTP_201_CREATED
    vault_id_a = vault_resp_a.json()["vault_id"]

    # User B tries to pass user A's vault_id in action request -> 404 Not Found
    action_b = client.post(
        "/api/v1/computer-access/action",
        headers=headers_b,
        json={
            "action": "list_directory",
            "parameters": {"path": ""},
            "vault_id": vault_id_a,
        },
    )
    assert action_b.status_code == status.HTTP_404_NOT_FOUND


def test_23_invalid_action_parameters_rejected(client: TestClient, auth_headers: dict):
    headers = {"Authorization": auth_headers["Authorization"]}
    client.post("/api/v1/computer-access/toggle", headers=headers, json={"enabled": True})

    # Extra disallowed parameters or wrong type
    resp = client.post(
        "/api/v1/computer-access/action",
        headers=headers,
        json={
            "action": "read_text_file",
            "parameters": {"path": "notes.txt", "unexpected_extra_param": 123},
        },
    )
    assert resp.status_code == status.HTTP_400_BAD_REQUEST


def test_24_executor_only_runs_registered_actions(tmp_path: Path, db_session: Session):
    permission_service = PermissionService()
    executor = ComputerAccessExecutor(permission_service=permission_service)

    # Enable for test user
    user_id = str(uuid.uuid4())
    user = User(id=user_id, username=f"user_{user_id[:6]}", password_hash="hash")
    db_session.add(user)
    permission_service.set_computer_access_enabled(db_session, user_id, True)

    # Attempt unregistered action on executor directly -> ActionNotAllowedError
    with pytest.raises(ActionNotAllowedError):
        executor.execute_action(
            db_session,
            user_id,
            request=pytest.importorskip("app.schemas.computer_access").ActionRequest(
                action="malicious_exec", parameters={}
            ),
        )
