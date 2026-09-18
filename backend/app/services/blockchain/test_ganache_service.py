"""
test_ganache_service.py — Standalone integration test for the GanacheAdapter
                          and BlockchainService against the live local Ganache network.

Tests (no HTTP, no auth, no DB required):
  1. Adapter health check
  2. anchor_hash  — record a sample document hash on-chain
  3. get_anchor_by_reference — retrieve the recorded hash
  4. verify_anchor (correct hash)  → matched=True
  5. verify_anchor (different hash) → matched=False
  6. Duplicate anchor detection    → AnchorAlreadyExistsError

Usage (from backend/ directory):
    python -m app.services.blockchain.test_ganache_service

Prerequisites:
    1. Ganache running:  npx ganache --deterministic
    2. Contract deployed: python -m app.services.blockchain.deploy
    3. .env configured (BLOCKCHAIN_PRIVATE_KEY, BLOCKCHAIN_CONTRACT_ADDRESS, etc.)
"""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.core.logger import configure_logging, get_logger

configure_logging()
logger = get_logger("blockchain.test_ganache_service")

# ---------------------------------------------------------------------------
# Sample test data — stable values used across all test steps
# ---------------------------------------------------------------------------

SAMPLE_DOCUMENT_ID = "test-doc-a1b2c3d4-e5f6-7890-abcd-ef1234567890"
SAMPLE_VAULT_ID    = "test-vault-cafebabe-dead-beef-0000-111122223333"

# Simulate a SHA-256 of an encrypted ciphertext blob
CORRECT_HASH   = "0x" + hashlib.sha256(b"encrypted-ciphertext-sample-payload-v1").hexdigest()
DIFFERENT_HASH = "0x" + hashlib.sha256(b"tampered-ciphertext-completely-different").hexdigest()

# privacy_reference mimics the HMAC the service would produce
PRIVACY_REF = hashlib.sha256(
    f"cipherix:privacy_ref:{SAMPLE_DOCUMENT_ID}:{SAMPLE_VAULT_ID}".encode()
).hexdigest()


# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------

_PASS = "[PASS]"
_FAIL = "[FAIL]"


def _section(title: str) -> None:
    print()
    print("=" * 60)
    print(f"  {title}")
    print("=" * 60)


def _result(label: str, ok: bool, detail: str = "") -> None:
    mark = _PASS if ok else _FAIL
    line = f"  {mark}  {label}"
    if detail:
        line += f"  |  {detail}"
    print(line)
    if not ok:
        print(f"         Detail: {detail}")


# ---------------------------------------------------------------------------
# Test steps
# ---------------------------------------------------------------------------

def test_health(adapter) -> bool:
    _section("Step 1 — Health check")
    try:
        h = adapter.health()
        connected = h.get("connected", False)
        _result("RPC connected",       connected,      f"rpc={h.get('rpc_url')}")
        _result("Chain ID correct",    h.get("chain_id") == 1337, f"chain_id={h.get('chain_id')}")
        _result("Contract address set", bool(h.get("contract_address")), h.get("contract_address", ""))
        _result("Contract owner set",   bool(h.get("contract_owner")),   h.get("contract_owner", ""))
        _result("Block number reported", h.get("block_number") is not None, f"block={h.get('block_number')}")
        print()
        print("  Full health dict:")
        for k, v in h.items():
            print(f"    {k:<22}: {v}")
        return connected
    except Exception as exc:
        _result("Health check", False, str(exc))
        return False


def test_anchor(adapter) -> bool:
    _section("Step 2 — anchor_hash (record on-chain)")
    try:
        receipt = adapter.anchor_hash(
            privacy_reference=PRIVACY_REF,
            integrity_hash=CORRECT_HASH,
        )
        ok = bool(receipt.get("tx_hash")) and receipt.get("block_number", 0) > 0
        _result("anchor_hash returned receipt",  ok,       f"tx={receipt.get('tx_hash', '')[:20]}...")
        _result("Status = anchored",             receipt.get("status") == "anchored", receipt.get("status"))
        _result("Block number > 0",              receipt.get("block_number", 0) > 0,  str(receipt.get("block_number")))
        _result("Gas used reported",             receipt.get("gas_used", 0) > 0,      str(receipt.get("gas_used")))
        print()
        print("  Receipt:")
        for k, v in receipt.items():
            print(f"    {k:<14}: {v}")
        return ok
    except Exception as exc:
        _result("anchor_hash", False, str(exc))
        return False


def test_get_record(adapter) -> bool:
    _section("Step 3 — get_anchor_by_reference (retrieve record)")
    try:
        record = adapter.get_anchor_by_reference(PRIVACY_REF)
        found = record is not None
        _result("Record found",           found,  "")
        if not found:
            return False

        _result("integrity_hash present", bool(record.get("integrity_hash")), record.get("integrity_hash", "")[:20] + "...")
        _result("timestamp > 0",          record.get("timestamp", 0) > 0,     str(record.get("timestamp")))
        _result("recorder is address",    record.get("recorder", "").startswith("0x"), record.get("recorder", ""))
        _result("vault_id is bytes32 hex", record.get("vault_id", "").startswith("0x"), record.get("vault_id", "")[:20] + "...")
        print()
        print("  On-chain record:")
        for k, v in record.items():
            print(f"    {k:<16}: {v}")
        return True
    except Exception as exc:
        _result("get_anchor_by_reference", False, str(exc))
        return False


def test_verify_correct(adapter) -> bool:
    _section("Step 4 — verify_anchor with CORRECT hash")
    try:
        matched = adapter.verify_anchor(
            privacy_reference=PRIVACY_REF,
            integrity_hash=CORRECT_HASH,
            tx_hash="",   # unused by GanacheAdapter
        )
        _result("Correct hash matches on-chain record", matched, f"matched={matched}")
        return matched
    except Exception as exc:
        _result("verify_anchor (correct)", False, str(exc))
        return False


def test_verify_wrong(adapter) -> bool:
    _section("Step 5 — verify_anchor with DIFFERENT (tampered) hash")
    try:
        matched = adapter.verify_anchor(
            privacy_reference=PRIVACY_REF,
            integrity_hash=DIFFERENT_HASH,
            tx_hash="",
        )
        rejected = not matched
        _result("Tampered hash is rejected", rejected, f"matched={matched} (expected False)")
        return rejected
    except Exception as exc:
        _result("verify_anchor (wrong hash)", False, str(exc))
        return False


def test_duplicate_anchor(adapter) -> bool:
    _section("Step 6 — Duplicate anchor prevention")
    from app.core.exceptions import AnchorAlreadyExistsError
    try:
        adapter.anchor_hash(
            privacy_reference=PRIVACY_REF,
            integrity_hash=CORRECT_HASH,
        )
        # Should have raised — no exception means duplicate slipped through
        _result("Duplicate rejected with AnchorAlreadyExistsError", False, "No exception raised!")
        return False
    except AnchorAlreadyExistsError:
        _result("AnchorAlreadyExistsError raised correctly", True, "")
        return True
    except Exception as exc:
        _result("Unexpected exception type", False, f"{type(exc).__name__}: {exc}")
        return False


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    logger.info("=== Cipherix — GanacheAdapter Integration Test ===")

    print()
    print("+----------------------------------------------------------+")
    print("|   Cipherix -- GanacheAdapter / BlockchainService Test    |")
    print("+----------------------------------------------------------+")
    print()
    print(f"  privacy_reference : {PRIVACY_REF[:32]}...")
    print(f"  correct_hash      : {CORRECT_HASH[:32]}...")
    print(f"  different_hash    : {DIFFERENT_HASH[:32]}...")

    # Import here so sys.path is set up first
    from app.services.blockchain.adapters.ganache import GanacheAdapter

    try:
        adapter = GanacheAdapter.from_settings()
    except Exception as exc:
        print()
        print(f"  [FAIL]  Cannot create GanacheAdapter: {exc}")
        print()
        print("  Ensure Ganache is running and .env is correctly configured:")
        print("    npx ganache --deterministic")
        print("    python -m app.services.blockchain.deploy")
        sys.exit(1)

    results = []
    results.append(("Health check",              test_health(adapter)))
    results.append(("anchor_hash (record)",       test_anchor(adapter)))
    results.append(("get_anchor_by_reference",    test_get_record(adapter)))
    results.append(("verify_anchor (correct)",    test_verify_correct(adapter)))
    results.append(("verify_anchor (tampered)",   test_verify_wrong(adapter)))
    results.append(("Duplicate prevention",       test_duplicate_anchor(adapter)))

    # Summary
    print()
    print("=" * 60)
    print("  SUMMARY")
    print("=" * 60)
    all_passed = True
    for name, passed in results:
        mark = _PASS if passed else _FAIL
        print(f"  {mark}  {name}")
        if not passed:
            all_passed = False

    print()
    if all_passed:
        print("  All tests passed. GanacheAdapter is correctly integrated.")
    else:
        print("  One or more tests FAILED. See details above.")

    logger.info("=== Test complete | all_passed=%s ===", all_passed)
    sys.exit(0 if all_passed else 1)


if __name__ == "__main__":
    main()
