# Cipherix Blockchain Document Integrity Documentation

## 1. Blockchain Architecture

Cipherix integrates EVM-compatible blockchain document integrity anchoring and verification using a hybrid architecture:

```
+-----------------------------------------------------------------------------------+
|                                  Cipherix UI                                      |
|                     (React / Vite - Activity Log & Integrity Modal)               |
+-----------------------------------------------------------------------------------+
                                         |
                                         v  REST API (JWT Auth)
+-----------------------------------------------------------------------------------+
|                                FastAPI Backend                                    |
|  +---------------------+   +---------------------+   +--------------------------+ |
|  |   DocumentService   |-->|  BlockchainService  |-->|  AuditService            | |
|  +---------------------+   +---------------------+   | (ComputerAccessAuditLog) | |
|             |                         |              +--------------------------+ |
|             v                         v                                           |
|       AES-256 Encrypt          Web3 Adapter                                       |
|     Ciphertext Storage   (Ganache / Local In-Memory)                               |
+-----------------------------------------------------------------------------------+
                                         |
                                         v  JSON-RPC (Port 8545)
+-----------------------------------------------------------------------------------+
|                             Ganache Local Blockchain                              |
|                                (EVM Chain ID 1337)                                |
|                                        |                                          |
|                                        v                                          |
|                    DocumentIntegrity.sol Smart Contract                           |
|                      `recordHash(bytes32, bytes32)`                               |
+-----------------------------------------------------------------------------------+
```

---

## 2. Why Blockchain is Used

Cipherix uses blockchain technology to guarantee **tamper-evident document integrity** without relying on a centralized authority.
- **Immutable Timestamped Proof**: Once a document ciphertext hash is recorded on-chain, neither the user, application, nor server admin can alter or backdate it.
- **Zero-Knowledge Integrity Verification**: Verifies whether an encrypted document stored locally on disk has been corrupted or modified without exposing the document content or encryption keys.

---

## 3. What is Stored On-Chain

Only non-reversible, non-sensitive cryptographic hashes and metadata are recorded on-chain:
- **Privacy Reference (`bytes32`)**: HMAC-SHA256 hash of `user_id` and `document_id` derived using the server's `JWT_SECRET_KEY`.
- **Integrity Hash (`bytes32`)**: SHA-256 cryptographic checksum calculated over the **encrypted ciphertext blob**.
- **Block Timestamp (`uint256`)**: EVM block timestamp.
- **Recorder Address (`address`)**: The Ethereum wallet address that submitted the transaction.

---

## 4. What is NOT Stored On-Chain

Cipherix strictly enforces data privacy. The following are **NEVER** placed on the blockchain or in audit logs:
- ❌ Plaintext document contents or text extracts
- ❌ Document filenames or raw metadata
- ❌ User passwords, AES encryption keys, master keys, or vault keys
- ❌ Seed phrases or recovery keys
- ❌ User identity identifiers in plaintext

---

## 5. SHA-256 Hashing Process

1. When a document is uploaded, it is encrypted at rest using **AES-256-GCM**.
2. Cipherix calculates the **SHA-256 checksum over the encrypted ciphertext blob** (not the plaintext):
   $$\text{Integrity Hash} = \text{SHA-256}(\text{Encrypted Ciphertext})$$
3. The resulting SHA-256 hex string is saved in SQLite database metadata and submitted to the blockchain contract via `recordHash(privacy_reference, integrity_hash)`.

---

## 6. Document Verification Process

When a user initiates **"Verify Integrity"**:
1. Cipherix verifies vault ownership and authorization for the current user.
2. Reads the encrypted ciphertext blob from disk and recalculates its live SHA-256 hash:
   $$\text{Current Hash} = \text{SHA-256}(\text{Disk Ciphertext})$$
3. Queries the `DocumentIntegrity` smart contract on-chain using the document's `privacy_reference` to retrieve the original anchored `integrity_hash`.
4. Compares:
   - `Current Hash == Stored DB Hash` (Local Disk Check)
   - `Current Hash == On-Chain Blockchain Hash` (Blockchain Ledger Check)
5. Returns a detailed verification result response (`verified: true/false`, `blockchain_match`, `integrity_match`, `tx_hash`, `network`).
6. Logs the operation into the unified Cipherix audit log system (`ComputerAccessAuditLog`).

---

## 7. Solidity Contract Role

The `DocumentIntegrity.sol` contract serves as an EVM registry:
- Contract File: `backend/app/services/blockchain/contracts/DocumentIntegrity.sol`
- Key Functions:
  - `recordHash(bytes32 privacyRef, bytes32 integrityHash)`: Records an anchor hash if not already recorded. Emits `HashRecorded`.
  - `getRecord(bytes32 privacyRef)`: Returns `(bytes32 integrityHash, uint256 timestamp, address recorder)`.
  - `verifyHash(bytes32 privacyRef, bytes32 integrityHash)`: Returns `bool` indicating if the provided hash matches on-chain.

---

## 8. Ganache Setup

Cipherix supports local EVM development using **Ganache**:
- Port: `8545`
- Chain ID: `1337`
- Deterministic mode ensures predictable account addresses and private keys across restarts.

---

## 9. Web3.py Integration

The `GanacheAdapter` class (`backend/app/services/blockchain/adapters/ganache.py`) uses `web3.py`:
- Connects to RPC via `web3.HTTPProvider`.
- Loads compiled Solidity ABI from `backend/app/services/blockchain/abi/DocumentIntegrity.json`.
- Automatically signs and broadcasts transactions using the configured deployer private key.

---

## 10. Required Environment Variables

Add the following to `backend/.env`:

```env
# Blockchain Feature Flags & Provider
BLOCKCHAIN_ENABLED=true
BLOCKCHAIN_PROVIDER=ganache        # Options: 'ganache' (live RPC) or 'local' (in-memory)
BLOCKCHAIN_NETWORK=ganache-local
BLOCKCHAIN_RPC_URL=http://127.0.0.1:8545
BLOCKCHAIN_CHAIN_ID=1337

# Contract & Account Config (from ganache --deterministic output)
BLOCKCHAIN_DEPLOYER_ADDRESS=0x90F8bf6A479f320ead074411a4B0e7944Ea8c9C1
BLOCKCHAIN_PRIVATE_KEY=0x4f3edf983ac636a65a842ce7c78d9aa706d3b113bce9c46f30d7d21715b23b1d
BLOCKCHAIN_CONTRACT_ADDRESS=0xcfeb869f69431e42cdb54a4f4f105c19c080a601
```

---

## 11. Required Installation Commands

### Backend Installation:
```bash
cd backend
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

### Frontend Installation:
```bash
cd frontend
npm install
```

---

## 12. How to Start Ganache

```bash
npx ganache --deterministic --port 8545 --chain.chainId 1337
```

---

## 13. How to Start the Cipherix Backend

```bash
cd backend
python -m uvicorn app.main:app --reload --port 8000
```

---

## 14. How to Start the Cipherix Frontend

```bash
cd frontend
npm run dev
```

---

## 15. How to Deploy / Redeploy the Contract

If Ganache is restarted or contract is recompiled:

```bash
cd backend
python -m app.services.blockchain.deploy
```

The script compiles `DocumentIntegrity.sol`, deploys it to Ganache, and prints the deployed contract address to set in `BLOCKCHAIN_CONTRACT_ADDRESS`.

---

## 16. How to Run Tests

### Run All Backend Tests:
```bash
cd backend
python -m pytest tests/
```

### Run Blockchain Test Suite:
```bash
cd backend
python -m pytest tests/test_blockchain_audit_logging.py tests/test_document_verification_api.py tests/test_document_upload_blockchain.py tests/test_blockchain.py tests/test_step10_end_to_end_verification.py
```

### Run Frontend Build Check:
```bash
cd frontend
npm run build
```
