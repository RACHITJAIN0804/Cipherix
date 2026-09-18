# Cipherix — Local Blockchain Development Setup & Documentation

## Overview

This package contains everything needed to integrate Cipherix with a **Ganache local blockchain** for document integrity anchoring using Web3.py and Solidity.

```
backend/app/services/blockchain/
├── __init__.py            # Canonical package exports
├── config.py              # BlockchainConfig (wraps Cipherix Settings)
├── client.py              # GanacheClient (Web3.py connection layer)
├── web3_abi.py            # DocumentIntegrityContract ABI wrapper
├── blockchain_service.py # Core service layer logic
├── connection_test.py     # Verify Ganache is reachable before deploying
├── compile.py             # Solc contract compiler script
├── deploy.py              # Ganache contract deployment script
├── test_ganache_service.py# Standalone Ganache integration test
├── adapters/              # Adapter implementations (Ganache, Local fallback)
└── contracts/
    ├── DocumentIntegrity.sol   # Solidity smart contract
    └── build/                  # Compiled ABI, bytecode, and deployment info
```

---

## Step 1 — Start Ganache

Run this in a **separate terminal** and keep it running:

```bash
npx ganache --deterministic
```

---

## Step 2 — Compile and Deploy Contract

From the `backend/` directory:

```bash
# Compile Solidity contract
python -m app.services.blockchain.compile

# Deploy contract to Ganache
python -m app.services.blockchain.deploy
```

---

## Step 3 — Run Connection Test & Service Integration Test

```bash
# Connection test
python -m app.services.blockchain.connection_test

# Live service test
python -m app.services.blockchain.test_ganache_service
```
