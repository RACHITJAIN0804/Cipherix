# Cipherix

Cipherix is a local-first, privacy-focused application for securely storing, managing, and interacting with personal knowledge. It combines end-to-end encrypted document storage with local Retrieval-Augmented Generation (RAG) and blockchain-anchored integrity verification.

## Core Features

- **Secure Vault Architecture**: Local-first document storage utilizing envelope encryption. All files and metadata are encrypted at rest.
- **Cryptographic Security**:
  - **AES-256-GCM** for document and vault encryption.
  - **Argon2id** for robust password hashing and key derivation.
  - **BIP-39 16-word Seed Phrases** for secure emergency account recovery and key re-wrapping.
- **Local AI Knowledge Assistant (RAG)**: Integrates local embeddings and a vector store to enable semantic search and context-aware queries over encrypted documents without relying on external cloud APIs.
- **Integrity Anchoring**: Implements SHA-256 blockchain-based integrity checks to guarantee document immutability and prevent tampering.
- **Audit Logging**: Comprehensive internal tracking of vault interactions for security auditing.

## Technology Stack

- **Backend**: Python, FastAPI, SQLAlchemy, SQLite
- **Frontend**: React 19, Vite, React Router, Framer Motion, Lucide React
- **Security & Cryptography**: AES-256-GCM, Argon2id, BIP-39
- **AI & Data Processing**: Local embeddings, Vector Store (RAG Pipeline)

## Architecture

1. **Backend**: A stateless FastAPI layer handles authentication (JWT), orchestrates the encryption/decryption of the vault, and interfaces with the RAG pipeline.
2. **Vault Storage**: User vaults are strictly compartmentalized. Metadata is managed via isolated SQLite databases within each vault, completely encrypted at rest.
3. **Frontend**: A React application providing secure authentication flows, a 16-word recovery wizard, document management, and a chat interface for the RAG assistant.

## Getting Started

### Prerequisites

- Python 3.10+
- Node.js 18+

### Backend Setup

```bash
cd backend
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -r requirements.txt
python -m uvicorn app.main:app --reload
```

### Frontend Setup

```bash
cd frontend
npm install
npm run dev
```

## Security Model

- **No Plaintext Persistence**: Master keys and passwords are never stored on disk.
- **Zero-Knowledge Architecture**: The backend application code cannot access document contents without the user's active session and derived keys.
- **Offline First**: All operations, including AI inference and document processing, are designed to operate entirely locally to prevent data exfiltration.

## License

MIT License