Cipherix
Secure Documents. Private Intelligence. Verifiable Integrity.

Cipherix is a local-first, privacy-focused document vault that combines secure document encryption, private local Retrieval-Augmented Generation (RAG), account recovery, and blockchain-backed document integrity verification.

The project is designed around one principle: your documents and sensitive data should remain under your control while still being searchable, intelligent, and verifiable.

Core Features
Encrypted Document Vault — Documents are encrypted before being stored using AES-256-GCM.
Secure Authentication — JWT-based authentication with password hashing and key derivation using Argon2id.
16-Word Recovery Seed — Custom 16-word recovery mechanism for securely recovering account access.
Local RAG Assistant — Ask questions about your documents using locally generated embeddings and a local LLM.
Semantic Search — Search documents by meaning rather than relying only on exact keywords.
Blockchain Integrity Verification — SHA-256 hashes of encrypted documents can be anchored to a local blockchain for later integrity verification.
Audit Logging — Security-relevant vault activity is recorded for auditing.
Local-First Architecture — AI inference, document processing, storage, and blockchain functionality are designed to operate locally.


How Cipherix Works

                 ┌─────────────────────┐
                 │      User Login     │
                 └──────────┬──────────┘
                            │
                            ▼
                 ┌─────────────────────┐
                 │   Secure Vault     │
                 └──────────┬──────────┘
                            │
                     Upload Document
                            │
                            ▼
                 ┌─────────────────────┐
                 │   AES-256-GCM       │
                 │     Encryption      │
                 └──────────┬──────────┘
                            │
                ┌───────────┴───────────┐
                │                       │
                ▼                       ▼
       ┌─────────────────┐     ┌─────────────────┐
       │ Encrypted Vault │     │   SHA-256 Hash  │
       │     Storage     │     └────────┬────────┘
       └────────┬────────┘              │
                │                       ▼
                │              ┌─────────────────┐
                │              │   Blockchain    │
                │              │ Integrity Anchor│
                │              └─────────────────┘
                │
                ▼
       ┌─────────────────┐
       │ Document        │
       │ Processing      │
       └────────┬────────┘
                │
                ▼
       ┌─────────────────┐
       │ Embeddings +    │
       │ ChromaDB        │
       └────────┬────────┘
                │
                ▼
       ┌─────────────────┐
       │ Local RAG       │
       │ + Ollama        │
       └────────┬────────┘
                │
                ▼
             Answer


Security Architecture

Cipherix separates document confidentiality, account recovery, AI retrieval, and blockchain integrity.

Document Encryption

Documents are encrypted using AES-256-GCM before being stored in the local vault.


Document
   ↓
AES-256-GCM
   ↓
Encrypted Document
   ↓
Local Vault


Password Security

Passwords are protected using Argon2id for password hashing and key derivation.

Recovery Seed

Cipherix implements a custom 16-word recovery seed mechanism using the BIP-39 English wordlist together with a SHA-256-based checksum.

The recovery seed is intended for account recovery and key re-wrapping.

Sensitive recovery material is not intended to be stored in:

Browser local storage
URLs
Cookies
Logs
Blockchain records
Vector databases
Source code
Blockchain Integrity

The blockchain layer does not store the actual document.

Instead:

Encrypted Document
       ↓
     SHA-256
       ↓
 Document Hash
       ↓
 Local Blockchain

 During verification, Cipherix calculates the document hash again and compares it with the blockchain-anchored value.

 Current Document
       ↓
    SHA-256
       ↓
Current Hash
       ↓
Compare
       ↓
Blockchain Hash


A matching hash indicates that the checked file matches the previously recorded integrity value. A mismatch indicates that the file has changed or that the stored data no longer corresponds to the recorded hash.

The blockchain layer does not store:

Document contents
Passwords
Recovery seeds
Encryption keys
Embeddings


Local AI / RAG

Cipherix includes a local Retrieval-Augmented Generation pipeline.

The general flow is:

Document
   ↓
Text Extraction
   ↓
Chunking
   ↓
Sentence Transformer Embeddings
   ↓
ChromaDB
   ↓
Semantic Retrieval
   ↓
Relevant Context
   ↓
Ollama Local LLM
   ↓
Answer

This allows users to ask questions about their stored documents without sending document content to an external AI service as part of the intended local workflow.Technology Stack
Frontend
React
Vite
React Router
Framer Motion
Lucide React
Backend
Python
FastAPI
SQLAlchemy
SQLite
JWT Authentication
Security
AES-256-GCM
Argon2id
SHA-256
Custom 16-word recovery seed
Secure key derivation and recovery mechanisms
AI / RAG
Sentence Transformers
ChromaDB
Ollama
Local embedding generation
Semantic document retrieval
Blockchain
Solidity
Ganache
Web3.py
py-solc-x
Local smart contract deployment
SHA-256 document integrity anchoring


System Architecture

┌─────────────────────────────────────────────────────┐
│                    React Frontend                   │
│                                                     │
│ Auth │ Vaults │ Documents │ RAG │ Recovery │ Audit │
└───────────────────────┬─────────────────────────────┘
                        │
                        │ REST API
                        ▼
┌─────────────────────────────────────────────────────┐
│                   FastAPI Backend                   │
│                                                     │
│ Authentication │ Vault │ Encryption │ RAG │ Security│
│ Blockchain │ Recovery │ Audit Logging              │
└───────────────┬──────────────┬──────────────┬───────┘
                │              │              │
                ▼              ▼              ▼
        ┌─────────────┐ ┌─────────────┐ ┌─────────────┐
        │ Encrypted   │ │  ChromaDB   │ │   SQLite    │
        │ Vault Files │ │ Vector Data │ │  Metadata   │
        └─────────────┘ └─────────────┘ └─────────────┘
                              │
                              ▼
                       ┌─────────────┐
                       │   Ollama    │
                       │ Local LLM   │
                       └─────────────┘

                ┌────────────────────────┐
                │   Local Blockchain     │
                │ Solidity + Ganache     │
                │      + Web3.py         │
                └────────────────────────┘



Account Recovery

Cipherix provides a dedicated recovery flow based on a 16-word recovery seed.

Recovery Flow

Generate Recovery Seed
          ↓
Display 16 Words
          ↓
User Confirms Selected Words
          ↓
Secure Recovery Setup
          ↓
Account Recovery When Needed

For account recovery:

Username
   +
16-Word Recovery Seed
   +
New Password
   ↓
Recovery Validation
   ↓
Account Access Restored

The recovery seed should be treated as highly sensitive information and stored securely by the user outside the application.


Blockchain Integrity Verification

Cipherix uses blockchain as an integrity-verification layer, not as a document-storage system.

When a document is uploaded


1. Document is encrypted.
2. Encrypted document is stored locally.
3. SHA-256 hash is calculated.
4. Hash and relevant metadata are anchored to the blockchain.

When a document is verified

1. Current encrypted document is read.
2. SHA-256 hash is calculated again.
3. Blockchain record is retrieved.
4. Both hashes are compared.
5. Verification result is returned.

This provides a tamper-evident mechanism for detecting changes to encrypted document files.

Getting Started
Prerequisites

Install the following:

Python 3.10+
Node.js 18+
npm
Git
Ollama
Ganache or another compatible local Ethereum development environment


Clone the Repository
git clone https://github.com/RACHITJAIN0804/Cipherix.git
cd Cipherix

Backend Setup

Navigate to the backend:
cd backend


Create a virtual environment:
python -m venv .venv

Activate it on Windows:
.\.venv\Scripts\Activate.ps1

Install dependencies:
pip install -r requirements.txt

Configure the environment variables using the provided example environment file.

Start the FastAPI development server:
uvicorn app.main:app --reload

The backend will be available locally through the configured FastAPI port.


Frontend Setup

Open another terminal and navigate to the frontend:
cd frontend

Install dependencies:
npm install

Start the development server:
npm run dev

Local AI Setup

Install Ollama and download a supported local model.

For example:
ollama pull llama3.2:1b

Verify the installed models:
ollama list

Cipherix can then communicate with the local Ollama service for RAG generation.

Blockchain Setup

Cipherix uses a local blockchain development environment for integrity anchoring.

The blockchain workflow consists of:

Solidity Smart Contract
        ↓
Compile
        ↓
Deploy to Local Blockchain
        ↓
Contract Address + ABI
        ↓
FastAPI Blockchain Service
        ↓
Document Integrity Operations

The local blockchain is intended for development and demonstration rather than production cryptocurrency infrastructure.

Testing

The project includes backend tests covering major application functionality.

Latest full backend test result:
255 passed
1 skipped
0 failed

The frontend production build also completes successfully using:
npm run build


Project Structure

Cipherix/
│
├── backend/
│   ├── app/
│   └── tests/
│
├── frontend/
│
├── docs/
│
├── .env.example
├── .gitignore
├── LICENSE
├── README.md
├── docker-compose.yml
└── requirements.txt

Runtime-generated data such as local environments, databases, vector stores, encrypted vault data, logs, dependency folders, and other machine-specific artifacts are excluded from version control where appropriate.

Security Principles

Cipherix follows several security principles:

Encrypt sensitive documents before local storage.
Use authenticated encryption with AES-256-GCM.
Use Argon2id for password security and key derivation.
Keep recovery material separate from blockchain data.
Do not place recovery seeds in URLs or browser storage.
Do not store document contents on the blockchain.
Do not store passwords, encryption keys, or recovery seeds on the blockchain.
Keep AI processing local through local embeddings, vector storage, and Ollama.
Use cryptographic hashes for document integrity verification.
Keep generated runtime artifacts out of source control.


Privacy Model

Cipherix is designed as a local-first application.

The architecture aims to keep the following components under the user's local environment:

Documents
Encryption
Vault Storage
Embeddings
Vector Search
LLM Inference
Blockchain Integrity Records

The exact privacy characteristics of a deployment depend on how the application and its surrounding infrastructure are configured.

Future Scope

Possible future improvements include:

Windows .exe distribution
Improved desktop packaging
Hardware-backed key protection
Additional local LLM support
Advanced document formats
More granular audit controls
Enhanced blockchain verification workflows
Automated encrypted backups
Multi-device synchronization with end-to-end encryption
Additional recovery mechanisms
Production-grade deployment configuration

License

This project is licensed under the MIT License.

See the LICENSE file for details.


Author

Rachit Jain