# Cipherix

> **Privacy-First AI Knowledge Vault with End-to-End Encryption**

Cipherix is an open-source, local-first platform designed to securely store, manage, and interact with personal knowledge using modern cryptography and AI.

The project combines encrypted document storage, Retrieval-Augmented Generation (RAG), local Large Language Models (LLMs), and blockchain-inspired cryptographic identity into a single privacy-focused application.

---

## ✨ Vision

Most AI assistants require users to upload sensitive information to cloud services.

Cipherix follows a different philosophy:

- 🔒 Your data remains on your device.
- 🤖 AI runs locally whenever possible.
- 📄 Documents are encrypted at rest.
- 🔑 Users own their encryption keys.
- 🧠 AI understands your knowledge without compromising privacy.

---

## Planned Features

### Secure Vault

- AES-256 encrypted document storage
- Password-based vault protection
- Secure file management
- Metadata indexing

### AI Knowledge Assistant

- Local Retrieval-Augmented Generation (RAG)
- Local LLM support
- Semantic document search
- Context-aware document conversations

### Cryptographic Identity

- Seed phrase generation
- Deterministic key derivation
- Digital signatures
- File integrity verification

### Privacy

- Local-first architecture
- No mandatory cloud services
- User-controlled encryption keys
- Secure document storage

---

## Technology Stack

### Backend

- Python
- FastAPI
- SQLite
- SQLAlchemy

### Security

- AES-256 Encryption
- Argon2id
- SHA-256
- Secure Random Number Generation

### AI

- Ollama
- ChromaDB / FAISS
- Sentence Transformers

### Frontend

- React
- Tauri

---

## Project Status

🚧 **Early Development**

Cipherix is currently under active development.

The initial focus is building a secure encrypted vault before introducing AI-powered features.

---

## Roadmap

- [ ] Project Setup
- [ ] Secure Vault
- [ ] AES-256 Encryption
- [ ] Seed Phrase Generation
- [ ] Metadata Database
- [ ] File Management
- [ ] REST API
- [ ] Desktop Application
- [ ] Local RAG
- [ ] Local AI Assistant
- [ ] Cryptographic Identity
- [ ] Document Signing

---

## Repository Structure

```
Cipherix/

backend/
frontend/
vaults/
models/
vector_db/
docs/
scripts/
```

---

## Contributing

Contributions, discussions, and feature suggestions are welcome.

Please open an issue before submitting large feature requests.

---

## License

This project is licensed under the MIT License.