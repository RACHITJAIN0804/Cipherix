"""
security/__init__.py
--------------------
Cryptographic Key Management package for Cipherix.

This package owns everything related to key lifecycle:

* Generating secure random Vault Keys during vault initialisation.
* Persisting key metadata (never plaintext key material) to disk.
* Validating that key metadata is structurally sound before any
  future cryptographic operation is attempted.

What this package does NOT do (yet):

* Key derivation via Argon2id.
* AES-256-GCM encryption / decryption.
* Key rotation or versioning transitions.
* Any interaction with user passwords or Master Keys.

Those responsibilities will be added in future milestones, one at a
time, without touching the stable interfaces defined here.
"""
