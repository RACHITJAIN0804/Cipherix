"""
connection_test.py — Verify Ganache connectivity before deploying contracts.

Run from the backend/ directory:
    python -m app.services.blockchain.connection_test

Prerequisites:
    1. pip install -r requirements.txt
    2. Ganache running: npx ganache --deterministic
    3. BLOCKCHAIN_PRIVATE_KEY set in .env
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.core.config import settings
from app.core.logger import configure_logging, get_logger
from app.services.blockchain.client import GanacheClient, GanacheConnectionError
from app.services.blockchain.config import get_blockchain_config

configure_logging()
logger = get_logger("blockchain.connection_test")


def main() -> None:
    logger.info("=== Cipherix — Ganache Connection Test ===")

    cfg = get_blockchain_config()

    if not cfg.enabled:
        logger.warning("blockchain_enabled=False in settings. Set BLOCKCHAIN_ENABLED=True to run this test.")
        sys.exit(0)

    client = GanacheClient(config=cfg)

    logger.info("Attempting connection to: %s", cfg.rpc_url)

    try:
        health = client.health()
    except Exception as exc:
        logger.error("Unexpected failure: %s", exc)
        sys.exit(1)

    if not health["connected"]:
        logger.error("Connection FAILED: %s", health.get("error", "Unknown"))
        logger.error("")
        logger.error("To start Ganache:")
        logger.error("  npm install -g ganache          # install once")
        logger.error("  npx ganache --deterministic     # starts on http://127.0.0.1:8545")
        logger.error("")
        logger.error("Then copy one of the printed private keys into your .env:")
        logger.error("  BLOCKCHAIN_PRIVATE_KEY=0x<key>")
        logger.error("  BLOCKCHAIN_DEPLOYER_ADDRESS=0x<address>")
        sys.exit(1)

    logger.info("Connection OK")
    logger.info("  Chain ID    : %d", health["chain_id"])
    logger.info("  Block number: %d", health["block_number"])
    logger.info("  Accounts    : %d", health["accounts"])
    logger.info("  Network     : %s", health["network"])

    w3 = client.w3
    accounts = client.get_accounts()

    logger.info("")
    logger.info("Available Ganache accounts:")
    for i, addr in enumerate(accounts):
        balance_wei = client.get_balance(addr)
        balance_eth = w3.from_wei(balance_wei, "ether")
        marker = "  <-- set as BLOCKCHAIN_DEPLOYER_ADDRESS" if i == 0 else ""
        logger.info("  [%d] %s  (%s ETH)%s", i, addr, balance_eth, marker)

    if not cfg.has_private_key:
        logger.warning("")
        logger.warning("BLOCKCHAIN_PRIVATE_KEY is not set in .env.")
        logger.warning("Copy the private key for account [0] from Ganache output and add it to .env.")
    else:
        logger.info("")
        logger.info("BLOCKCHAIN_PRIVATE_KEY: set (not shown)")

    logger.info("")
    logger.info("=== Connection test PASSED. Ready for contract deployment. ===")


if __name__ == "__main__":
    main()
