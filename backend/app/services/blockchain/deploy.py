"""
deploy.py — Deploy DocumentIntegrity.sol to a local Ganache network.

Usage (from backend/ directory):
    python -m app.services.blockchain.deploy

Prerequisites:
    1. Ganache running:  npx ganache --deterministic
    2. Contract compiled: python -m app.services.blockchain.compile
    3. .env configured with BLOCKCHAIN_PRIVATE_KEY and BLOCKCHAIN_DEPLOYER_ADDRESS

After deployment, the script writes the contract address to:
    app/services/blockchain/contracts/build/deployment.json
Set BLOCKCHAIN_CONTRACT_ADDRESS in your .env to this address.
"""
from __future__ import annotations

import json
import sys
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.core.logger import configure_logging, get_logger

configure_logging()
logger = get_logger("blockchain.deploy")

CONTRACT_NAME = "DocumentIntegrity"
BUILD_DIR = Path(__file__).parent / "contracts" / "build"
COMBINED_JSON = BUILD_DIR / f"{CONTRACT_NAME}.json"
DEPLOYMENT_JSON = BUILD_DIR / "deployment.json"


def load_build_artifact() -> dict:
    if not COMBINED_JSON.exists():
        logger.error(
            "Build artifact not found: %s\n"
            "Run 'python -m app.services.blockchain.compile' first.",
            COMBINED_JSON,
        )
        sys.exit(1)

    artifact = json.loads(COMBINED_JSON.read_text(encoding="utf-8"))
    logger.info(
        "Loaded build artifact | contract=%s | solc=%s | abi_entries=%d",
        artifact["contractName"],
        artifact["solcVersion"],
        len(artifact["abi"]),
    )
    return artifact


def deploy(artifact: dict) -> dict:
    from web3 import Web3
    from web3.middleware import ExtraDataToPOAMiddleware
    from eth_account import Account

    from app.services.blockchain.config import get_blockchain_config

    cfg = get_blockchain_config()

    if not cfg.has_private_key:
        logger.error(
            "BLOCKCHAIN_PRIVATE_KEY is not set in .env.\n"
            "Copy the private key for account [0] from Ganache output and add it to .env:\n"
            "  BLOCKCHAIN_PRIVATE_KEY=0x<key>"
        )
        sys.exit(1)

    logger.info("Connecting to Ganache at %s ...", cfg.rpc_url)
    w3 = Web3(Web3.HTTPProvider(cfg.rpc_url, request_kwargs={"timeout": cfg.connection_timeout_seconds}))
    w3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)

    if not w3.is_connected():
        logger.error(
            "Cannot connect to Ganache at '%s'.\n"
            "Make sure Ganache is running: npx ganache --deterministic",
            cfg.rpc_url,
        )
        sys.exit(1)

    chain_id = w3.eth.chain_id
    logger.info("Connected | chain_id=%d | block=%d", chain_id, w3.eth.block_number)

    pk = cfg.private_key
    if not pk.startswith(("0x", "0X")):
        pk = "0x" + pk
    deployer = Account.from_key(pk)
    deployer_address = deployer.address
    logger.info("Deployer address: %s", deployer_address)

    balance_wei = w3.eth.get_balance(deployer_address)
    balance_eth = w3.from_wei(balance_wei, "ether")
    logger.info("Deployer balance: %s ETH", balance_eth)
    if balance_wei == 0:
        logger.error("Deployer account has 0 ETH. Fund it from Ganache.")
        sys.exit(1)

    contract = w3.eth.contract(abi=artifact["abi"], bytecode=artifact["bytecode"])

    nonce = w3.eth.get_transaction_count(deployer_address)
    gas_estimate = contract.constructor().estimate_gas({"from": deployer_address})
    gas_limit = int(gas_estimate * 1.2)
    logger.info("Gas estimate: %d | gas limit (×1.2): %d", gas_estimate, gas_limit)

    tx = contract.constructor().build_transaction({
        "from": deployer_address,
        "nonce": nonce,
        "gas": gas_limit,
        "gasPrice": w3.eth.gas_price,
        "chainId": chain_id,
    })

    signed_tx = w3.eth.account.sign_transaction(tx, private_key=pk)
    tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
    logger.info("Transaction sent | tx_hash=%s", tx_hash.hex())
    logger.info("Waiting for receipt...")

    receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)

    if receipt.status != 1:
        logger.error("Deployment FAILED | status=%d | tx_hash=%s", receipt.status, tx_hash.hex())
        sys.exit(1)

    contract_address = receipt.contractAddress
    logger.info("Contract deployed successfully!")
    logger.info("  Contract address : %s", contract_address)
    logger.info("  Transaction hash : %s", tx_hash.hex())
    logger.info("  Block number     : %d", receipt.blockNumber)
    logger.info("  Gas used         : %d", receipt.gasUsed)

    deployment_info = {
        "contractName": CONTRACT_NAME,
        "contractAddress": contract_address,
        "deployerAddress": deployer_address,
        "txHash": tx_hash.hex(),
        "blockNumber": receipt.blockNumber,
        "gasUsed": receipt.gasUsed,
        "network": cfg.network,
        "chainId": chain_id,
        "rpcUrl": cfg.rpc_url,
        "deployedAt": datetime.now(UTC).isoformat(),
        "solcVersion": artifact["solcVersion"],
        "abi": artifact["abi"],
    }

    BUILD_DIR.mkdir(parents=True, exist_ok=True)
    DEPLOYMENT_JSON.write_text(json.dumps(deployment_info, indent=2), encoding="utf-8")
    logger.info("Deployment info saved to: %s", DEPLOYMENT_JSON)

    logger.info("")
    logger.info("=== ACTION REQUIRED ===")
    logger.info("Add the following to your .env file:")
    logger.info("  BLOCKCHAIN_CONTRACT_ADDRESS=%s", contract_address)
    logger.info("  BLOCKCHAIN_DEPLOYER_ADDRESS=%s", deployer_address)

    return deployment_info


def verify_deployment(deployment_info: dict) -> None:
    from web3 import Web3
    from web3.middleware import ExtraDataToPOAMiddleware
    from app.services.blockchain.config import get_blockchain_config

    cfg = get_blockchain_config()
    w3 = Web3(Web3.HTTPProvider(cfg.rpc_url, request_kwargs={"timeout": cfg.connection_timeout_seconds}))
    w3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)

    contract_address = deployment_info["contractAddress"]
    abi = deployment_info["abi"]

    contract = w3.eth.contract(
        address=Web3.to_checksum_address(contract_address),
        abi=abi,
    )

    try:
        owner = contract.functions.owner().call()
        logger.info("Post-deploy verification OK | owner()=%s", owner)
    except Exception as exc:
        logger.warning("Post-deploy verification call failed: %s", exc)


def main() -> None:
    logger.info("=== Cipherix — Contract Deployment ===")
    artifact = load_build_artifact()
    deployment_info = deploy(artifact)
    verify_deployment(deployment_info)
    logger.info("=== Deployment complete. ===")


if __name__ == "__main__":
    main()
