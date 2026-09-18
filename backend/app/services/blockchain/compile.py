"""
compile.py — Compile DocumentIntegrity.sol using py-solc-x.

Outputs ABI and bytecode to app/services/blockchain/contracts/build/.

Usage (from backend/ directory):
    python -m app.services.blockchain.compile

py-solc-x downloads the solc binary automatically on first run.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.core.logger import configure_logging, get_logger

configure_logging()
logger = get_logger("blockchain.compile")

SOLIDITY_VERSION = "0.8.20"
CONTRACT_NAME = "DocumentIntegrity"
CONTRACT_FILE = Path(__file__).parent / "contracts" / f"{CONTRACT_NAME}.sol"
BUILD_DIR = Path(__file__).parent / "contracts" / "build"


def compile_contract() -> dict:
    try:
        import solcx
    except ImportError:
        logger.error("py-solc-x not installed. Run: pip install py-solc-x")
        sys.exit(1)

    logger.info("Installing solc %s (cached after first run)...", SOLIDITY_VERSION)
    solcx.install_solc(SOLIDITY_VERSION, show_progress=True)
    solcx.set_solc_version(SOLIDITY_VERSION)
    logger.info("solc %s ready.", SOLIDITY_VERSION)

    source = CONTRACT_FILE.read_text(encoding="utf-8")
    logger.info("Compiling %s ...", CONTRACT_FILE.name)

    compiled = solcx.compile_source(
        source,
        output_values=["abi", "bin"],
        solc_version=SOLIDITY_VERSION,
        optimize=True,
        optimize_runs=200,
    )

    key = f"<stdin>:{CONTRACT_NAME}"
    if key not in compiled:
        available = list(compiled.keys())
        logger.error("Contract '%s' not found in compiled output. Found: %s", CONTRACT_NAME, available)
        sys.exit(1)

    contract_interface = compiled[key]
    abi = contract_interface["abi"]
    bytecode = contract_interface["bin"]

    logger.info(
        "Compilation succeeded | ABI entries=%d | bytecode_bytes=%d",
        len(abi),
        len(bytecode) // 2,
    )
    return {"abi": abi, "bytecode": bytecode}


def save_build_artifacts(abi: list, bytecode: str) -> None:
    BUILD_DIR.mkdir(parents=True, exist_ok=True)

    abi_path = BUILD_DIR / f"{CONTRACT_NAME}.abi.json"
    bin_path = BUILD_DIR / f"{CONTRACT_NAME}.bin"
    combined_path = BUILD_DIR / f"{CONTRACT_NAME}.json"

    abi_path.write_text(json.dumps(abi, indent=2), encoding="utf-8")
    bin_path.write_text(bytecode, encoding="utf-8")

    combined = {
        "contractName": CONTRACT_NAME,
        "solcVersion": SOLIDITY_VERSION,
        "abi": abi,
        "bytecode": bytecode,
    }
    combined_path.write_text(json.dumps(combined, indent=2), encoding="utf-8")

    logger.info("Build artifacts written:")
    logger.info("  ABI      : %s", abi_path)
    logger.info("  Bytecode : %s", bin_path)
    logger.info("  Combined : %s", combined_path)


def main() -> None:
    logger.info("=== Cipherix — Solidity Compiler ===")

    if not CONTRACT_FILE.exists():
        logger.error("Contract source not found: %s", CONTRACT_FILE)
        sys.exit(1)

    result = compile_contract()
    save_build_artifacts(result["abi"], result["bytecode"])

    logger.info("=== Compilation complete. Run 'python -m app.services.blockchain.deploy' next. ===")


if __name__ == "__main__":
    main()
