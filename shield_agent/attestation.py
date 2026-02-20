"""
ClawChain attestation module.

Submits scan results to ``pallet-agent-receipts`` for on-chain audit proof.
Each scan produces an immutable receipt containing:

* **input_hash** — SHA-256 of the scanned contract address
* **output_hash** — SHA-256 of the scan result (address + score + vulns + timestamp)

Full RPC integration requires ``substrate-interface``; until that is wired
the module operates in *stub mode*, returning deterministic hashes without
making real on-chain calls.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

from .models import ScanResult

CLAWCHAIN_RPC = "wss://testnet.clawchain.win"


@dataclass
class AttestationResult:
    """Result of submitting an attestation to ClawChain."""

    success: bool
    tx_hash: str | None
    block_number: int | None
    error: str | None


def compute_scan_hash(scan_result: ScanResult) -> str:
    """Compute a deterministic SHA-256 hash of a scan result.

    The hash covers the fields that uniquely identify the scan output:
    contract address, risk score, vulnerability count, and timestamp.
    """
    data = {
        "address": scan_result.contract_address,
        "risk_score": scan_result.risk_score,
        "vuln_count": len(scan_result.vulnerabilities),
        "timestamp": scan_result.scan_timestamp,
    }
    return hashlib.sha256(
        json.dumps(data, sort_keys=True).encode()
    ).hexdigest()


def attest_scan(
    scan_result: ScanResult,
    agent_id: str = "shield-agent-v0.1",
) -> AttestationResult:
    """Submit a scan result to ClawChain ``pallet-agent-receipts``.

    This creates an immutable on-chain record proving:
    - *This* agent scanned *this* contract
    - At *this* time
    - And produced *this* result (hash)

    .. note::
        Currently operates in **stub mode** — hashes are computed locally
        and returned without an actual RPC call.  Full integration requires
        ``substrate-interface`` and a funded ClawChain testnet account.

    Args:
        scan_result: The completed scan to attest.
        agent_id: Identifier for the scanning agent.

    Returns:
        An :class:`AttestationResult` with the (stubbed) transaction hash.
    """
    input_hash = hashlib.sha256(
        scan_result.contract_address.encode()
    ).hexdigest()
    output_hash = compute_scan_hash(scan_result)

    # TODO: Wire to actual ClawChain RPC when substrateinterface is available
    # from substrateinterface import SubstrateInterface, Keypair
    # substrate = SubstrateInterface(url=CLAWCHAIN_RPC)
    # call = substrate.compose_call(
    #     call_module="AgentReceipts",
    #     call_function="submit_receipt",
    #     call_params={
    #         "agent_id": agent_id,
    #         "input_hash": f"0x{input_hash}",
    #         "output_hash": f"0x{output_hash}",
    #     },
    # )

    print(f"[ClawChain] Attesting scan: {scan_result.contract_address[:10]}...")
    print(f"[ClawChain] Agent: {agent_id}")
    print(f"[ClawChain] Input hash:  0x{input_hash[:16]}...")
    print(f"[ClawChain] Output hash: 0x{output_hash[:16]}...")
    print(
        f"[ClawChain] RPC: {CLAWCHAIN_RPC} (stub mode — testnet connection pending)"
    )

    return AttestationResult(
        success=True,
        tx_hash=f"0x{output_hash[:64]}",  # stub — real tx hash from chain
        block_number=None,
        error=None,
    )
