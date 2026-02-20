"""PoC scan of the top 10 most-forked DeFi contracts.

Usage::

    python -m shield_agent.poc_scan [--demo] [--attest] [--dry-run]

Flags:

* ``--demo``    Use built-in vulnerable Solidity snippets (no network).
* ``--attest``  Submit results to ClawChain pallet-agent-receipts.
* ``--dry-run`` Skip all external API calls.
"""

from __future__ import annotations

import argparse
import sys
import time

from rich.console import Console
from rich.table import Table

from .attestation import attest_scan
from .models import RiskLevel, ScanResult
from .scanner import ContractScanner

console = Console()

# ------------------------------------------------------------------ #
# Real top-10 DeFi contracts
# ------------------------------------------------------------------ #
TOP_DEFI_CONTRACTS = [
    {"name": "Uniswap V2 Router", "address": "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D", "network": "ethereum"},
    {"name": "Uniswap V3 Router", "address": "0xE592427A0AEce92De3Edee1F18E0157C05861564", "network": "ethereum"},
    {"name": "Aave V3 Pool", "address": "0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2", "network": "ethereum"},
    {"name": "Compound V3 USDC", "address": "0xc3d688B66703497DAA19211EEdff47f25384cdc3", "network": "ethereum"},
    {"name": "Curve 3Pool", "address": "0xbEbc44782C7dB0a1A60Cb6fe97d0b483032FF1C7", "network": "ethereum"},
    {"name": "MakerDAO DAI", "address": "0x6B175474E89094C44Da98b954EedeAC495271d0F", "network": "ethereum"},
    {"name": "Chainlink ETH/USD", "address": "0x5f4eC3Df9cbd43714FE2740f5E3616155c5b8419", "network": "ethereum"},
    {"name": "1inch Router V5", "address": "0x1111111254EEB25477B68fb85Ed929f73A960582", "network": "ethereum"},
    {"name": "Balancer Vault", "address": "0xBA12222222228d8Ba445958a75a0704d566BF2C8", "network": "ethereum"},
    {"name": "WETH", "address": "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2", "network": "ethereum"},
]

# ------------------------------------------------------------------ #
# Demo contracts with known vulnerabilities
# ------------------------------------------------------------------ #
DEMO_VULNERABLE_CONTRACTS = {
    "ReentrancyDemo": {
        "source": """
pragma solidity ^0.8.0;
contract Vulnerable {
    mapping(address => uint) public balances;

    function withdraw(uint amount) public {
        require(balances[msg.sender] >= amount);
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success);
        balances[msg.sender] -= amount;  // State update AFTER external call!
    }
}
""",
        "address": "0xDEMO_REENTRANCY_000000000000000000",
        "expected_vuln": "reentrancy",
    },
    "TxOriginDemo": {
        "source": """
pragma solidity ^0.8.0;
contract TxOriginVuln {
    address owner;
    function transfer(address to, uint amount) public {
        require(tx.origin == owner, "Not authorized");
        payable(to).transfer(amount);
    }
}
""",
        "address": "0xDEMO_TXORIGIN_000000000000000000",
        "expected_vuln": "access_control",
    },
    "SelfdestructDemo": {
        "source": """
pragma solidity ^0.8.0;
contract Destructible {
    address payable owner;
    function destroy() public {
        require(msg.sender == owner);
        selfdestruct(owner);
    }
}
""",
        "address": "0xDEMO_SELFDESTRUCT_0000000000000000",
        "expected_vuln": "access_control",
    },
    "DelegatecallDemo": {
        "source": """
pragma solidity ^0.8.0;
contract Proxy {
    address public implementation;
    fallback() external payable {
        (bool ok, ) = implementation.delegatecall(msg.data);
        require(ok);
    }
}
""",
        "address": "0xDEMO_DELEGATECALL_00000000000000000",
        "expected_vuln": "access_control",
    },
    "UncheckedMathDemo": {
        "source": """
pragma solidity ^0.8.0;
contract UncheckedMath {
    function unsafeAdd(uint a, uint b) public pure returns (uint) {
        unchecked {
            return a + b;
        }
    }
}
""",
        "address": "0xDEMO_UNCHECKED_000000000000000000",
        "expected_vuln": "integer_overflow",
    },
}


# ------------------------------------------------------------------ #
# Helpers
# ------------------------------------------------------------------ #

def _risk_colour(level: RiskLevel) -> str:
    return {
        RiskLevel.LOW: "green",
        RiskLevel.MEDIUM: "yellow",
        RiskLevel.HIGH: "red",
        RiskLevel.CRITICAL: "bold red",
    }.get(level, "white")


def print_result(name: str, result: ScanResult) -> None:
    """Print a single contract scan result."""
    colour = _risk_colour(result.risk_level)
    src = "✅" if result.source_available else "❌"
    console.print(
        f"  {src} [bold]{name:<22}[/bold]  "
        f"[{colour}]{result.risk_level.value:>8}[/{colour}]  "
        f"score={result.risk_score:>3}/100  "
        f"vulns={len(result.vulnerabilities)}"
    )
    for v in result.vulnerabilities:
        sev_colour = _risk_colour(v.severity)
        console.print(
            f"      [{sev_colour}]{v.severity.value:>8}[/{sev_colour}]  "
            f"{v.type}: {v.description}"
        )


def print_summary_table(
    contracts: list[dict[str, str]],
    results: list[ScanResult],
    title: str = "🛡️ ShieldAgent PoC Scan",
) -> None:
    """Print a summary table of all scan results."""
    console.print()

    table = Table(title=title)
    table.add_column("#", justify="right", style="dim")
    table.add_column("Contract", style="cyan")
    table.add_column("Source", justify="center")
    table.add_column("Vulns", justify="right")
    table.add_column("Score", justify="right")
    table.add_column("Risk", justify="center")

    for i, (contract, result) in enumerate(zip(contracts, results), 1):
        colour = _risk_colour(result.risk_level)
        table.add_row(
            str(i),
            contract["name"],
            "✅" if result.source_available else "❌",
            str(len(result.vulnerabilities)),
            f"{result.risk_score}/100",
            f"[{colour}]{result.risk_level.value}[/{colour}]",
        )

    console.print(table)

    total_vulns = sum(len(r.vulnerabilities) for r in results)
    avg_score = sum(r.risk_score for r in results) / len(results) if results else 0
    console.print(f"\n  Total vulnerabilities found: [bold]{total_vulns}[/bold]")
    console.print(f"  Average risk score: [bold]{avg_score:.1f}/100[/bold]\n")


# ------------------------------------------------------------------ #
# Scan runners
# ------------------------------------------------------------------ #

def run_demo_scan(attest: bool = False) -> list[ScanResult]:
    """Scan built-in demo contracts with known vulnerabilities."""
    console.print("\n🛡️  [bold]ShieldAgent Demo Scan[/bold]")
    console.print(
        f"    Scanning {len(DEMO_VULNERABLE_CONTRACTS)} demo contracts "
        "(local, no network)\n"
    )

    scanner = ContractScanner()
    results: list[ScanResult] = []
    contracts_meta: list[dict[str, str]] = []

    for name, info in DEMO_VULNERABLE_CONTRACTS.items():
        source = info["source"]
        address = info["address"]

        vulns = scanner.analyse_source(source)
        score = scanner.compute_risk_score(vulns)
        level = ScanResult.compute_risk_level(score)

        result = ScanResult(
            contract_address=address,
            contract_name=name,
            scan_timestamp=time.time(),
            vulnerabilities=vulns,
            risk_score=score,
            risk_level=level,
            source_available=True,
        )
        results.append(result)
        contracts_meta.append({"name": name, "address": address})

        print_result(name, result)

        if attest:
            attest_scan(result)

    print_summary_table(
        contracts_meta,
        results,
        title="🛡️ ShieldAgent Demo Scan — Known Vulnerable Contracts",
    )
    return results


def run_poc_scan(
    attest: bool = False,
    dry_run: bool = False,
) -> list[ScanResult]:
    """Scan all top DeFi contracts and print a risk report."""
    console.print("\n🛡️  [bold]ShieldAgent PoC Scan[/bold]")
    console.print(f"    Scanning {len(TOP_DEFI_CONTRACTS)} contracts...\n")

    scanner = ContractScanner()
    results: list[ScanResult] = []

    for contract in TOP_DEFI_CONTRACTS:
        result = scanner.scan(contract["address"], dry_run=dry_run)
        results.append(result)
        print_result(contract["name"], result)
        if not dry_run:
            time.sleep(0.25)  # Rate-limit Etherscan free API

        if attest:
            attest_scan(result)

    print_summary_table(
        TOP_DEFI_CONTRACTS,
        results,
        title="🛡️ ShieldAgent PoC Scan — Top 10 DeFi Contracts",
    )
    return results


# ------------------------------------------------------------------ #
# CLI entry point
# ------------------------------------------------------------------ #

def main(argv: list[str] | None = None) -> None:
    """Parse args and run the appropriate scan."""
    parser = argparse.ArgumentParser(
        description="ShieldAgent PoC vulnerability scanner",
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Use built-in demo vulnerable contracts (no network)",
    )
    parser.add_argument(
        "--attest",
        action="store_true",
        help="Submit results to ClawChain pallet-agent-receipts",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Dry run — skip external API calls",
    )
    args = parser.parse_args(argv)

    if args.demo:
        run_demo_scan(attest=args.attest)
    else:
        run_poc_scan(attest=args.attest, dry_run=args.dry_run)


if __name__ == "__main__":
    main()
