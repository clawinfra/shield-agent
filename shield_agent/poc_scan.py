"""PoC scan of the top 10 most-forked DeFi contracts.

Usage:
    python -m shield_agent.poc_scan [--dry-run]
"""

from __future__ import annotations

import sys
import time

from rich.console import Console
from rich.table import Table

from .models import RiskLevel, ScanResult
from .scanner import ContractScanner

console = Console()

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


def print_summary(results: list[ScanResult]) -> None:
    """Print a summary table of all scan results."""
    console.print()

    table = Table(title="🛡️ ShieldAgent PoC Scan — Top 10 DeFi Contracts")
    table.add_column("#", justify="right", style="dim")
    table.add_column("Contract", style="cyan")
    table.add_column("Source", justify="center")
    table.add_column("Vulns", justify="right")
    table.add_column("Score", justify="right")
    table.add_column("Risk", justify="center")

    for i, (contract, result) in enumerate(zip(TOP_DEFI_CONTRACTS, results), 1):
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


def run_poc_scan(dry_run: bool = False) -> list[ScanResult]:
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

    print_summary(results)
    return results


if __name__ == "__main__":
    dry = "--dry-run" in sys.argv
    run_poc_scan(dry_run=dry)
