"""ShieldAgent CLI — scan, monitor, and report on smart contract security."""

from __future__ import annotations

import sys
import time

import click
from rich.console import Console
from rich.table import Table

from .models import RiskLevel
from .scanner import ContractScanner

console = Console()


def _risk_colour(level: RiskLevel) -> str:
    return {
        RiskLevel.LOW: "green",
        RiskLevel.MEDIUM: "yellow",
        RiskLevel.HIGH: "red",
        RiskLevel.CRITICAL: "bold red",
    }.get(level, "white")


@click.group()
@click.version_option(package_name="shield-agent")
def main():
    """🛡️ ShieldAgent — AI-Powered DeFi Security Sentinel."""


@main.command()
@click.argument("contract_address")
@click.option("--network", default="mainnet", help="Target network (mainnet, goerli, etc.)")
@click.option("--dry-run", is_flag=True, help="Skip API calls, validate structure only")
def scan(contract_address: str, network: str, dry_run: bool):
    """Scan a smart contract for vulnerabilities."""
    console.print(f"\n🛡️  Scanning [bold]{contract_address}[/bold] on {network}...\n")

    scanner = ContractScanner()
    result = scanner.scan(contract_address, network=network, dry_run=dry_run)

    if not result.source_available:
        console.print("[yellow]⚠ Source code not available (unverified contract or dry-run)[/yellow]")
        return

    table = Table(title=f"Scan Results — {result.contract_name}")
    table.add_column("Type", style="cyan")
    table.add_column("Severity", justify="center")
    table.add_column("Description")
    table.add_column("Line", justify="right")

    for vuln in result.vulnerabilities:
        colour = _risk_colour(vuln.severity)
        table.add_row(
            vuln.type,
            f"[{colour}]{vuln.severity.value}[/{colour}]",
            vuln.description,
            str(vuln.line_number or "—"),
        )

    console.print(table)
    colour = _risk_colour(result.risk_level)
    console.print(f"\nRisk Score: [{colour}]{result.risk_score}/100 ({result.risk_level.value})[/{colour}]\n")


@main.command()
@click.argument("contract_address")
@click.option("--network", default="mainnet", help="Target network")
@click.option("--interval", default=3600, type=int, help="Scan interval in seconds")
@click.option("--dry-run", is_flag=True, help="Skip API calls")
def monitor(contract_address: str, network: str, interval: int, dry_run: bool):
    """Continuously monitor a smart contract."""
    console.print(f"🔄 Monitoring [bold]{contract_address}[/bold] every {interval}s\n")
    console.print("Press Ctrl+C to stop.\n")

    scanner = ContractScanner()
    try:
        while True:
            result = scanner.scan(contract_address, network=network, dry_run=dry_run)
            ts = time.strftime("%H:%M:%S")
            colour = _risk_colour(result.risk_level)
            console.print(
                f"[dim]{ts}[/dim]  {result.contract_name}  "
                f"[{colour}]{result.risk_level.value}[/{colour}] "
                f"({result.risk_score}/100)  "
                f"vulns={len(result.vulnerabilities)}"
            )
            time.sleep(interval)
    except KeyboardInterrupt:
        console.print("\n✋ Monitoring stopped.")


@main.command()
@click.argument("scan_id")
def report(scan_id: str):
    """Retrieve a previous scan report by ID."""
    # Placeholder — will integrate with ClawChain attestation store in v0.3
    console.print(f"📄 Report retrieval for scan [bold]{scan_id}[/bold] — coming in v0.3 (ClawChain attestation)")
    sys.exit(0)


if __name__ == "__main__":
    main()
