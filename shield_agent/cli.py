"""ShieldAgent CLI — scan, monitor, and report on smart contract security."""

from __future__ import annotations

import json
import sys
import time

import click
from rich.console import Console
from rich.table import Table

from .models import RiskLevel, PalletScanResult, ChainAuditReport
from .scanner import ContractScanner
from .substrate_scanner import SubstrateScanner

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


@main.command("scan-pallet")
@click.argument("pallet_dir")
@click.option("--attest", is_flag=True, help="Attest results to ClawChain pallet-agent-receipts")
@click.option("--output", type=click.Choice(["text", "json"]), default="text", help="Output format")
def scan_pallet(pallet_dir: str, attest: bool, output: str):
    """Audit a single Substrate pallet directory for vulnerabilities."""
    from .attestation import attest_scan

    scanner = SubstrateScanner()
    result = scanner.analyse_pallet(pallet_dir)

    if output == "json":
        data = {
            "pallet_name": result.pallet_name,
            "pallet_path": result.pallet_path,
            "risk_score": result.risk_score,
            "risk_level": result.risk_level.value,
            "files_scanned": result.files_scanned,
            "has_benchmarks": result.has_benchmarks,
            "vulnerabilities": [
                {
                    "type": v.type,
                    "description": v.description,
                    "severity": v.severity.value,
                    "line_number": v.line_number,
                    "code_snippet": v.code_snippet,
                }
                for v in result.vulnerabilities
            ],
        }
        click.echo(json.dumps(data, indent=2))
        return

    colour = _risk_colour(result.risk_level)
    bench_icon = "✅" if result.has_benchmarks else "❌"
    console.print(f"\n🛡️  Pallet Audit — [bold]{result.pallet_name}[/bold]")
    console.print(f"   Path:        {result.pallet_path}")
    console.print(f"   Files:       {result.files_scanned}")
    console.print(f"   Benchmarks:  {bench_icon}")
    console.print(f"   Risk:        [{colour}]{result.risk_level.value} ({result.risk_score}/100)[/{colour}]\n")

    if result.vulnerabilities:
        table = Table(title=f"Findings — {result.pallet_name}")
        table.add_column("Type", style="cyan", no_wrap=True)
        table.add_column("Severity", justify="center")
        table.add_column("Description")
        table.add_column("Line", justify="right")

        for v in result.vulnerabilities:
            vc = _risk_colour(v.severity)
            table.add_row(
                v.type,
                f"[{vc}]{v.severity.value}[/{vc}]",
                v.description,
                str(v.line_number or "—"),
            )
        console.print(table)
    else:
        console.print("[green]✅ No vulnerabilities found.[/green]")

    if attest:
        from .attestation import attest_scan as _attest
        # Wrap PalletScanResult into ScanResult-compatible shape for attestation stub
        from .models import ScanResult
        sr = ScanResult(
            contract_address=result.pallet_path,
            contract_name=result.pallet_name,
            scan_timestamp=result.scan_timestamp,
            vulnerabilities=result.vulnerabilities,
            risk_score=result.risk_score,
            risk_level=result.risk_level,
            source_available=True,
        )
        att = _attest(sr, agent_id="shield-agent-substrate-v1")
        if att.success:
            console.print(f"\n📜 Attested on-chain: [dim]{att.tx_hash}[/dim]")
        else:
            console.print(f"\n[red]Attestation failed: {att.error}[/red]")


@main.command("audit-chain")
@click.argument("pallets_dir")
@click.option("--attest", is_flag=True, help="Attest results to ClawChain pallet-agent-receipts")
@click.option("--output", type=click.Choice(["text", "json"]), default="text", help="Output format")
def audit_chain(pallets_dir: str, attest: bool, output: str):
    """Audit all Substrate pallets under a directory (full chain audit).

    Exits with code 1 if any CRITICAL or HIGH findings are present.
    """
    scanner = SubstrateScanner()
    report = scanner.scan_chain(pallets_dir)

    if output == "json":
        data = {
            "chain_name": report.chain_name,
            "scan_timestamp": report.scan_timestamp,
            "overall_risk": report.overall_risk.value,
            "total_vulnerabilities": report.total_vulnerabilities,
            "critical_count": report.critical_count,
            "high_count": report.high_count,
            "pallets": [
                {
                    "pallet_name": p.pallet_name,
                    "risk_score": p.risk_score,
                    "risk_level": p.risk_level.value,
                    "files_scanned": p.files_scanned,
                    "has_benchmarks": p.has_benchmarks,
                    "vulnerability_count": len(p.vulnerabilities),
                    "vulnerabilities": [
                        {
                            "type": v.type,
                            "description": v.description,
                            "severity": v.severity.value,
                            "line_number": v.line_number,
                        }
                        for v in p.vulnerabilities
                    ],
                }
                for p in report.pallets
            ],
        }
        click.echo(json.dumps(data, indent=2))
        if report.critical_count > 0 or report.high_count > 0:
            sys.exit(1)
        return

    overall_colour = _risk_colour(report.overall_risk)
    console.print(f"\n🛡️  [bold]ClawChain Pallet Audit[/bold] — {report.chain_name}")
    console.print(f"   Pallets scanned: {len(report.pallets)}")
    console.print(f"   Total findings:  {report.total_vulnerabilities}")
    console.print(
        f"   Overall risk:    [{overall_colour}]{report.overall_risk.value}[/{overall_colour}]"
        f"  (CRITICAL={report.critical_count}, HIGH={report.high_count})\n"
    )

    table = Table(title="Per-Pallet Summary")
    table.add_column("#", justify="right", style="dim")
    table.add_column("Pallet", style="cyan")
    table.add_column("Files", justify="right")
    table.add_column("Benchmarks", justify="center")
    table.add_column("Findings", justify="right")
    table.add_column("Score", justify="right")
    table.add_column("Risk", justify="center")

    for i, p in enumerate(report.pallets, 1):
        pc = _risk_colour(p.risk_level)
        bench = "✅" if p.has_benchmarks else "❌"
        table.add_row(
            str(i),
            p.pallet_name,
            str(p.files_scanned),
            bench,
            str(len(p.vulnerabilities)),
            f"{p.risk_score}/100",
            f"[{pc}]{p.risk_level.value}[/{pc}]",
        )

    console.print(table)

    # Detailed findings for CRITICAL/HIGH pallets
    for p in report.pallets:
        critical_high = [v for v in p.vulnerabilities if v.severity in (RiskLevel.CRITICAL, RiskLevel.HIGH)]
        if critical_high:
            console.print(f"\n  [bold]{p.pallet_name}[/bold] — CRITICAL/HIGH findings:")
            for v in critical_high:
                vc = _risk_colour(v.severity)
                loc = f":{v.line_number}" if v.line_number else ""
                console.print(f"    [{vc}]{v.severity.value:>8}[/{vc}]  {v.type}  {v.description}{loc}")

    if attest:
        from .attestation import attest_scan as _attest
        from .models import ScanResult
        # Attest per-pallet
        for p in report.pallets:
            sr = ScanResult(
                contract_address=p.pallet_path,
                contract_name=p.pallet_name,
                scan_timestamp=p.scan_timestamp,
                vulnerabilities=p.vulnerabilities,
                risk_score=p.risk_score,
                risk_level=p.risk_level,
                source_available=True,
            )
            att = _attest(sr, agent_id="shield-agent-substrate-v1")
            icon = "📜" if att.success else "❌"
            console.print(f"\n  {icon} {p.pallet_name}: {att.tx_hash or att.error}")

    console.print()
    if report.critical_count > 0 or report.high_count > 0:
        console.print(
            f"[bold red]FAIL[/bold red] — {report.critical_count} CRITICAL, "
            f"{report.high_count} HIGH findings. Resolve before mainnet."
        )
        sys.exit(1)
    else:
        console.print("[bold green]PASS[/bold green] — audit clean (no CRITICAL/HIGH findings)")


if __name__ == "__main__":
    main()
