"""SPECTER RAVEN CE — Autonomous Infrastructure Reconnaissance and Enumeration CLI."""
from __future__ import annotations
import asyncio
import json
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Optional
import uuid

import typer
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, TextColumn

from .models import GateLevel
from .gate import GateEnforcer
from .subsystems import (
    ReconSubsystem,
    EnumerateSubsystem,
    ReportSubsystem,
)

__version__ = "1.0.0"

app = typer.Typer(name="specter-raven", help="SPECTER RAVEN CE — Infrastructure Reconnaissance", no_args_is_help=True)
console = Console()
ACCENT = "#FF0000"


def _banner():
    """Display banner."""
    t = Text()
    t.append("╔══════════════════════════════════════════════════════╗\n", style=f"{ACCENT}")
    t.append("║  SPECTER RAVEN CE                                   ║\n", style=f"{ACCENT}")
    t.append("║  See what an autonomous red team sees.              ║\n", style="dim")
    t.append("║  Engineered by Richard Barron                       ║\n", style="dim")
    t.append("║  Red Specter Security Research Ltd                 ║\n", style="dim")
    t.append("╚══════════════════════════════════════════════════════╝\n", style=f"{ACCENT}")
    return t


@app.command()
def scan(
    target: str = typer.Argument(..., help="Target IP or hostname"),
    ports: str = typer.Option("80,443,22,25,3306,5432,6379,8080,8443", "--ports", "-p", help="Ports to scan"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output file (JSON/Markdown)"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress detailed output"),
):
    """Scan target for open ports and OS detection."""
    if not quiet:
        console.print(_banner())

    console.print(f"[bold cyan]Target:[/bold cyan] {target}")
    console.print(f"[bold cyan]Ports:[/bold cyan] {ports}")
    console.print()

    # Parse ports
    try:
        port_list = [int(p.strip()) for p in ports.split(",")]
    except ValueError:
        console.print("[red]Invalid port list[/red]")
        sys.exit(1)

    enforcer = GateEnforcer(GateLevel.OPEN)
    recon = ReconSubsystem(enforcer=enforcer)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console if not quiet else None,
    ) as progress:
        task = progress.add_task("[cyan]Scanning ports...", total=None)
        try:
            result = asyncio.run(recon.scan_ports(target, ports=port_list))
            progress.update(task, completed=True)
        except Exception as e:
            console.print(f"[red]Scan failed: {str(e)}[/red]")
            sys.exit(1)

        task = progress.add_task("[cyan]Detecting OS...", total=None)
        try:
            os_result = asyncio.run(recon.detect_os(target))
            progress.update(task, completed=True)
        except Exception as e:
            os_result = None

    # Display results
    console.print()
    console.print("[bold cyan]Scan Results[/bold cyan]")
    if result:
        for port, service in sorted(result.items()):
            console.print(f"  Port {port}: {service}")

    if os_result:
        console.print(f"[cyan]OS:[/cyan] {os_result}")

    # Save if requested
    if output:
        data = {
            "target": target,
            "ports": result,
            "os": os_result,
            "timestamp": datetime.now().isoformat(),
        }
        output_path = Path(output)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        if output.endswith(".json"):
            with open(output_path, "w") as f:
                json.dump(data, f, indent=2)
        else:
            with open(output_path, "w") as f:
                f.write(f"# Scan Results for {target}\n\n")
                f.write(f"**Timestamp:** {data['timestamp']}\n\n")
                f.write("## Open Ports\n\n")
                for port, service in sorted(result.items()):
                    f.write(f"- Port {port}: {service}\n")
                if os_result:
                    f.write(f"\n## OS\n\n{os_result}\n")

        console.print(f"[cyan]Results saved:[/cyan] {output_path}")


@app.command()
def enumerate(
    target: str = typer.Argument(..., help="Target IP or hostname"),
    ports: str = typer.Option("80,443", "--ports", "-p", help="Ports to enumerate"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output file (JSON/Markdown)"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress detailed output"),
):
    """Enumerate services, versions, and TLS certificates."""
    if not quiet:
        console.print(_banner())

    console.print(f"[bold cyan]Target:[/bold cyan] {target}")
    console.print(f"[bold cyan]Ports:[/bold cyan] {ports}")
    console.print()

    # Parse ports
    try:
        port_list = [int(p.strip()) for p in ports.split(",")]
    except ValueError:
        console.print("[red]Invalid port list[/red]")
        sys.exit(1)

    enforcer = GateEnforcer(GateLevel.OPEN)
    enum_sys = EnumerateSubsystem(enforcer=enforcer)

    results = {}

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console if not quiet else None,
    ) as progress:
        for port in port_list:
            service = "http" if port in [80, 8080] else "https" if port in [443, 8443] else "unknown"
            task = progress.add_task(f"[cyan]Enumerating port {port}...", total=None)
            try:
                fingerprint = asyncio.run(enum_sys.fingerprint_service(target, port, service))
                tls = asyncio.run(enum_sys.parse_tls_cert(target, port)) if port in [443, 8443] else None
                results[port] = {
                    "fingerprint": fingerprint,
                    "tls": tls,
                }
                progress.update(task, completed=True)
            except Exception as e:
                results[port] = {"error": str(e)}
                progress.update(task, completed=True)

    # Display results
    console.print()
    console.print("[bold cyan]Enumeration Results[/bold cyan]")
    for port, data in sorted(results.items()):
        console.print(f"\n[bold]Port {port}[/bold]")
        if "error" in data:
            console.print(f"  [yellow]Error: {data['error']}[/yellow]")
        else:
            console.print(f"  Fingerprint: {json.dumps(data.get('fingerprint', {}), indent=2)[:100]}...")
            if data.get('tls'):
                console.print(f"  TLS: Found")

    # Save if requested
    if output:
        output_path = Path(output)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        if output.endswith(".json"):
            with open(output_path, "w") as f:
                json.dump(results, f, indent=2)
        else:
            with open(output_path, "w") as f:
                f.write(f"# Enumeration Results for {target}\n\n")
                f.write(f"**Timestamp:** {datetime.now().isoformat()}\n\n")
                for port, data in sorted(results.items()):
                    f.write(f"## Port {port}\n\n")
                    if "error" in data:
                        f.write(f"Error: {data['error']}\n\n")
                    else:
                        f.write(f"```json\n{json.dumps(data, indent=2)}\n```\n\n")

        console.print(f"[cyan]Results saved:[/cyan] {output_path}")


@app.command()
def report(
    target: str = typer.Argument(..., help="Target IP or hostname"),
    json_file: Optional[str] = typer.Option(None, "--from-json", help="Load scan results from JSON file"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output file"),
):
    """Generate findings report from scan/enumeration results."""
    console.print(_banner())

    console.print(f"[bold cyan]Target:[/bold cyan] {target}")

    enforcer = GateEnforcer(GateLevel.OPEN)
    report_sys = ReportSubsystem(enforcer=enforcer)

    # Create target profile
    from .models import TargetProfile
    profile = TargetProfile(ip_address=target)

    if json_file and Path(json_file).exists():
        with open(json_file, "r") as f:
            data = json.load(f)
            profile.open_ports = data.get("ports", {})

    findings = report_sys.generate_findings(profile)

    console.print()
    console.print("[bold cyan]Findings Report[/bold cyan]")
    console.print(json.dumps(findings, indent=2))

    if output:
        output_path = Path(output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w") as f:
            f.write(f"# Findings Report - {target}\n\n")
            f.write(f"**Generated:** {datetime.now().isoformat()}\n\n")
            f.write(f"```json\n{json.dumps(findings, indent=2)}\n```\n")
        console.print(f"[cyan]Report saved:[/cyan] {output_path}")


@app.command()
def version():
    """Display version information."""
    console.print(f"SPECTER RAVEN CE v{__version__}")


def main():
    """CLI entry point."""
    app()


if __name__ == "__main__":
    main()
