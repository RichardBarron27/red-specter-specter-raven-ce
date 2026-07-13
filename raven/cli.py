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

from .models import GateLevel, TargetMission
from .gate import GateEnforcer
from .subsystems import (
    ReconSubsystem,
    EnumerateSubsystem,
    ReportSubsystem,
)

__version__ = "1.0.1"

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
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output file (JSON/Markdown)"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress detailed output"),
):
    """Scan target for open ports and OS detection."""
    if not quiet:
        console.print(_banner())

    console.print(f"[bold cyan]Target:[/bold cyan] {target}")
    console.print()

    mission = TargetMission(
        mission_id=str(uuid.uuid4())[:8],
        target_ip=target,
        gate_level=GateLevel.OPEN,
    )
    recon = ReconSubsystem(mission)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console if not quiet else None,
    ) as progress:
        task = progress.add_task("[cyan]Scanning ports and detecting OS...", total=None)
        try:
            result = asyncio.run(recon.execute())
            progress.update(task, completed=True)
        except Exception as e:
            console.print(f"[red]Scan failed: {str(e)}[/red]")
            sys.exit(1)

    # Display results
    console.print()
    console.print("[bold cyan]Scan Results[/bold cyan]")
    if result and result.open_ports:
        for port, service in sorted(result.open_ports.items()):
            console.print(f"  Port {port}: {service}")

    if result and result.os:
        console.print(f"[cyan]OS:[/cyan] {result.os}")

    # Save if requested
    if output:
        data = {
            "target": target,
            "ports": result.open_ports if result else {},
            "os": result.os if result else None,
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
                for port, service in sorted(data.get('ports', {}).items()):
                    f.write(f"- Port {port}: {service}\n")
                if data.get('os'):
                    f.write(f"\n## OS\n\n{data['os']}\n")

        console.print(f"[cyan]Results saved:[/cyan] {output_path}")


@app.command()
def enumerate(
    target: str = typer.Argument(..., help="Target IP or hostname"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output file (JSON/Markdown)"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress detailed output"),
):
    """Enumerate services, versions, and TLS certificates."""
    if not quiet:
        console.print(_banner())

    console.print(f"[bold cyan]Target:[/bold cyan] {target}")
    console.print()

    # First do recon to get profile
    mission = TargetMission(
        mission_id=str(uuid.uuid4())[:8],
        target_ip=target,
        gate_level=GateLevel.OPEN,
    )
    recon = ReconSubsystem(mission)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console if not quiet else None,
    ) as progress:
        task = progress.add_task("[cyan]Running reconnaissance...", total=None)
        try:
            profile = asyncio.run(recon.execute())
            mission.profile = profile
            progress.update(task, completed=True)
        except Exception as e:
            console.print(f"[red]Recon failed: {str(e)}[/red]")
            sys.exit(1)

        # Now enumerate services
        enum_sys = EnumerateSubsystem(mission)
        task = progress.add_task("[cyan]Enumerating services...", total=None)
        try:
            services = enum_sys.execute()
            progress.update(task, completed=True)
        except Exception as e:
            console.print(f"[red]Enumeration failed: {str(e)}[/red]")
            sys.exit(1)

    # Display results
    console.print()
    console.print("[bold cyan]Enumeration Results[/bold cyan]")
    if services:
        for service in services:
            console.print(f"\n[bold]Port {service.port}/{service.protocol}[/bold]")
            console.print(f"  Service: {service.service}")
            if service.version:
                console.print(f"  Version: {service.version}")

    # Save if requested
    if output:
        services_data = [
            {
                "port": s.port,
                "protocol": s.protocol,
                "service": s.service,
                "version": s.version,
            }
            for s in (services or [])
        ]
        data = {
            "target": target,
            "services": services_data,
            "timestamp": datetime.now().isoformat(),
        }
        output_path = Path(output)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        if output.endswith(".json"):
            with open(output_path, "w") as f:
                json.dump(data, f, indent=2)
        else:
            with open(output_path, "w") as f:
                f.write(f"# Enumeration Results for {target}\n\n")
                f.write(f"**Timestamp:** {data['timestamp']}\n\n")
                for svc in services_data:
                    f.write(f"## Port {svc['port']}/{svc['protocol']}\n\n")
                    f.write(f"- **Service:** {svc['service']}\n")
                    if svc.get('version'):
                        f.write(f"- **Version:** {svc['version']}\n")
                    f.write("\n")

        console.print(f"[cyan]Results saved:[/cyan] {output_path}")


@app.command()
def report(
    target: str = typer.Argument(..., help="Target IP or hostname"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output file"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress detailed output"),
):
    """Generate findings report from scan/enumeration."""
    if not quiet:
        console.print(_banner())

    console.print(f"[bold cyan]Target:[/bold cyan] {target}")
    console.print()

    mission = TargetMission(
        mission_id=str(uuid.uuid4())[:8],
        target_ip=target,
        gate_level=GateLevel.OPEN,
    )

    # Run full pipeline: recon -> enumerate -> report
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console if not quiet else None,
    ) as progress:
        # Recon
        recon = ReconSubsystem(mission)
        task = progress.add_task("[cyan]Reconnaissance...", total=None)
        try:
            profile = asyncio.run(recon.execute())
            mission.profile = profile
            progress.update(task, completed=True)
        except Exception as e:
            console.print(f"[red]Recon failed: {str(e)}[/red]")
            sys.exit(1)

        # Enumerate
        enum_sys = EnumerateSubsystem(mission)
        task = progress.add_task("[cyan]Enumeration...", total=None)
        try:
            services = enum_sys.execute()
            progress.update(task, completed=True)
        except Exception as e:
            console.print(f"[red]Enumeration failed: {str(e)}[/red]")
            sys.exit(1)

        # Report
        report_sys = ReportSubsystem(mission)
        task = progress.add_task("[cyan]Generating report...", total=None)
        try:
            raven_report = report_sys.execute()
            progress.update(task, completed=True)
        except Exception as e:
            console.print(f"[red]Report generation failed: {str(e)}[/red]")
            sys.exit(1)

    # Display report
    console.print()
    console.print("[bold cyan]Report Summary[/bold cyan]")
    console.print(f"Mission ID: {raven_report.mission_id}")
    console.print(f"Target: {raven_report.target_ip}")
    console.print(f"Status: {raven_report.status}")
    console.print(f"Gate Level: {raven_report.gate_level.value}")

    # Save if requested
    if output:
        output_path = Path(output)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        if output.endswith(".json"):
            with open(output_path, "w") as f:
                f.write(report_sys.to_json(raven_report))
        else:
            with open(output_path, "w") as f:
                f.write(report_sys.to_markdown(raven_report))

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
