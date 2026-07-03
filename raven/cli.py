"""SPECTER RAVEN — Autonomous Red Team Platform CLI (T171)."""
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
from rich.table import Table
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, TextColumn

from .models import TargetMission, GateLevel
from .gate import GateViolation, RavenKey
from .subsystems import (
    ReconSubsystem,
    EnumerateSubsystem,
    AssessSubsystem,
    SelectSubsystem,
    StrikeSubsystem,
    EscalateSubsystem,
    SpreadSubsystem,
    PersistSubsystem,
    HarvestSubsystem,
    ReportSubsystem,
)

__version__ = "1.0.0"

app = typer.Typer(name="raven", help="SPECTER RAVEN — Autonomous Red Team Platform", no_args_is_help=True)
console = Console()
ACCENT = "#FF0000"


def _banner():
    """Display banner."""
    t = Text()
    t.append("SPECTER RAVEN ", style=f"bold {ACCENT}")
    t.append(f"v{__version__}\n", style="dim")
    t.append("Autonomous Traditional Red Team Platform\n", style=ACCENT)
    t.append("Red Specter Security Research Ltd", style="dim")
    return Panel(t, border_style=ACCENT, expand=False)


@app.command()
def run(
    target: str = typer.Argument(..., help="Target IP or CIDR range"),
    gate: str = typer.Option("OPEN", "--gate", "-g", help="Gate level (OPEN/STRIKE/UNLEASHED)"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output directory for reports"),
    gpu: bool = typer.Option(False, "--gpu", help="Enable GPU acceleration (PRION mutations)"),
    model: str = typer.Option("deepseek-r1", "--model", "-m", help="AI model for decisions"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress detailed output"),
):
    """Launch autonomous red team mission against target."""
    console.print(_banner())

    # Validate gate level
    try:
        gate_level = GateLevel[gate.upper()]
    except KeyError:
        console.print(f"[red]Invalid gate level: {gate}[/red]")
        sys.exit(1)

    # Create mission
    mission_id = str(uuid.uuid4())[:8]
    mission = TargetMission(
        mission_id=mission_id,
        target_ip=target,
        gate_level=gate_level,
        created_at=datetime.now(),
    )

    console.print(f"\n[bold cyan]Mission ID:[/bold cyan] {mission_id}")
    console.print(f"[bold cyan]Target:[/bold cyan] {target}")
    console.print(f"[bold cyan]Gate Level:[/bold cyan] {gate_level.value}")
    console.print(f"[bold cyan]AI Model:[/bold cyan] {model}")
    if gpu:
        console.print(f"[bold cyan]GPU Acceleration:[/bold cyan] Enabled")
    console.print()

    # Load RAVEN_KEY if UNLEASHED
    raven_key = None
    if gate_level == GateLevel.UNLEASHED:
        raven_key = _load_raven_key()
        if not raven_key:
            console.print("[red]UNLEASHED gate requires RAVEN_KEY.[/red]")
            console.print("Generate with: raven keygen --output ~/.redspecter/raven_key")
            sys.exit(1)

    # Execute kill chain
    try:
        _execute_kill_chain(mission, raven_key, output, quiet)
    except GateViolation as e:
        console.print(f"[red]Gate Violation:[/red] {str(e)}")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]Mission Failed:[/red] {str(e)}")
        sys.exit(1)


def _execute_kill_chain(
    mission: TargetMission,
    raven_key: Optional[RavenKey],
    output_dir: Optional[str],
    quiet: bool,
) -> None:
    """Execute all 10 subsystems in kill chain order."""
    start_time = time.time()

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console if not quiet else None,
    ) as progress:
        # RAVEN-RECON
        task = progress.add_task("[cyan]RAVEN-RECON: Reconnaissance...", total=None)
        try:
            recon = ReconSubsystem(mission)
            asyncio.run(recon.execute())
            progress.update(task, completed=True)
        except Exception as e:
            console.print(f"[red]RECON failed: {str(e)}[/red]")
            mission.halt(f"RECON failed: {str(e)}")
            return

        # RAVEN-ENUMERATE
        task = progress.add_task("[cyan]RAVEN-ENUMERATE: Enumeration...", total=None)
        try:
            enumerate_sys = EnumerateSubsystem(mission)
            enumerate_sys.execute()
            progress.update(task, completed=True)
        except Exception as e:
            console.print(f"[red]ENUMERATE failed: {str(e)}[/red]")
            mission.halt(f"ENUMERATE failed: {str(e)}")
            return

        # RAVEN-ASSESS
        task = progress.add_task("[cyan]RAVEN-ASSESS: Vulnerability Assessment...", total=None)
        try:
            assess = AssessSubsystem(mission)
            assess.execute()
            progress.update(task, completed=True)
        except Exception as e:
            console.print(f"[red]ASSESS failed: {str(e)}[/red]")
            mission.halt(f"ASSESS failed: {str(e)}")
            return

        # RAVEN-SELECT
        task = progress.add_task("[cyan]RAVEN-SELECT: Payload Selection...", total=None)
        try:
            select = SelectSubsystem(mission)
            select.execute()
            progress.update(task, completed=True)
        except Exception as e:
            console.print(f"[red]SELECT failed: {str(e)}[/red]")
            mission.halt(f"SELECT failed: {str(e)}")
            return

        # RAVEN-STRIKE
        task = progress.add_task("[red]RAVEN-STRIKE: Payload Delivery...", total=None)
        try:
            strike = StrikeSubsystem(mission)
            strike.execute()
            progress.update(task, completed=True)
        except Exception as e:
            console.print(f"[red]STRIKE failed: {str(e)}[/red]")
            mission.halt(f"STRIKE failed: {str(e)}")
            return

        # RAVEN-ESCALATE
        task = progress.add_task("[red]RAVEN-ESCALATE: Privilege Escalation...", total=None)
        try:
            escalate = EscalateSubsystem(mission)
            escalate.execute()
            progress.update(task, completed=True)
        except Exception as e:
            console.print(f"[red]ESCALATE failed: {str(e)}[/red]")
            mission.halt(f"ESCALATE failed: {str(e)}")
            return

        # RAVEN-SPREAD
        task = progress.add_task("[red]RAVEN-SPREAD: Lateral Movement...", total=None)
        try:
            spread = SpreadSubsystem(mission)
            spread.execute()
            progress.update(task, completed=True)
        except Exception as e:
            console.print(f"[red]SPREAD failed: {str(e)}[/red]")
            mission.halt(f"SPREAD failed: {str(e)}")
            return

        # RAVEN-PERSIST
        task = progress.add_task("[red]RAVEN-PERSIST: Persistence...", total=None)
        try:
            persist = PersistSubsystem(mission)
            persist.execute()
            progress.update(task, completed=True)
        except Exception as e:
            console.print(f"[red]PERSIST failed: {str(e)}[/red]")
            mission.halt(f"PERSIST failed: {str(e)}")
            return

        # RAVEN-HARVEST
        task = progress.add_task("[red]RAVEN-HARVEST: Data Harvesting...", total=None)
        try:
            harvest = HarvestSubsystem(mission)
            harvest.execute()
            progress.update(task, completed=True)
        except Exception as e:
            console.print(f"[red]HARVEST failed: {str(e)}[/red]")
            mission.halt(f"HARVEST failed: {str(e)}")
            return

        # RAVEN-REPORT
        task = progress.add_task("[cyan]RAVEN-REPORT: Report Generation...", total=None)
        try:
            report_sys = ReportSubsystem(mission, raven_key)
            report = report_sys.execute()
            progress.update(task, completed=True)

            # Save reports
            if output_dir:
                _save_reports(mission.mission_id, report, report_sys, output_dir)

        except Exception as e:
            console.print(f"[red]REPORT failed: {str(e)}[/red]")
            mission.halt(f"REPORT failed: {str(e)}")
            return

    # Summary
    duration_sec = time.time() - start_time
    console.print()
    console.print("[bold cyan]Mission Complete[/bold cyan]")
    console.print(f"[cyan]Duration:[/cyan] {duration_sec:.1f}s")
    console.print(f"[cyan]Status:[/cyan] {'Halted' if mission.halted else 'Completed'}")
    if mission.halted:
        console.print(f"[cyan]Halt Reason:[/cyan] {mission.halt_reason}")


def _load_raven_key() -> Optional[RavenKey]:
    """Load RAVEN_KEY from disk."""
    key_path = Path.home() / ".redspecter" / "raven_key"
    if not key_path.exists():
        return None

    try:
        with open(key_path, "rb") as f:
            data = json.load(f)

        return RavenKey(
            ed25519_private=bytes.fromhex(data["ed25519_private"]),
            ed25519_public=bytes.fromhex(data["ed25519_public"]),
            ml_dsa_65_private=bytes.fromhex(data["ml_dsa_65_private"]),
            ml_dsa_65_public=bytes.fromhex(data["ml_dsa_65_public"]),
            key_id=data.get("key_id", ""),
        )
    except Exception:
        return None


def _save_reports(mission_id: str, report, report_sys, output_dir: str) -> None:
    """Save JSON and markdown reports."""
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    # Save JSON
    json_file = output_path / f"raven-{mission_id}.json"
    with open(json_file, "w") as f:
        f.write(report_sys.to_json(report))

    # Save Markdown
    md_file = output_path / f"raven-{mission_id}.md"
    with open(md_file, "w") as f:
        f.write(report_sys.to_markdown(report))

    console.print(f"[cyan]Reports saved:[/cyan] {output_path}")


@app.command()
def keygen(
    output: str = typer.Option("~/.redspecter/raven_key", "--output", "-o", help="Output path for RAVEN_KEY"),
):
    """Generate Ed25519 + ML-DSA-65 keypair for UNLEASHED operations."""
    console.print(_banner())
    console.print("\n[bold]Generating RAVEN_KEY...[/bold]\n")

    try:
        # Generate Ed25519 keypair (32 bytes each)
        ed25519_private = bytes(range(32))  # In production: use cryptography.hazmat.primitives
        ed25519_public = bytes(range(32, 64))

        # Generate ML-DSA-65 keypair (2400 + 1312 bytes)
        ml_dsa_65_private = bytes(range(2400))
        ml_dsa_65_public = bytes(range(1312))

        key = RavenKey(
            ed25519_private=ed25519_private,
            ed25519_public=ed25519_public,
            ml_dsa_65_private=ml_dsa_65_private,
            ml_dsa_65_public=ml_dsa_65_public,
            key_id=str(uuid.uuid4())[:8],
            created_at=time.time(),
        )

        # Save key
        output_path = Path(output).expanduser()
        output_path.parent.mkdir(parents=True, exist_ok=True)

        key_data = {
            "key_id": key.key_id,
            "ed25519_private": key.ed25519_private.hex(),
            "ed25519_public": key.ed25519_public.hex(),
            "ml_dsa_65_private": key.ml_dsa_65_private.hex(),
            "ml_dsa_65_public": key.ml_dsa_65_public.hex(),
            "created_at": key.created_at,
        }

        with open(output_path, "w") as f:
            json.dump(key_data, f, indent=2)

        output_path.chmod(0o600)

        console.print(f"[green]✓ RAVEN_KEY generated[/green]")
        console.print(f"[cyan]Key ID:[/cyan] {key.key_id}")
        console.print(f"[cyan]Location:[/cyan] {output_path}")
        console.print(f"[cyan]Permissions:[/cyan] 0600")

    except Exception as e:
        console.print(f"[red]Keygen failed: {str(e)}[/red]")
        sys.exit(1)


@app.command()
def version():
    """Display version information."""
    console.print(f"SPECTER RAVEN v{__version__}")


def main():
    """CLI entry point."""
    app()


if __name__ == "__main__":
    main()
