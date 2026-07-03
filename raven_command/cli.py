"""Red Specter RAVEN Command — Standalone GUI CLI.

Usage:
    raven-command launch        Launch GUI
    raven-command stop          Graceful shutdown
    raven-command status        Show status
    raven-command doctor        Diagnose installation
"""
from __future__ import annotations

import json
import os
import signal
import shutil
import subprocess
import sys
import time
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

app = typer.Typer(
    name="raven-command",
    help="Red Specter RAVEN — Dark web, breach data, OSINT — conversational threat intel.",
    no_args_is_help=True,
)
console = Console()

VERSION = "1.0.0"
PRODUCT_NAME = "Red Specter RAVEN"
TOOL_NAME = "RAVEN"
TOOL_KEY = "raven"
TOOL_ID = 26
TESTS = 174
ACCENT = "#FFB300"
TAGLINE = "Dark web, breach data, OSINT — conversational threat intel."
CATEGORY = "Threat Intelligence"
API_PORT = 8150
GUI_PORT = 8151


def _product_root() -> Path:
    return Path(__file__).resolve().parent.parent


def _pid_file() -> Path:
    return Path(os.path.expanduser(f"~/.red-specter/{TOOL_KEY}-gui.pid"))


def _write_pid(backend_pid: int, frontend_pid: int | None):
    pf = _pid_file()
    pf.parent.mkdir(parents=True, exist_ok=True)
    pf.write_text(json.dumps({
        "backend": backend_pid,
        "frontend": frontend_pid,
        "tool": TOOL_KEY,
        "started": time.strftime("%Y-%m-%d %H:%M:%S"),
    }, indent=2))


def _read_pid() -> dict | None:
    pf = _pid_file()
    if not pf.exists():
        return None
    try:
        return json.loads(pf.read_text())
    except (json.JSONDecodeError, OSError):
        return None


def _banner() -> Panel:
    t = Text()
    t.append(f"{PRODUCT_NAME} ", style=f"bold {ACCENT}")
    t.append(f"v{VERSION}\n", style="dim")
    t.append(f"{TAGLINE}\n", style=f"{ACCENT}")
    t.append(f"{TESTS:,} Tests | {CATEGORY}\n", style="dim")
    t.append("Red Specter Security Research \u2014 Innovation Beyond Belief\n", style="dim")
    t.append("Engineered by Richard Barron", style="dim")
    return Panel(t, border_style=ACCENT, expand=False)


def _kill_pid(pid: int, name: str) -> bool:
    if not pid:
        return False
    try:
        os.kill(pid, signal.SIGTERM)
        for _ in range(50):
            time.sleep(0.1)
            try:
                os.kill(pid, 0)
            except OSError:
                console.print(f"  [green]\u2713[/] {name} stopped [dim](PID {pid})[/]")
                return True
        os.kill(pid, signal.SIGKILL)
        console.print(f"  [yellow]![/] {name} force-killed [dim](PID {pid})[/]")
        return True
    except OSError:
        console.print(f"  [green]\u2713[/] {name} already stopped")
        return True


@app.command()
def launch(
    host: str = typer.Option("0.0.0.0", "--host", help="Listen address"),
    api_port: int = typer.Option(8150, "--api-port", help="API port"),
    gui_port: int = typer.Option(8151, "--gui-port", help="GUI port"),
    docker: bool = typer.Option(False, "--docker", "-d", help="Launch via Docker"),
):
    """Launch Red Specter RAVEN GUI."""
    console.print(_banner())

    root = _product_root()

    if docker:
        compose = root / "docker-compose.gui.yml"
        if compose.exists():
            console.print(f"  [bold {ACCENT}]Launching via Docker...[/]")
            os.execlp("docker", "docker", "compose", "-f", str(compose), "up", "-d")
        else:
            console.print("[red]  docker-compose.gui.yml not found[/]")
            raise typer.Exit(1)
        return

    pids = _read_pid()
    if pids:
        try:
            os.kill(pids["backend"], 0)
            console.print(f"  [yellow]![/] Already running since {pids.get('started', 'unknown')}")
            console.print(f"      Run [bold]raven-command stop[/] first.")
            raise typer.Exit(1)
        except OSError:
            pass

    gui_dir = root / "gui"
    frontend_dist = gui_dir / "frontend" / "dist"
    backend_dir = gui_dir / "backend"

    if not frontend_dist.exists():
        console.print("  [yellow]![/] Building frontend (first run only)...")
        frontend_dir = gui_dir / "frontend"
        subprocess.run(["npm", "ci", "--legacy-peer-deps"], cwd=str(frontend_dir),
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["npm", "run", "build"], cwd=str(frontend_dir),
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        console.print("  [green]\u2713[/] Frontend built")

    backend_env = os.environ.copy()
    backend_env["RS_DEMO_MODE"] = "0"

    console.print(f"  [green]\u2713[/] Starting backend on :{api_port}")
    backend_proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "main:app", "--host", host, "--port", str(api_port)],
        cwd=str(backend_dir),
        env=backend_env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(2)

    console.print(f"  [green]\u2713[/] Serving GUI on :{gui_port}")
    frontend_proc = subprocess.Popen(
        [sys.executable, "-m", "http.server", str(gui_port), "--directory", str(frontend_dist), "--bind", host],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    _write_pid(backend_proc.pid, frontend_proc.pid)

    console.print()
    console.print(f"  [bold {ACCENT}]{PRODUCT_NAME}[/] is running")
    console.print("  \u2500" * 37)
    console.print(f"  GUI:      [bold]http://localhost:{gui_port}[/]")
    console.print(f"  API:      [bold]http://localhost:{api_port}[/]")
    console.print(f"  API Docs: [bold]http://localhost:{api_port}/docs[/]")
    console.print()
    console.print(f"  Press Ctrl+C or run [bold]raven-command stop[/] to shutdown")

    def shutdown(*_):
        console.print()
        _kill_pid(backend_proc.pid, "Backend")
        _kill_pid(frontend_proc.pid, "Frontend")
        pf = _pid_file()
        if pf.exists():
            pf.unlink()
        raise SystemExit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    try:
        backend_proc.wait()
    except KeyboardInterrupt:
        shutdown()


@app.command()
def stop():
    """Graceful shutdown of Red Specter RAVEN GUI."""
    console.print(_banner())
    pids = _read_pid()
    if not pids:
        console.print(f"  [dim]{PRODUCT_NAME} GUI is not running.[/]")
        return

    console.print(f"  [bold {ACCENT}]Shutting down {PRODUCT_NAME}...[/]")
    _kill_pid(pids.get("frontend"), "Frontend")
    _kill_pid(pids.get("backend"), "Backend")
    pf = _pid_file()
    if pf.exists():
        pf.unlink()
    console.print(f"\n  [green]\u2713[/] {PRODUCT_NAME} GUI stopped.")


@app.command()
def status():
    """Show GUI status."""
    console.print(_banner())

    pids = _read_pid()
    running = False
    if pids:
        try:
            os.kill(pids["backend"], 0)
            running = True
        except OSError:
            pass

    table = Table(title=PRODUCT_NAME, border_style=ACCENT, title_style=f"bold {ACCENT}")
    table.add_column("Component", style="bold")
    table.add_column("Status", justify="center")

    if running:
        table.add_row("Backend", f"[green]\u25cf RUNNING[/] [dim](PID {pids['backend']})[/]")
        fpid = pids.get("frontend")
        table.add_row("Frontend", f"[green]\u25cf SERVING[/] [dim](PID {fpid})[/]" if fpid else "[yellow]\u25cb NOT STARTED[/]")
        table.add_row("Started", pids.get("started", "unknown"))
    else:
        table.add_row("Backend", "[dim]\u25cb STOPPED[/]")
        table.add_row("Frontend", "[dim]\u25cb STOPPED[/]")

    console.print(table)
    console.print(f"\n  {TESTS:,} tests | {CATEGORY}")

    if running:
        console.print(f"\n  [bold green]\u25cf RUNNING[/]")
    else:
        console.print(f"\n  [dim]\u25cb STOPPED[/]")
        console.print(f"  Launch: [bold]raven-command launch[/]")


@app.command()
def doctor():
    """Diagnose installation issues."""
    console.print(_banner())
    console.print("[bold]Running diagnostics...\n[/]")

    checks = [
        ("Python 3.11+", lambda: sys.version_info >= (3, 11)),
        ("Node.js", lambda: shutil.which("node")),
        ("npm", lambda: shutil.which("npm")),
        (f"{TOOL_NAME} CLI", lambda: shutil.which("raven")),
    ]

    for name, check in checks:
        try:
            ok = check()
            console.print(f"  [green]\u2713[/] {name}" if ok else f"  [red]\u2717[/] {name}")
        except Exception:
            console.print(f"  [red]\u2717[/] {name} (error)")

    root = _product_root()
    gui_ok = (root / "gui" / "frontend" / "src").exists()
    backend_ok = (root / "gui" / "backend" / "main.py").exists()

    g = "[green]\u2713[/]"
    r = "[red]\u2717[/]"
    console.print(f"\n  GUI source: {g if gui_ok else r}")
    console.print(f"  Backend:    {g if backend_ok else r}")


def main():
    app()


if __name__ == "__main__":
    main()
