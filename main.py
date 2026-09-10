#!/usr/bin/env python3
"""
Canary EDR Tripwire — defensive honey-file ransomware detector for macOS / Linux.

Monitors ~/.canary for tampering, attributes the offending PID via lsof,
terminates it with psutil, logs locally, and optionally alerts via Discord.
"""

from __future__ import annotations

import logging
import os
import signal
import subprocess
import sys
import threading
import time
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Deque, Dict, List, Set

import psutil
import requests
from rich import box
from shutil import which

from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from watchdog.events import (
    FileDeletedEvent,
    FileModifiedEvent,
    FileSystemEventHandler,
)
from watchdog.observers import Observer

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

CANARY_DIR = Path.home() / ".canary"
HONEY_FILES = ("passwords.txt", "financials.docx", "private_keys.pem")
LOG_FILE = Path(__file__).resolve().parent / "security.log"
DISCORD_WEBHOOK_URL = os.environ.get("DISCORD_WEBHOOK_URL", "").strip()
REFRESH_HZ = 4
MAX_EVENT_ROWS = 40
OUR_PID = os.getpid()

# Seed content designed to look like high-value targets (bait only).
HONEY_CONTENT: Dict[str, bytes] = {
    "passwords.txt": (
        b"# INTERNAL - DO NOT DISTRIBUTE\n"
        b"admin@corp.local:Summer2024!\n"
        b"vpn_gateway:P@ssw0rd_Backup\n"
        b"db_root:s3cret_key_vault\n"
    ),
    "financials.docx": (
        b"PK\x03\x04"  # minimal ZIP/DOCX magic so scanners treat it as Office
        b"Q1_FORECAST_CONFIDENTIAL\n"
        b"Account ending 4421 | wire instructions attached\n"
    ),
    "private_keys.pem": (
        b"-----BEGIN RSA PRIVATE KEY-----\n"
        b"MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF4P\n"
        b"CANARY_BAIT_KEY_NOT_REAL_MATERIAL_AAAA\n"
        b"-----END RSA PRIVATE KEY-----\n"
    ),
}


# ---------------------------------------------------------------------------
# Shared state (handler thread ↔ TUI thread)
# ---------------------------------------------------------------------------

class EventStore:
    """Thread-safe ring buffer of defense events for the TUI and logging."""

    def __init__(self, maxlen: int = MAX_EVENT_ROWS) -> None:
        self._lock = threading.Lock()
        self._events: Deque[Dict[str, str]] = deque(maxlen=maxlen)
        self.blocked_count = 0
        self.last_error: str = ""

    def add(self, row: Dict[str, str]) -> None:
        with self._lock:
            self._events.appendleft(row)
            if row.get("action") == "KILLED":
                self.blocked_count += 1

    def snapshot(self) -> List[Dict[str, str]]:
        with self._lock:
            return list(self._events)


STORE = EventStore()
STOP = threading.Event()


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

def setup_logging() -> logging.Logger:
    logger = logging.getLogger("canary_edr")
    logger.setLevel(logging.INFO)
    logger.handlers.clear()

    fmt = logging.Formatter(
        "%(asctime)s | %(levelname)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    fh = logging.FileHandler(LOG_FILE, encoding="utf-8")
    fh.setFormatter(fmt)
    sh = logging.StreamHandler(sys.stderr)
    sh.setFormatter(fmt)
    sh.setLevel(logging.WARNING)
    logger.addHandler(fh)
    logger.addHandler(sh)
    return logger


LOG = setup_logging()


# ---------------------------------------------------------------------------
# Honey-file initialization
# ---------------------------------------------------------------------------

def init_honey_files() -> List[Path]:
    CANARY_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    created: List[Path] = []
    for name in HONEY_FILES:
        path = CANARY_DIR / name
        if not path.exists():
            path.write_bytes(HONEY_CONTENT[name])
            path.chmod(0o600)
        created.append(path)
    LOG.info("Honey-files ready under %s (%d files)", CANARY_DIR, len(created))
    return created


# ---------------------------------------------------------------------------
# Attribution (lsof) + defense (psutil kill)
# ---------------------------------------------------------------------------

def pids_holding_file(path: Path) -> Set[int]:
    """Return PIDs that currently have *path* open, via lsof."""
    pids: Set[int] = set()
    try:
        result = subprocess.run(
            ["lsof", "-t", "--", str(path)],
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        STORE.last_error = f"lsof failed: {exc}"
        LOG.warning("lsof failed for %s: %s", path, exc)
        return pids

    for line in result.stdout.splitlines():
        line = line.strip()
        if line.isdigit():
            pids.add(int(line))
    return pids


def terminate_pid(pid: int) -> tuple[bool, str]:
    """Kill *pid* unless it is our own process. Returns (ok, detail)."""
    if pid == OUR_PID or pid == os.getppid():
        return False, "skipped (self/parent)"

    try:
        proc = psutil.Process(pid)
        name = proc.name()
        cmdline = " ".join(proc.cmdline()[:6]) or name
        proc.kill()
        try:
            proc.wait(timeout=2)
        except psutil.TimeoutExpired:
            pass
        return True, f"{name} ({cmdline})"
    except psutil.NoSuchProcess:
        return False, "already exited"
    except psutil.AccessDenied as exc:
        return False, f"access denied: {exc}"
    except Exception as exc:  # noqa: BLE001 — defense path must not crash
        return False, f"error: {exc}"


def alert_discord(details: Dict[str, str]) -> None:
    """POST an embed to Discord. Failures are logged, never raised."""
    if not DISCORD_WEBHOOK_URL:
        return
    try:
        embed = {
            "title": "🛑 Ransomware Attack Neutralized",
            "color": 0xE74C3C,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "fields": [
                {"name": k.replace("_", " ").title(), "value": str(v) or "—", "inline": False}
                for k, v in details.items()
            ],
            "footer": {"text": "Canary EDR Tripwire"},
        }
        resp = requests.post(
            DISCORD_WEBHOOK_URL,
            json={"embeds": [embed]},
            timeout=5,
        )
        if resp.status_code >= 400:
            LOG.warning("Discord webhook HTTP %s: %s", resp.status_code, resp.text[:200])
    except Exception as exc:  # noqa: BLE001
        LOG.warning("Discord webhook failed: %s", exc)


def handle_tripwire(path: Path, event_type: str) -> None:
    """Attribute + kill + log + alert for one filesystem event."""
    now = datetime.now().strftime("%H:%M:%S")
    pids = pids_holding_file(path)

    # Deleted files may no longer appear in lsof; still record the event.
    if not pids:
        row = {
            "time": now,
            "event": event_type,
            "file": path.name,
            "pid": "—",
            "process": "unattributed",
            "action": "LOGGED",
        }
        STORE.add(row)
        msg = f"{event_type} on {path} — no open PID via lsof"
        LOG.warning(msg)
        alert_discord(
            {
                "event": event_type,
                "file": str(path),
                "pid": "n/a",
                "process": "unattributed",
                "action": "logged only",
                "note": "lsof returned no holders (process may have exited)",
            }
        )
        return

    for pid in sorted(pids):
        ok, detail = terminate_pid(pid)
        action = "KILLED" if ok else "FAILED"
        row = {
            "time": now,
            "event": event_type,
            "file": path.name,
            "pid": str(pid),
            "process": detail[:48],
            "action": action,
        }
        STORE.add(row)
        LOG.critical(
            "%s on %s | PID %s | %s | %s",
            event_type,
            path,
            pid,
            detail,
            action,
        )
        alert_discord(
            {
                "event": event_type,
                "file": str(path),
                "pid": str(pid),
                "process": detail,
                "action": action,
                "host": os.uname().nodename,
            }
        )


# ---------------------------------------------------------------------------
# Watchdog handler
# ---------------------------------------------------------------------------

class CanaryHandler(FileSystemEventHandler):
    """Fire defense on modification or deletion of honey-files only."""

    def __init__(self, watched: Set[str]) -> None:
        super().__init__()
        self._watched = watched
        self._cooldown: Dict[str, float] = {}
        self._cooldown_lock = threading.Lock()
        self._cooldown_secs = 1.0

    def _relevant(self, path: str) -> bool:
        return Path(path).name in self._watched and not path.endswith("~")

    def _throttled(self, key: str) -> bool:
        now = time.monotonic()
        with self._cooldown_lock:
            last = self._cooldown.get(key, 0.0)
            if now - last < self._cooldown_secs:
                return True
            self._cooldown[key] = now
        return False

    def on_modified(self, event: FileModifiedEvent) -> None:  # type: ignore[override]
        if event.is_directory or not self._relevant(event.src_path):
            return
        if self._throttled(f"mod:{event.src_path}"):
            return
        handle_tripwire(Path(event.src_path), "MODIFIED")

    def on_deleted(self, event: FileDeletedEvent) -> None:  # type: ignore[override]
        if event.is_directory or not self._relevant(event.src_path):
            return
        if self._throttled(f"del:{event.src_path}"):
            return
        handle_tripwire(Path(event.src_path), "DELETED")


# ---------------------------------------------------------------------------
# Rich TUI
# ---------------------------------------------------------------------------

def _self_stats() -> tuple[float, float]:
    try:
        p = psutil.Process(OUR_PID)
        return p.cpu_percent(interval=None), p.memory_info().rss / (1024 * 1024)
    except psutil.Error:
        return 0.0, 0.0


def build_layout(file_count: int) -> Layout:
    layout = Layout(name="root")
    layout.split_column(
        Layout(name="header", size=3),
        Layout(name="body"),
        Layout(name="footer", size=5),
    )
    layout["body"].split_row(
        Layout(name="status", ratio=1),
        Layout(name="events", ratio=3),
    )
    # Populate once so Live has widgets before first refresh.
    layout["header"].update(
        Panel(
            Text("CANARY EDR TRIPWIRE", justify="center", style="bold white"),
            style="bold red",
            box=box.HEAVY,
        )
    )
    layout["status"].update(Panel("…", title="Status"))
    layout["events"].update(Panel("…", title="Live Event Log"))
    layout["footer"].update(Panel("…", title="System Stats"))
    return layout


def render_status(file_count: int) -> Panel:
    body = Table.grid(padding=(0, 1))
    body.add_column(style="bold cyan", justify="right")
    body.add_column(style="white")
    body.add_row("State", "[bold green]EDR Tripwire Active[/]")
    body.add_row("Canary dir", str(CANARY_DIR))
    body.add_row("Monitored", str(file_count))
    body.add_row("Blocked", str(STORE.blocked_count))
    body.add_row("Webhook", "configured" if DISCORD_WEBHOOK_URL else "not set")
    body.add_row("PID", str(OUR_PID))
    if STORE.last_error:
        body.add_row("Last err", STORE.last_error[:40])
    return Panel(body, title="Status", border_style="green", box=box.ROUNDED)


def render_events() -> Panel:
    table = Table(
        box=box.SIMPLE_HEAD,
        expand=True,
        show_edge=False,
        pad_edge=False,
    )
    table.add_column("Time", style="dim", width=8)
    table.add_column("Event", style="yellow", width=10)
    table.add_column("File", style="cyan", ratio=1)
    table.add_column("PID", style="magenta", width=8)
    table.add_column("Process", style="white", ratio=2)
    table.add_column("Action", width=8)

    rows = STORE.snapshot()
    if not rows:
        table.add_row("—", "—", "waiting for activity…", "—", "—", "—")
    else:
        for r in rows:
            action_style = "bold red" if r["action"] == "KILLED" else "yellow"
            table.add_row(
                r["time"],
                r["event"],
                r["file"],
                r["pid"],
                r["process"],
                Text(r["action"], style=action_style),
            )
    return Panel(table, title="Live Event Log", border_style="blue", box=box.ROUNDED)


def render_stats() -> Panel:
    cpu, mem = _self_stats()
    sys_cpu = psutil.cpu_percent(interval=None)
    sys_mem = psutil.virtual_memory().percent
    grid = Table.grid(expand=True, padding=(0, 2))
    grid.add_column()
    grid.add_column()
    grid.add_column()
    grid.add_row(
        f"[bold]Process CPU[/]  {cpu:5.1f}%",
        f"[bold]Process RSS[/]  {mem:6.1f} MiB",
        f"[bold]Host CPU[/]  {sys_cpu:5.1f}%",
    )
    grid.add_row(
        f"[bold]Host Mem[/]   {sys_mem:5.1f}%",
        f"[bold]Log file[/]   {LOG_FILE.name}",
        f"[dim]Ctrl+C to stop[/]",
    )
    return Panel(grid, title="System Stats", border_style="magenta", box=box.ROUNDED)


def refresh_layout(layout: Layout, file_count: int) -> None:
    layout["status"].update(render_status(file_count))
    layout["events"].update(render_events())
    layout["footer"].update(render_stats())


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    if sys.platform not in ("darwin", "linux"):
        print("This tool targets macOS or Linux only.", file=sys.stderr)
        return 1

    if which("lsof") is None:
        print("lsof is required but was not found on PATH.", file=sys.stderr)
        return 1

    honey = init_honey_files()
    watched = {p.name for p in honey}

    # Warm psutil CPU counters
    psutil.Process(OUR_PID).cpu_percent(interval=None)
    psutil.cpu_percent(interval=None)

    handler = CanaryHandler(watched)
    observer = Observer()
    observer.schedule(handler, str(CANARY_DIR), recursive=False)
    observer.daemon = True
    observer.start()
    LOG.info("Observer started on %s", CANARY_DIR)

    def _shutdown(*_args: object) -> None:
        STOP.set()

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    console = Console()
    layout = build_layout(len(honey))
    refresh_layout(layout, len(honey))

    try:
        with Live(layout, console=console, refresh_per_second=REFRESH_HZ, screen=True):
            while not STOP.is_set():
                refresh_layout(layout, len(honey))
                time.sleep(1.0 / REFRESH_HZ)
    finally:
        observer.stop()
        observer.join(timeout=5)
        LOG.info("Shutdown complete. Events blocked: %d", STORE.blocked_count)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
