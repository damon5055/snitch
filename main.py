#!/usr/bin/env python3
"""
snitch — defensive honey-file tripwire for macOS / Linux.

Watches ~/.snitch bait files, diffs tampering, attributes PIDs via lsof,
kills offenders with psutil, logs locally, alerts Discord, and archives
events to Supabase so the terminal UI stays lean.
"""

from __future__ import annotations

import difflib
import hashlib
import logging
import os
import signal
import subprocess
import sys
import threading
import time
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from shutil import which
from typing import Deque, Dict, List, Optional, Set, Tuple

import psutil
import requests
from dotenv import load_dotenv
from rich import box
from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.style import Style
from rich.table import Table
from rich.text import Text
from watchdog.events import (
    FileDeletedEvent,
    FileModifiedEvent,
    FileSystemEventHandler,
)
from watchdog.observers import Observer

load_dotenv()

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

SNITCH_DIR = Path.home() / ".snitch"
HONEY_FILES = ("passwords.txt", "financials.docx", "private_keys.pem")
LOG_FILE = Path(__file__).resolve().parent / "security.log"
DISCORD_WEBHOOK_URL = os.environ.get("DISCORD_WEBHOOK_URL", "").strip()
SUPABASE_URL = os.environ.get("SUPABASE_URL", "").strip().rstrip("/")
SUPABASE_KEY = (
    os.environ.get("SUPABASE_KEY", "").strip()
    or os.environ.get("SUPABASE_ANON_KEY", "").strip()
)
REFRESH_HZ = 4
MAX_LIVE_ROWS = 8
DIFF_STORE_LIMIT = 4000
CONTENT_STORE_LIMIT = 8000
OUR_PID = os.getpid()
HOST = os.uname().nodename

# Matrix palette + alert accents
C_GREEN = "green"
C_DIM = "dark_green"
C_WHITE = "bright_white"
C_ALERT = "bold bright_green"
C_MODIFY = "bold bright_blue"
C_DELETE = "bold bright_red"
BORDER = "green"
BOX = box.SQUARE

# Discord embed sidebar colors
DISCORD_COLOR_MODIFY = 0x3498DB  # blue
DISCORD_COLOR_DELETE = 0xE74C3C  # red
DISCORD_COLOR_DEFAULT = 0x00FF41  # matrix green (touch / other)

HONEY_CONTENT: Dict[str, bytes] = {
    "passwords.txt": (
        b"# INTERNAL - DO NOT DISTRIBUTE\n"
        b"admin@corp.local:Summer2024!\n"
        b"vpn_gateway:P@ssw0rd_Backup\n"
        b"db_root:s3cret_key_vault\n"
    ),
    "financials.docx": (
        b"PK\x03\x04"
        b"Q1_FORECAST_CONFIDENTIAL\n"
        b"Account ending 4421 | wire instructions attached\n"
    ),
    "private_keys.pem": (
        b"-----BEGIN RSA PRIVATE KEY-----\n"
        b"MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF4P\n"
        b"SNITCH_BAIT_KEY_NOT_REAL_MATERIAL_AAAA\n"
        b"-----END RSA PRIVATE KEY-----\n"
    ),
}

SORT_MODES: Tuple[Tuple[str, str], ...] = (
    ("newest", "created_at.desc"),
    ("oldest", "created_at.asc"),
    ("action", "action.asc,created_at.desc"),
    ("file", "file_name.asc,created_at.desc"),
    ("deletes", "is_delete.desc,created_at.desc"),
)


@dataclass
class ChangeRecord:
    """What happened to a bait file vs the last remembered snapshot."""

    kind: str  # DELETE | MODIFY | TOUCH
    summary: str
    content_diff: str
    before_content: str
    after_content: str
    before_bytes: bytes
    after_bytes: Optional[bytes]
    is_delete: bool


# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------

class EventStore:
    def __init__(self, maxlen: int = MAX_LIVE_ROWS) -> None:
        self._lock = threading.Lock()
        self._events: Deque[Dict[str, str]] = deque(maxlen=maxlen)
        self.blocked_count = 0
        self.cloud_count = 0
        self.last_error: str = ""
        self.supabase_ok = bool(SUPABASE_URL and SUPABASE_KEY)
        self.sort_idx = 0
        self.peek_rows: List[Dict[str, str]] = []
        self.peek_label = "newest"
        self._snapshots: Dict[str, bytes] = {}

    def add(self, row: Dict[str, str]) -> None:
        with self._lock:
            self._events.appendleft(row)
            if row.get("action") == "KILLED":
                self.blocked_count += 1

    def snapshot_events(self) -> List[Dict[str, str]]:
        with self._lock:
            return list(self._events)

    def set_file_snapshot(self, path: Path, data: bytes) -> None:
        with self._lock:
            self._snapshots[str(path)] = data

    def get_file_snapshot(self, path: Path) -> bytes:
        with self._lock:
            return self._snapshots.get(str(path), b"")

    def take_change(self, path: Path, new_data: Optional[bytes]) -> ChangeRecord:
        """Compare to last snapshot, then remember the new contents (or clear on delete)."""
        key = str(path)
        with self._lock:
            old = self._snapshots.get(key, b"")
            if new_data is None:
                self._snapshots.pop(key, None)
                before = _bytes_to_stored_text(old)
                return ChangeRecord(
                    kind="DELETE",
                    summary="DELETE! file removed",
                    content_diff=(
                        f"!!! DELETE !!!\n"
                        f"file: {path.name}\n"
                        f"last known contents were:\n"
                        f"{before or '[empty]'}"
                    ),
                    before_content=before,
                    after_content="",
                    before_bytes=old,
                    after_bytes=None,
                    is_delete=True,
                )
            self._snapshots[key] = new_data

        before = _bytes_to_stored_text(old)
        after = _bytes_to_stored_text(new_data)

        if old == new_data:
            return ChangeRecord(
                kind="TOUCH",
                summary="TOUCH (no content change)",
                content_diff="",
                before_content=before,
                after_content=after,
                before_bytes=old,
                after_bytes=new_data,
                is_delete=False,
            )

        if _looks_binary(old) or _looks_binary(new_data):
            oh = hashlib.sha256(old).hexdigest()[:12]
            nh = hashlib.sha256(new_data).hexdigest()[:12]
            summary = f"MODIFY binary {len(old)}B->{len(new_data)}B"
            body = (
                f"!!! MODIFY (binary) !!!\n"
                f"size: {len(old)} -> {len(new_data)} bytes\n"
                f"sha256: {oh} -> {nh}"
            )
            return ChangeRecord(
                kind="MODIFY",
                summary=summary,
                content_diff=body,
                before_content=f"[binary sha={oh} size={len(old)}]",
                after_content=f"[binary sha={nh} size={len(new_data)}]",
                before_bytes=old,
                after_bytes=new_data,
                is_delete=False,
            )

        old_lines = old.decode("utf-8", errors="replace").splitlines()
        new_lines = new_data.decode("utf-8", errors="replace").splitlines()
        delta = list(
            difflib.unified_diff(
                old_lines,
                new_lines,
                fromfile=f"a/{path.name}",
                tofile=f"b/{path.name}",
                lineterm="",
                n=2,
            )
        )
        added = sum(1 for ln in delta if ln.startswith("+") and not ln.startswith("+++"))
        removed = sum(1 for ln in delta if ln.startswith("-") and not ln.startswith("---"))
        summary = f"MODIFY +{added} -{removed}"
        body = "!!! MODIFY !!!\n" + ("\n".join(delta) if delta else "(no line diff)")
        if len(body) > DIFF_STORE_LIMIT:
            body = body[:DIFF_STORE_LIMIT] + "\n… [truncated]"
        return ChangeRecord(
            kind="MODIFY",
            summary=summary,
            content_diff=body,
            before_content=before,
            after_content=after,
            before_bytes=old,
            after_bytes=new_data,
            is_delete=False,
        )


STORE = EventStore()
STOP = threading.Event()


def _looks_binary(data: bytes) -> bool:
    if not data:
        return False
    return b"\x00" in data[:512]


def _bytes_to_stored_text(data: bytes) -> str:
    if not data:
        return ""
    if _looks_binary(data):
        digest = hashlib.sha256(data).hexdigest()[:16]
        return f"[binary sha={digest} size={len(data)}]"
    text = data.decode("utf-8", errors="replace")
    if len(text) > CONTENT_STORE_LIMIT:
        return text[:CONTENT_STORE_LIMIT] + "\n… [truncated]"
    return text


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

def setup_logging() -> logging.Logger:
    logger = logging.getLogger("snitch")
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
# Honey-file init
# ---------------------------------------------------------------------------

def init_honey_files() -> List[Path]:
    SNITCH_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    created: List[Path] = []
    for name in HONEY_FILES:
        path = SNITCH_DIR / name
        if not path.exists():
            path.write_bytes(HONEY_CONTENT[name])
            path.chmod(0o600)
        data = path.read_bytes()
        STORE.set_file_snapshot(path, data)
        supabase_upsert_snapshot(path, data, is_deleted=False)
        created.append(path)
    LOG.info("bait ready under %s (%d files)", SNITCH_DIR, len(created))
    return created


# ---------------------------------------------------------------------------
# Supabase archive — events + live snapshots
# ---------------------------------------------------------------------------

def _sb_headers(**extra: str) -> Dict[str, str]:
    headers = {
        "apikey": SUPABASE_KEY,
        "Authorization": f"Bearer {SUPABASE_KEY}",
        "Content-Type": "application/json",
        "Prefer": "return=minimal",
    }
    headers.update(extra)
    return headers


def supabase_insert_event(payload: Dict[str, object]) -> None:
    if not STORE.supabase_ok:
        return
    try:
        url = f"{SUPABASE_URL}/rest/v1/snitch_events"
        resp = requests.post(url, headers=_sb_headers(), json=payload, timeout=6)
        if resp.status_code >= 400:
            STORE.last_error = f"supabase {resp.status_code}"
            LOG.warning("supabase event insert failed: %s %s", resp.status_code, resp.text[:200])
        else:
            with STORE._lock:
                STORE.cloud_count += 1
    except Exception as exc:  # noqa: BLE001
        STORE.last_error = f"supabase: {exc}"
        LOG.warning("supabase event insert error: %s", exc)


def supabase_upsert_snapshot(path: Path, data: Optional[bytes], *, is_deleted: bool) -> None:
    """Remember current bait contents in Supabase (overwrite each modify / mark deletes)."""
    if not STORE.supabase_ok:
        return
    try:
        if is_deleted or data is None:
            payload = {
                "host": HOST,
                "file_name": path.name,
                "file_path": str(path),
                "content": None,
                "content_sha": None,
                "byte_size": 0,
                "is_deleted": True,
                "updated_at": datetime.now(timezone.utc).isoformat(),
            }
        else:
            payload = {
                "host": HOST,
                "file_name": path.name,
                "file_path": str(path),
                "content": _bytes_to_stored_text(data),
                "content_sha": hashlib.sha256(data).hexdigest(),
                "byte_size": len(data),
                "is_deleted": False,
                "updated_at": datetime.now(timezone.utc).isoformat(),
            }
        url = f"{SUPABASE_URL}/rest/v1/snitch_snapshots"
        resp = requests.post(
            url,
            headers=_sb_headers(**{"Prefer": "resolution=merge-duplicates,return=minimal"}),
            params={"on_conflict": "host,file_name"},
            json=payload,
            timeout=6,
        )
        if resp.status_code >= 400:
            STORE.last_error = f"snap {resp.status_code}"
            LOG.warning("supabase snapshot upsert failed: %s %s", resp.status_code, resp.text[:200])
    except Exception as exc:  # noqa: BLE001
        STORE.last_error = f"snap: {exc}"
        LOG.warning("supabase snapshot error: %s", exc)


def supabase_fetch(sort_order: str, limit: int = 5) -> List[Dict[str, str]]:
    if not STORE.supabase_ok:
        return []
    try:
        url = f"{SUPABASE_URL}/rest/v1/snitch_events"
        headers = {**_sb_headers(), "Prefer": "count=exact"}
        resp = requests.get(
            url,
            headers=headers,
            params={
                "select": "created_at,event_type,change_kind,file_name,pid,action,diff_summary,is_delete",
                "order": sort_order,
                "limit": str(limit),
            },
            timeout=6,
        )
        if resp.status_code >= 400:
            STORE.last_error = f"supabase get {resp.status_code}"
            return []
        content_range = resp.headers.get("content-range", "")
        if "/" in content_range:
            total = content_range.split("/")[-1]
            if total.isdigit():
                with STORE._lock:
                    STORE.cloud_count = max(STORE.cloud_count, int(total))
        rows = []
        for item in resp.json():
            ts = str(item.get("created_at", ""))[11:19] or "—"
            kind = str(item.get("change_kind") or item.get("event_type") or "")
            if item.get("is_delete"):
                kind = "DELETE!"
            rows.append(
                {
                    "time": ts,
                    "event": kind,
                    "file": str(item.get("file_name", "")),
                    "pid": str(item.get("pid") or "—"),
                    "action": str(item.get("action", "")),
                    "diff": str(item.get("diff_summary") or "")[:40],
                }
            )
        return rows
    except Exception as exc:  # noqa: BLE001
        STORE.last_error = f"supabase: {exc}"
        LOG.warning("supabase fetch error: %s", exc)
        return []


def refresh_cloud_peek() -> None:
    label, order = SORT_MODES[STORE.sort_idx]
    rows = supabase_fetch(order, limit=5)
    with STORE._lock:
        STORE.peek_label = label
        STORE.peek_rows = rows


def cycle_sort() -> None:
    STORE.sort_idx = (STORE.sort_idx + 1) % len(SORT_MODES)
    refresh_cloud_peek()


# ---------------------------------------------------------------------------
# Attribution + kill
# ---------------------------------------------------------------------------

def pids_holding_file(path: Path) -> Set[int]:
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


def terminate_pid(pid: int) -> Tuple[bool, str]:
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
    except Exception as exc:  # noqa: BLE001
        return False, f"error: {exc}"


def alert_discord(details: Dict[str, str]) -> None:
    if not DISCORD_WEBHOOK_URL:
        return
    try:
        event = str(details.get("event", "")).upper()
        if event.startswith("DELETE"):
            title = "snitch // DELETE!"
            color = DISCORD_COLOR_DELETE
        elif event.startswith("MODIFY"):
            title = "snitch // MODIFY"
            color = DISCORD_COLOR_MODIFY
        else:
            title = "snitch // tripwire hit"
            color = DISCORD_COLOR_DEFAULT
        embed = {
            "title": title,
            "color": color,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "fields": [
                {
                    "name": k.replace("_", " "),
                    "value": (str(v)[:900] or "—"),
                    "inline": False,
                }
                for k, v in details.items()
            ],
            "footer": {"text": "snitch"},
        }
        resp = requests.post(
            DISCORD_WEBHOOK_URL,
            json={"embeds": [embed]},
            timeout=5,
        )
        if resp.status_code >= 400:
            LOG.warning("discord HTTP %s: %s", resp.status_code, resp.text[:200])
    except Exception as exc:  # noqa: BLE001
        LOG.warning("discord failed: %s", exc)


def _read_optional(path: Path) -> Optional[bytes]:
    try:
        return path.read_bytes()
    except OSError:
        return None


def record_event(
    *,
    path: Path,
    pid: str,
    process: str,
    action: str,
    change: ChangeRecord,
) -> None:
    now = datetime.now().strftime("%H:%M:%S")
    display_event = "DELETE!" if change.is_delete else change.kind
    row = {
        "time": now,
        "event": display_event,
        "file": path.name,
        "pid": pid,
        "process": process[:48],
        "action": action,
        "diff": change.summary[:48],
    }
    STORE.add(row)

    log_line = (
        f"{display_event} on {path} | PID {pid} | {process} | {action} | {change.summary}"
    )
    if change.content_diff:
        LOG.critical("%s\nCHANGE:\n%s", log_line, change.content_diff)
    else:
        LOG.critical("%s", log_line)

    discord_title_bits = {
        "event": display_event,
        "file": str(path),
        "pid": pid,
        "process": process,
        "action": action,
        "summary": change.summary,
        "what_changed": (change.content_diff[:700] if change.content_diff else "n/a"),
        "before": (change.before_content[:400] if change.before_content else "[empty]"),
        "after": (
            "[DELETED — file gone]"
            if change.is_delete
            else (change.after_content[:400] if change.after_content else "[empty]")
        ),
        "host": HOST,
    }
    alert_discord(discord_title_bits)

    # Remember latest contents in the cloud snapshot table
    supabase_upsert_snapshot(
        path,
        change.after_bytes,
        is_deleted=change.is_delete,
    )

    # Full incident row (before/after + diff) for sorting/history
    supabase_insert_event(
        {
            "host": HOST,
            "event_type": "DELETED" if change.is_delete else "MODIFIED",
            "change_kind": change.kind,
            "file_name": path.name,
            "file_path": str(path),
            "pid": pid if pid != "—" else None,
            "process_info": process,
            "action": action,
            "diff_summary": change.summary,
            "content_diff": change.content_diff or None,
            "before_content": change.before_content or None,
            "after_content": (
                None if change.is_delete else (change.after_content or None)
            ),
            "is_delete": change.is_delete,
        }
    )


def handle_tripwire(path: Path, event_type: str) -> None:
    new_data: Optional[bytes]
    if event_type == "DELETED":
        new_data = None
    else:
        new_data = _read_optional(path)

    change = STORE.take_change(path, new_data)
    pids = pids_holding_file(path) if path.exists() else set()

    if not pids:
        record_event(
            path=path,
            pid="—",
            process="unattributed",
            action="LOGGED",
            change=change,
        )
        return

    for pid in sorted(pids):
        ok, detail = terminate_pid(pid)
        record_event(
            path=path,
            pid=str(pid),
            process=detail,
            action="KILLED" if ok else "FAILED",
            change=change,
        )


# ---------------------------------------------------------------------------
# Watchdog
# ---------------------------------------------------------------------------

class SnitchHandler(FileSystemEventHandler):
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
# TUI — matrix (black / dark green / white), live-only + tiny cloud peek
# ---------------------------------------------------------------------------

def _self_stats() -> Tuple[float, float]:
    try:
        p = psutil.Process(OUR_PID)
        return p.cpu_percent(interval=None), p.memory_info().rss / (1024 * 1024)
    except psutil.Error:
        return 0.0, 0.0


def build_layout() -> Layout:
    layout = Layout(name="root")
    layout.split_column(
        Layout(name="header", size=3),
        Layout(name="body"),
        Layout(name="peek", size=9),
        Layout(name="footer", size=4),
    )
    layout["body"].split_row(
        Layout(name="status", ratio=1),
        Layout(name="events", ratio=3),
    )
    layout["header"].update(
        Panel(
            Text("snitch", justify="center", style=f"bold {C_WHITE}"),
            style=C_GREEN,
            box=BOX,
            border_style=BORDER,
        )
    )
    for name in ("status", "events", "peek", "footer"):
        layout[name].update(Panel("…", border_style=BORDER, box=BOX))
    return layout


def render_status(file_count: int) -> Panel:
    cloud = "online" if STORE.supabase_ok else "offline"
    body = Table.grid(padding=(0, 1))
    body.add_column(style=f"bold {C_DIM}", justify="right")
    body.add_column(style=C_WHITE)
    body.add_row("state", f"[{C_ALERT}]armed[/]")
    body.add_row("bait", str(SNITCH_DIR))
    body.add_row("files", str(file_count))
    body.add_row("killed", str(STORE.blocked_count))
    body.add_row("discord", "on" if DISCORD_WEBHOOK_URL else "off")
    body.add_row("supabase", cloud)
    body.add_row("archived", str(STORE.cloud_count))
    body.add_row("pid", str(OUR_PID))
    if STORE.last_error:
        body.add_row("err", Text(STORE.last_error[:36], style="bold green"))
    return Panel(body, title="status", title_align="left", border_style=BORDER, box=BOX, style="black")


def render_events() -> Panel:
    table = Table(
        box=box.SIMPLE_HEAD,
        expand=True,
        show_edge=False,
        pad_edge=False,
        header_style=f"bold {C_GREEN}",
        border_style=BORDER,
    )
    table.add_column("time", style=C_DIM, width=8)
    table.add_column("event", width=9)
    table.add_column("file", style=C_WHITE, ratio=1)
    table.add_column("pid", style=C_DIM, width=7)
    table.add_column("change", style=C_GREEN, ratio=1)
    table.add_column("action", width=7)

    rows = STORE.snapshot_events()
    if not rows:
        table.add_row("—", "—", "waiting…", "—", "—", "—")
    else:
        for r in rows:
            ev = r["event"]
            if ev.startswith("DELETE"):
                event_style = C_DELETE
            elif ev.startswith("MODIFY"):
                event_style = C_MODIFY
            else:
                event_style = C_GREEN
            action_style = C_ALERT if r["action"] == "KILLED" else C_WHITE
            change_style = C_DELETE if ev.startswith("DELETE") else (
                C_MODIFY if ev.startswith("MODIFY") else C_GREEN
            )
            table.add_row(
                r["time"],
                Text(ev, style=event_style),
                r["file"],
                r["pid"],
                Text(r.get("diff", "") or "—", style=change_style),
                Text(r["action"], style=action_style),
            )
    return Panel(
        table,
        title="live (session only)",
        title_align="left",
        border_style=BORDER,
        box=BOX,
        style="black",
    )


def render_peek() -> Panel:
    """Compact cloud archive peek — sorted in Supabase, not dumped into live."""
    if not STORE.supabase_ok:
        tip = Text(
            "set SUPABASE_URL + SUPABASE_KEY → past events live in the cloud\n"
            "run sql/snitch_events.sql in the Supabase SQL editor once",
            style=C_DIM,
        )
        return Panel(tip, title="archive", title_align="left", border_style=BORDER, box=BOX, style="black")

    table = Table(box=box.SIMPLE_HEAD, expand=True, show_edge=False, header_style=C_DIM)
    table.add_column("time", width=8, style=C_DIM)
    table.add_column("event", width=9, style=C_GREEN)
    table.add_column("file", style=C_WHITE, ratio=1)
    table.add_column("action", width=7, style=C_GREEN)
    table.add_column("diff", style=C_DIM, ratio=1)

    with STORE._lock:
        label = STORE.peek_label
        rows = list(STORE.peek_rows)

    if not rows:
        table.add_row("—", "—", "press s to load / cycle sort", "—", "—")
    else:
        for r in rows:
            ev = r["event"]
            if ev.startswith("DELETE"):
                ev_style = C_DELETE
            elif ev.startswith("MODIFY"):
                ev_style = C_MODIFY
            else:
                ev_style = C_GREEN
            table.add_row(
                r["time"],
                Text(ev, style=ev_style),
                r["file"],
                r["action"],
                Text(r.get("diff", "—"), style=ev_style),
            )

    title = Text("archive peek · sort=", style=C_DIM)
    title.append(label, style=C_ALERT)
    title.append(" · ", style=C_DIM)
    title.append("s", style=C_ALERT)
    title.append(" cycle  ", style=C_WHITE)
    title.append("r", style=C_ALERT)
    title.append(" refresh", style=C_WHITE)
    return Panel(table, title=title, title_align="left", border_style=BORDER, box=BOX, style="black")


def render_footer() -> Panel:
    cpu, mem = _self_stats()
    line = Text(style=C_WHITE)
    line.append(f"cpu {cpu:4.1f}%  ", style=C_GREEN)
    line.append(f"rss {mem:5.1f}M  ", style=C_GREEN)
    line.append(f"host {psutil.cpu_percent(interval=None):4.1f}%  ", style=C_DIM)
    line.append("│  ", style=C_DIM)
    line.append("s", style=C_ALERT)
    line.append(" sort  ", style=C_WHITE)
    line.append("r", style=C_ALERT)
    line.append(" refresh  ", style=C_WHITE)
    line.append("ctrl+c", style=C_ALERT)
    line.append(" quit", style=C_WHITE)
    return Panel(line, title="snitch", title_align="left", border_style=BORDER, box=BOX, style="black")


def refresh_layout(layout: Layout, file_count: int) -> None:
    layout["status"].update(render_status(file_count))
    layout["events"].update(render_events())
    layout["peek"].update(render_peek())
    layout["footer"].update(render_footer())


def input_listener() -> None:
    """Non-blocking-ish key reader for s/r without leaving Live."""
    try:
        import tty
        import termios
    except ImportError:
        return

    fd = sys.stdin.fileno()
    try:
        old = termios.tcgetattr(fd)
    except termios.error:
        return
    try:
        tty.setcbreak(fd)
        while not STOP.is_set():
            # select-style wait
            import select

            ready, _, _ = select.select([sys.stdin], [], [], 0.25)
            if not ready:
                continue
            ch = sys.stdin.read(1)
            if ch in ("s", "S"):
                cycle_sort()
            elif ch in ("r", "R"):
                refresh_cloud_peek()
    finally:
        try:
            termios.tcsetattr(fd, termios.TCSADRAIN, old)
        except termios.error:
            pass


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    if sys.platform not in ("darwin", "linux"):
        print("snitch targets macOS or Linux only.", file=sys.stderr)
        return 1
    if which("lsof") is None:
        print("lsof is required but was not found on PATH.", file=sys.stderr)
        return 1

    honey = init_honey_files()
    watched = {p.name for p in honey}

    psutil.Process(OUR_PID).cpu_percent(interval=None)
    psutil.cpu_percent(interval=None)

    if STORE.supabase_ok:
        refresh_cloud_peek()

    handler = SnitchHandler(watched)
    observer = Observer()
    observer.schedule(handler, str(SNITCH_DIR), recursive=False)
    observer.daemon = True
    observer.start()
    LOG.info("observer started on %s", SNITCH_DIR)

    def _shutdown(*_args: object) -> None:
        STOP.set()

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    t = threading.Thread(target=input_listener, name="keys", daemon=True)
    t.start()

    console = Console(style=Style(color="green", bgcolor="black"))
    layout = build_layout()
    refresh_layout(layout, len(honey))

    try:
        with Live(layout, console=console, refresh_per_second=REFRESH_HZ, screen=True):
            while not STOP.is_set():
                refresh_layout(layout, len(honey))
                time.sleep(1.0 / REFRESH_HZ)
    finally:
        STOP.set()
        observer.stop()
        observer.join(timeout=5)
        LOG.info("shutdown. killed=%d", STORE.blocked_count)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
