"""Shared utility functions."""

from __future__ import annotations

import logging
import re
import socket
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

_RESOLVE_CACHE: dict[str, str] = {}

FILETIME_EPOCH_DIFF = 116444736000000000
FILETIME_PER_SEC = 10000000


def filetime_days_ago(val: str | int | None) -> int | None:
    """Convert a Windows FILETIME value to the number of days ago it represents.

    Returns ``None`` if the value is missing, zero, or unparseable.
    """
    if val is None or str(val) == "0":
        return None
    try:
        ticks = int(val)
        if ticks <= 0:
            return None
        unix = (ticks - FILETIME_EPOCH_DIFF) / FILETIME_PER_SEC
        dt = datetime.fromtimestamp(unix, tz=timezone.utc)
        return (datetime.now(timezone.utc) - dt).days
    except (ValueError, OSError):
        return None


def resolve_ip(hostname: str, caller_logger: logging.Logger | None = None) -> str:
    """Resolve a hostname to an IP: DNS first, then NetBIOS (best-effort).

    If already an IP, returns it. Returns the resolved IP, or the original
    hostname if both DNS and NetBIOS fail. Results are cached per hostname.
    """
    log = caller_logger or logger
    if hostname in _RESOLVE_CACHE:
        return _RESOLVE_CACHE[hostname]

    # Already an IP?
    try:
        socket.inet_aton(hostname)
        _RESOLVE_CACHE[hostname] = hostname
        return hostname
    except OSError:
        pass

    # DNS
    try:
        ip = socket.gethostbyname(hostname)
        log.info("Resolved %s -> %s (DNS)", hostname, ip)
        _RESOLVE_CACHE[hostname] = ip
        return ip
    except socket.gaierror as exc:
        log.debug("DNS resolution failed for %s: %s", hostname, exc)

    # NetBIOS fallback (best-effort, local subnet, UDP/137)
    ip = _netbios_resolve(hostname, log)
    if ip:
        log.info("Resolved %s -> %s (NetBIOS)", hostname, ip)
        _RESOLVE_CACHE[hostname] = ip
        return ip

    log.warning("Failed to resolve %s (DNS + NetBIOS)", hostname)
    _RESOLVE_CACHE[hostname] = hostname
    return hostname


def _netbios_resolve(hostname: str, log: logging.Logger) -> str | None:
    """Best-effort NetBIOS name query of the short name. Returns IP or None."""
    short = hostname.split(".")[0]
    try:
        from impacket import nmb
        nb = nmb.NetBIOS()
        resp = nb.gethostbyname(short, nmb.TYPE_SERVER)
        entries = getattr(resp, "entries", None)
        if entries:
            return entries[0]
    except Exception as exc:
        log.debug("NetBIOS resolution failed for %s: %s", short, exc)
    return None


def _strip_ansi(text: str) -> str:
    """Strip ANSI escape codes and carriage returns from PTY output."""
    text = re.sub(r'\x1b\[[0-9;]*[a-zA-Z]|\x1b\].*?\x07', '', text)
    return text.replace('\r', '')


def _timed_prompt(prompt_text: str, default: str = "", timeout: float = 3.0,
                  auto_msg: str = "") -> str:
    """Prompt with auto-proceed countdown.

    Displays a countdown timer.  If the operator presses Enter (or any key
    followed by Enter) before the timer elapses, their input is used.
    Otherwise the default value is returned automatically.

    Args:
        prompt_text: Text to display before the countdown.
        default: Value returned on timeout or empty Enter.
        timeout: Seconds to wait before auto-proceeding.
        auto_msg: Custom auto-proceed message (e.g. "auto-proceeding with 'bob' in").

    Returns:
        The operator's input, or *default* if timed out / Enter pressed.
    """
    import select
    import sys

    # Use print() not console.print() — Rich eats [x] as markup tags
    if not auto_msg:
        auto_msg = "auto-proceed in"
    timer_note = f"({auto_msg} {timeout:.0f}s, Enter to continue)"
    print(f"  {prompt_text} {timer_note} ", end="", flush=True)

    try:
        ready, _, _ = select.select([sys.stdin], [], [], timeout)
        if ready:
            answer = sys.stdin.readline().strip()
            return answer if answer else default
        else:
            # Timeout — auto-proceed
            print(default)
            return default
    except (EOFError, KeyboardInterrupt):
        print()
        return default
