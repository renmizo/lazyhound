"""CLI output formatting helpers – mirrors lazyhound finder formatting patterns."""

from __future__ import annotations

import os
import random
import shutil
import sys
import time

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from lazyhound import __version__

console = Console()

# LazyHound wordmark (figlet).
_ART = r"""    __                      __  __                      __
   / /   ____ _____  __  __/ / / /___  __  ______  ____/ /
  / /   / __ `/_  / / / / / /_/ / __ \/ / / / __ \/ __  / 
 / /___/ /_/ / / /_/ /_/ / __  / /_/ / /_/ / / / / /_/ /  
/_____/\__,_/ /___/\__, /_/ /_/\____/\__,_/_/ /_/\__,_/   
                  /____/                                  """


def _build_banner() -> list:
    """LazyHound ASCII splash as Rich Text lines (static form)."""
    return [Text(line, style="bold cyan") for line in _ART.splitlines()]


BANNER_LINES = _build_banner()

VERSION_SUBTITLE = (
    "[bold white]  Active Directory & Entra Attack-Path Analysis[/bold white]\n"
    f"[dim]  v{__version__} | github.com/renmizo/lazyhound[/dim]"
)


# ---------------------------------------------------------------------------
# Animated splash — a "reverse dissolve": the logo materialises out of noise.
# ---------------------------------------------------------------------------
_NOISE = "@#%&*+=~/\\|<>:.-"


def _animation_enabled(lines: list[str]) -> bool:
    """Animate only on an interactive terminal wide enough for the art, and not
    when LAZYHOUND_NO_ANIM is set (pipes/CI/redirects always fall back)."""
    if os.environ.get("LAZYHOUND_NO_ANIM"):
        return False
    try:
        if not sys.stdout.isatty():
            return False
    except Exception:
        return False
    cols = shutil.get_terminal_size((80, 24)).columns
    return cols >= max((len(line) for line in lines), default=0)


def _dissolve(lines: list[str], frames: int = 16, delay: float = 0.035) -> None:
    """Reveal the art by resolving each cell out of random noise, in random
    order, over a few frames — redrawn in place with ANSI cursor moves."""
    h = len(lines)
    widths = [len(line) for line in lines]
    cells = [(r, c) for r in range(h) for c in range(widths[r]) if lines[r][c] != " "]
    random.shuffle(cells)
    per = max(1, -(-len(cells) // frames))     # ceil: cells revealed per frame
    revealed: set = set()
    out = sys.stdout
    out.write("\n" * h)                        # reserve the block
    out.flush()
    i = 0
    try:
        while True:
            for _ in range(per):
                if i < len(cells):
                    revealed.add(cells[i])
                    i += 1
            done = i >= len(cells)
            out.write(f"\x1b[{h}A")             # cursor to the top of the block
            for r in range(h):
                buf = []
                for c in range(widths[r]):
                    ch = lines[r][c]
                    if ch == " ":
                        buf.append(" ")
                    elif (r, c) in revealed:
                        buf.append(ch)
                    else:
                        buf.append(random.choice(_NOISE))
                out.write("\x1b[1;36m" + "".join(buf) + "\x1b[0m\x1b[K\n")
            out.flush()
            if done:
                break
            time.sleep(delay)
    except BaseException:
        # The splash must never break startup — leave a clean static logo.
        out.write(f"\x1b[{h}A")
        for line in lines:
            out.write("\x1b[1;36m" + line + "\x1b[0m\x1b[K\n")
        out.flush()


def _render_logo() -> None:
    lines = _ART.splitlines()
    if _animation_enabled(lines):
        _dissolve(lines)
    else:
        for line in BANNER_LINES:
            console.print(line, highlight=False)


def show_banner() -> None:
    _render_logo()
    console.print("[bold white]  AD & Entra Attack-Path Analysis[/bold white]")
    console.print(f"[dim]  v{__version__} | MAP: collect → search → analyze   "
                  "·   ASSESS: scan → report[/dim]\n")


def show_version() -> None:
    """Animated logo + version subtitle (used by the 'version' command)."""
    _render_logo()
    console.print()
    console.print(VERSION_SUBTITLE)


def show_command_help(title: str, help_text: str) -> None:
    console.print(Panel(
        Text(help_text),
        title=f"[bold]{title}[/bold]",
        border_style="cyan",
    ))


# ---------------------------------------------------------------------------
# Detailed per-command help with parameters and examples
# ---------------------------------------------------------------------------

_COMMAND_HELP: dict[str, str] = {
    "domain": (
        "[bold]domain[/bold] [<fqdn|netbios|sid>]\n\n"
        "Show or switch the ACTIVE domain for a multi-domain (forest) collection.\n"
        "The active domain is the default scope for search/analyze commands and is\n"
        "shown in the prompt. Single-domain collections don't need this.\n\n"
        "[bold]Usage:[/bold]\n"
        "  domain                     list the domains in the collection (* = active)\n"
        "  domain <fqdn|netbios|sid>  set the active domain (updates the prompt)\n\n"
        "[bold]Related:[/bold] every search/analyze command takes [bold]--domain all|<fqdn>[/bold]\n"
        "as a one-shot override; 'all' = forest-wide. See e.g. 'members --help'.\n\n"
        "[bold]Examples:[/bold]\n"
        "  domain                     GLOBEX.CORP (GLOBEX) S-1-5-21-… 1820 objs\n"
        "  domain acme.corp        switch default to ACME.CORP\n"
        "  members \"domain admins\" --domain all     forest-wide, Domain column"
    ),
    "options": (
        "[bold]options[/bold] [key=value ...] | all | clear\n\n"
        "View or set connection settings used for collection and scans. With no\n"
        "arguments, shows only the options you've explicitly set; 'options all'\n"
        "shows every setting including defaults.\n\n"
        "[bold]Connection identity:[/bold]\n"
        "  dc            Domain controller host / IP\n"
        "  domain        Target domain (e.g. corp.local)\n"
        "  username      Bind username\n"
        "  port          LDAP port (default: 389)\n"
        "  auth_method   ntlm | simple | kerberos (default: ntlm)\n\n"
        "[bold]Credential[/bold] (mutually exclusive — setting one clears the others):\n"
        "  password      Bind password (masked in output)\n"
        "  nthash        NT hash for pass-the-hash: bare 32-hex or LM:NT\n"
        "  ccache        Kerberos credential cache path (forces GSSAPI). A\n"
        "                krb5.conf is auto-generated for the realm; needs the DC\n"
        "                FQDN and the 'gssapi' package for LDAP (collect/scan).\n\n"
        "[bold]Transport[/bold] (also set in lazyhound.yml; shown under 'options all'):\n"
        "  use_ssl, use_start_tls, validate_cert, timeout, nameserver\n\n"
        "[bold]Usage:[/bold]\n"
        "  options                  show the options you've set\n"
        "  options all              show every setting (incl. defaults)\n"
        "  options <key>=<value>    set a value\n"
        "  options <key>=           clear a single key\n"
        "  options clear            reset all connection settings\n\n"
        "[bold]Examples:[/bold]\n"
        "  options dc=10.0.0.1 domain=corp.local username=admin\n"
        "  options password=P@ssw0rd\n"
        "  options nthash=aad3b435...:e19ccf75...   pass-the-hash\n"
        "  options ccache=/tmp/admin.ccache         Kerberos (TGT from kinit/getTGT)\n"
        "  options all"
    ),
}

# Verbose per-command help for the collect/search/analyze menus (keyed
# "<submenu>:<cmd>"), kept in a separate module to stay manageable.
from lazyhound.menu_help import MENU_HELP  # noqa: E402
_COMMAND_HELP.update(MENU_HELP)


def show_detailed_help(cmd_name: str, commands: list[tuple[str, str, str]],
                       submenu: str = "") -> None:
    """Show detailed help for a specific command.

    A command name can exist in several submenus (e.g. 'run', 'export'); a
    submenu-namespaced entry ('analyze:run') wins over the bare name so each
    menu shows its own help."""
    # Check for rich help first — namespaced ("submenu:cmd") then bare.
    ns = f"{submenu}:{cmd_name}"
    key = ns if (submenu and ns in _COMMAND_HELP) else cmd_name
    if key in _COMMAND_HELP:
        console.print(Panel(
            Text.from_markup(_COMMAND_HELP[key]),
            title=f"[bold cyan]Help: {cmd_name}[/bold cyan]",
            border_style="cyan",
        ))
        return

    # Fall back to basic help from command tuple
    for name, args, desc in commands:
        if name == cmd_name:
            console.print(f"\n[bold]{name}[/bold] {args}")
            console.print(f"  {desc}\n")
            return
    console.print(f"[red]Unknown command: {cmd_name}[/red]")


def pop_flag(tokens: list[str], flag: str) -> bool:
    """Remove a boolean flag from tokens and return True if found."""
    for i, t in enumerate(tokens):
        if t == flag:
            tokens.pop(i)
            return True
    return False


def pop_option(tokens: list[str], name: str, default: str = "") -> str:
    """Remove --name VALUE or -name VALUE from tokens and return VALUE."""
    flags = {f"--{name}", f"-{name}"}
    for i, t in enumerate(tokens):
        if t in flags and i + 1 < len(tokens):
            tokens.pop(i)
            return tokens.pop(i)
    return default


def pop_top_skip(tokens: list[str]) -> tuple[int, int]:
    """Extract --top N and --skip M from tokens."""
    top = int(pop_option(tokens, "top", "50"))
    skip = int(pop_option(tokens, "skip", "0"))
    return top, skip
