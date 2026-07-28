"""Interactive readline-based REPL for LazyHound.

Mirrors lazyhound finder's shell architecture with submenu navigation,
tab completion, and Rich console output.
"""

from __future__ import annotations

import json
import os
import readline
import shlex
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich.text import Text

from lazyhound.config import Config
from lazyhound.finder.finder_utils import _timed_prompt
from lazyhound.formatting import (
    BANNER_LINES,
    VERSION_SUBTITLE,
    pop_flag,
    pop_option,
    pop_top_skip,
    show_banner,
    show_command_help,
    show_detailed_help,
)
from lazyhound.storage.history import HistoryStore

console = Console()

# Remembers the last project folder chosen at first-run so that launching
# ``lazyhound`` from an unconfigured directory defaults the prompt to it.
_LAST_PROJECT_FILE = Path.home() / ".lazyhound" / "last_project"


def _load_last_project() -> str | None:
    """Return the most recently used project folder, or None."""
    try:
        path = _LAST_PROJECT_FILE.read_text(encoding="utf-8").strip()
    except OSError:
        return None
    return path if path and Path(path).is_dir() else None


def _save_last_project(path: str) -> None:
    """Persist *path* as the most recently used project folder."""
    try:
        _LAST_PROJECT_FILE.parent.mkdir(parents=True, exist_ok=True)
        _LAST_PROJECT_FILE.write_text(path, encoding="utf-8")
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Command definitions: (name, args_hint, description)
# ---------------------------------------------------------------------------

_MAIN_COMMANDS = [
    ("collect", "run [flags] | <subcommand>", "Collect AD (LDAP) & Entra (Graph); import/export BloodHound & AzureHound"),
    ("analyze", "run [flags] | <subcommand>", "Attack-path analysis (graph-based)"),
    ("scan", "run [flags] | <subcommand>", "Live security assessment (76 checks)"),
    ("report", "run [--type analyze|scan|heatmap|dashboard|graph|killchain|radar|target|leaderboard] …", "Report generation from analyze or scan data"),
    ("search", "<subcommand> …", "Explore collected AD & Entra data"),
    ("options", "[key=value ...]", "View/set connection settings"),
    ("domain", "[<fqdn|netbios|sid>]", "Show/switch the active domain"),
    ("version", "", "Show version information"),
    ("help", "[verb]", "Show help; 'help <verb>' lists a verb's subcommands"),
    ("exit", "", "Exit shell"),
]

# Top-level menu groups (display only): the two workflow tracks.
# Anything not listed here falls under "General".
_MAIN_GROUPS = [
    ("Map", ["collect", "search", "analyze"]),
    ("Assess", ["scan", "report"]),
]

_COLLECT_COMMANDS = [
    ("run", "[--stealth low|med|high] [--nodisabled] [--slim] [--adcs] [--network]", "Run LDAP collection from DC (--adcs/--network chain enrichment after)"),
    ("crawl", "[--targets all|dcs|servers|workstations] [--batch-size N]", "Session + local group enumeration via SMB"),
    ("adcs", "", "CA-host ADCS enrichment (ESC6/7/8/11) of the loaded collection"),
    ("clear", "--sessions | --local-admins | --adcs | --all", "Strip crawl-derived data from collection"),
    ("load", "<collection_id|file>", "Load a previous collection"),
    ("unload", "", "Unload the current collection from memory"),
    ("list", "", "List stored collections"),
    ("stats", "", "Quick collection summary (objects, realms, totals)"),
    ("delete", "<collection_id> | --all", "Delete a stored collection"),
    ("export", "[--bloodhound] [--azurehound] [--raw] -o <path>", "Export collection data (BloodHound .zip / AzureHound .json / raw)"),
    ("import", "<bloodhound.zip|json> [--nodisabled] [--slim]", "Import BloodHound/raw data"),
    ("azure", "<azurehound.json> | --run --tenant <id|domain> [--username <upn> | --device-code | --client-id <id>] [--nodisabled] [--slim]", "Collect Entra live via Graph (user or service-principal auth) or import AzureHound JSON"),
    ("options", "[key=value ...]", "View/set connection settings"),
    ("search", "", "Jump to the search menu (Ctrl+S)"),
    ("analyze", "", "Jump to the analyze menu"),
    ("scan", "", "Jump to the scan menu"),
    ("report", "", "Jump to the report menu"),
    ("domain", "[<fqdn|netbios|sid>]", "Show/switch the active domain (multi-domain collections)"),
    ("back", "", "Return to main menu"),
    ("help", "[command]", "Show help"),
]

_SCAN_COMMANDS = [
    ("run", "[--category CAT] [--check ID] [--exclude ID] [--profile strict|balanced|lenient] [--no-collection]", "Run security scan (collection-aware if one is loaded)"),
    ("checks", "", "List available scan checks (75)"),
    ("list", "", "List past scans"),
    ("show", "<scan_id>", "Re-render stored scan results"),
    ("delete", "<scan_id> | --all", "Delete a stored scan"),
    ("diff", "<id_a> <id_b>", "Compare two scans"),
    ("export", "<scan_id> --format <fmt> -o <path>", "Export scan results"),
    ("scoring", "[--profile strict|balanced|lenient]", "Show the scoring/grading model scans will use"),
    ("options", "[key=value ...]", "View/set connection settings"),
    ("collect", "", "Jump to the collect menu"),
    ("search", "", "Jump to the search menu (Ctrl+S)"),
    ("analyze", "", "Jump to the analyze menu"),
    ("report", "", "Jump to the report menu"),
    ("domain", "[<fqdn|netbios|sid>]", "Show/switch the active domain (multi-domain collections)"),
    ("back", "", "Return to main menu"),
    ("help", "[command]", "Show help"),
]

_SEARCH_COMMANDS = [
    ("info", "<object> [--domain all|<fqdn>]", "Object details (name, SID, DN)"),
    ("members", "<group> [--recursive] [--domain all|<fqdn>]", "Group membership"),
    ("memberof", "<principal> [--domain all|<fqdn>]", "Groups a principal belongs to"),
    ("acl", "<object> [--domain all|<fqdn>]", "DACL for an object"),
    ("who-can", "<right> <target> [--domain all|<fqdn>]", "Principals with a right on target"),
    ("custom", "<filter> [attrs] [--domain all|<fqdn>]", "Open attribute search"),
    ("graph", "<source> [--depth N] [--weighted]", "Attack path graph"),
    ("kerberoastable", "[--domain all|<fqdn>]", "List kerberoastable accounts"),
    ("delegation-map", "[--domain all|<fqdn>]", "All delegation relationships"),
    ("computers", "[--os-filter TEXT] [--domain all|<fqdn>]", "Computer listing"),
    ("trusts", "", "Domain trusts"),
    ("templates", "", "Certificate templates"),
    ("spns", "[--domain all|<fqdn>]", "Objects with SPNs"),
    ("stats", "", "Detailed collection stats (enabled/disabled, realms, OS)"),
    ("collect", "", "Jump to the collect menu"),
    ("analyze", "", "Jump to the analyze menu"),
    ("scan", "", "Jump to the scan menu"),
    ("report", "", "Jump to the report menu"),
    ("domain", "[<fqdn|netbios|sid>]", "Show/switch the active domain (multi-domain collections)"),
    ("back", "", "Return to main menu"),
    ("help", "[command]", "Show help"),
]

_ANALYZE_COMMANDS = [
    ("run", "[--category CAT] [--checks CHK] [--exclude CHK] [--owned USER,...] [--notier0] [--prune] [--aggregate SLUG,...] [--noexpand] [--expand-cap N] [--domain all|<fqdn>]", "Run attack path analysis"),
    ("shortest", "[--from USER] [--to TARGET] [--depth N] [--domain all|<fqdn>]", "Shortest attack paths to DA/high-value"),
    ("trace", "--to <target> [--from <source>] [--depth N] [--domain all|<fqdn>]", "Shortest path(s) to ANY target object"),
    ("paths", "[--show] [--category CAT[,CAT2,...]] [--severity SEV] [--top N] [--show-inherited] [--domain all|<fqdn>]", "Findings summary; --show for full tables, --category to filter"),
    ("graph", "[paths|blast|trusts]", "Render a diagram in the terminal (ASCII)"),
    ("find", "<predicates> [--reaches <target|tier0>] [--from <source>]", "Ad-hoc graph query by attribute/reachability"),
    ("export", "--format <json|csv|ascii|mermaid|dot|svg|png> [--type KIND] [--category CAT] [--severity SEV] [--from ACCT] [--to TARGET] [--domain all|<fqdn>] -o <path>", "Export analysis / diagrams. --category/--severity draws those findings (e.g. laps_read); --from scopes a path to its nearest Tier-Zero target (--to overrides)"),
    ("checks", "", "List available analysis checks"),
    ("collect", "", "Jump to the collect menu"),
    ("search", "", "Jump to the search menu (Ctrl+S)"),
    ("scan", "", "Jump to the scan menu"),
    ("report", "", "Jump to the report menu"),
    ("domain", "[<fqdn|netbios|sid>]", "Show/switch the active domain (multi-domain collections)"),
    ("back", "", "Return to main menu"),
    ("help", "[command]", "Show help"),
]

_REPORT_COMMANDS = [
    ("run", "[--type analyze|scan|heatmap|dashboard|graph|killchain|radar|target|leaderboard] [--id <scan_id>] [--format html|pdf|markdown] [--style 1-5] [-o <path>]", "Build a report from the loaded analyze / scan data (--id reports a stored scan)"),
    ("collect", "", "Jump to the collect menu"),
    ("search", "", "Jump to the search menu (Ctrl+S)"),
    ("analyze", "", "Jump to the analyze menu"),
    ("scan", "", "Jump to the scan menu"),
    ("domain", "[<fqdn|netbios|sid>]", "Show/switch the active domain (multi-domain collections)"),
    ("back", "", "Return to main menu"),
    ("help", "[command]", "Show help"),
]


from collections import namedtuple

WORKFLOW_VERBS = frozenset({"collect", "analyze", "scan", "report", "search"})
GLOBAL_CMDS = frozenset({"domain", "options", "help", "exit", "quit", "version"})

# --- options taxonomy -------------------------------------------------------
# Core connection identity — shown in the default `options` view when set.
_CORE_OPTION_KEYS = ("dc", "domain", "username", "password", "nthash",
                     "ccache", "port", "auth_method")
# Transport tuning — lives in lazyhound.yml; hidden from the default view but
# visible/settable via `options all`.
_TRANSPORT_OPTION_KEYS = ("use_ssl", "use_start_tls", "validate_cert",
                          "timeout", "nameserver")
# Derived caches — never presented as settable options.
_DERIVED_OPTION_KEYS = ("dc_fqdn", "base_dn", "target_host")
# Every key the options command recognises (guards state-restore so a stale DB
# can't resurrect removed keys).
_VALID_OPTION_KEYS = frozenset(
    _CORE_OPTION_KEYS + _TRANSPORT_OPTION_KEYS + _DERIVED_OPTION_KEYS)

# Subcommands per verb. Launching is explicit: 'run' is a subcommand for the
# four workflow verbs (search has no run — its actions are its subcommands). A
# bare verb (or a first token that isn't a subcommand) shows the verb's help.
VERB_SUBCOMMANDS = {
    "collect": frozenset({"run", "crawl", "adcs", "load", "unload", "list", "stats",
                          "delete", "clear", "import", "export", "azure", "options"}),
    "analyze": frozenset({"run", "shortest", "trace", "paths", "graph", "find",
                          "export", "checks"}),
    "scan": frozenset({"run", "checks", "list", "show", "delete", "diff",
                       "export", "scoring", "options"}),
    "report": frozenset({"run"}),
    "search": frozenset({"custom", "info", "members", "memberof", "acl",
                        "who-can", "graph", "kerberoastable", "delegation-map",
                        "computers", "trusts", "templates", "spns", "stats"}),
}

_VERB_TABLES = {
    "collect": _COLLECT_COMMANDS, "analyze": _ANALYZE_COMMANDS,
    "scan": _SCAN_COMMANDS, "report": _REPORT_COMMANDS, "search": _SEARCH_COMMANDS,
}

Parsed = namedtuple("Parsed", "kind verb sub args message")


def _resolve_prefix(token: str, names) -> tuple[str | None, list[str]]:
    """(resolved_name, matches). Exact wins; unique prefix resolves; multiple
    prefix matches -> (None, matches); no match -> (None, [])."""
    names = list(names)
    if token in names:
        return token, [token]
    matches = sorted({n for n in names if n.startswith(token)})
    if len(matches) == 1:
        return matches[0], matches
    return None, matches


def parse_command(line: str) -> Parsed:
    """Route a REPL line under the flat verb+subcommand grammar.

    kind: noop | run | sub | global | help | error | unknown
    """
    try:
        tokens = shlex.split(line)
    except ValueError:
        tokens = line.split()
    if not tokens:
        return Parsed("noop", None, None, [], "")
    head = tokens[0].lower()
    rest = tokens[1:]

    # '??' (and 'help all') = the full command tree; '?' = the minimal menu.
    if head == "??":
        return Parsed("help", None, None, ["all"], "")
    if head == "?":
        head = "help"

    # help [verb [sub] | global | all]
    if head == "help":
        if rest:
            token = rest[0].lower()
            if token == "all":
                return Parsed("help", None, None, ["all"], "")
            v, _ = _resolve_prefix(token, WORKFLOW_VERBS)
            if v:
                # 'help <verb> <sub>' == '<verb> <sub> --help' (detailed help).
                if len(rest) >= 2:
                    sub, _ = _resolve_prefix(rest[1].lower(), VERB_SUBCOMMANDS[v])
                    if sub:
                        return Parsed("sub", v, sub, ["--help"], "")
                return Parsed("help", v, None, [], "")
            # 'help <global>' -> that global's detailed help.
            g, _ = _resolve_prefix(token, {"options", "domain", "version"})
            if g:
                return Parsed("global", g, None, ["--help"], "")
        return Parsed("help", None, None, rest, "")

    # other globals (domain / exit / quit / version)
    if head in GLOBAL_CMDS:
        return Parsed("global", head, None, rest, "")

    # resolve the verb (prefix-aware)
    verb, matches = _resolve_prefix(head, WORKFLOW_VERBS)
    if verb is None:
        if matches:
            return Parsed("error", None, None, [],
                          f"Ambiguous command '{head}': {', '.join(matches)}")
        return Parsed("unknown", None, None, [head] + rest,
                      f"Unknown command: {head}. Type 'help'.")

    subs = VERB_SUBCOMMANDS[verb]

    # Uniform: a known subcommand ('run' included for the workflow verbs)
    # dispatches; a bare verb — or a first token that isn't a subcommand
    # (e.g. a flag) — shows the verb's subcommand help. Launching is explicit
    # via 'run', so you never launch by accident.
    if rest:
        sub, sm = _resolve_prefix(rest[0].lower(), subs)
        if sub:
            return Parsed("sub", verb, sub, rest[1:], "")
        if sm:
            return Parsed("error", verb, None, [],
                          f"Ambiguous {verb} subcommand: {', '.join(sm)}")
    return Parsed("help", verb, None, [], "")


class InteractiveShell:
    """LazyHound interactive REPL."""

    def __init__(self, config: Config | None = None):
        self.config = config or Config.load()
        self._history_path = Path.home() / ".lazyhound_history"

        # Connection options (mutable from the `options` command). Only the
        # connection settings are surfaced — tool-path / screenshot / pacing
        # keys were unused everywhere and have been removed.
        self._options: dict[str, Any] = dict(self.config.connection)

        # Storage — opened in run() via _open_storage(), after the project
        # folder has been resolved, so databases never land in a stray CWD.
        self.history: HistoryStore | None = None
        self._finder_history = None

        self._completion_matches: list[str] = []

        # LazyHound collection/scan state
        self._collection_data: dict | None = None
        self._collection_file: Path | None = None
        self._collection_domain: str = ""
        self._active_domain_sid: str = ""   # active domain in a multi-domain collection
        self._collection_id: str = ""
        self._scan_results: dict | None = None
        self._analysis_result = None  # AnalysisResult from analyzer

        # Active crawl job (network enumeration)
        self._enum_job = None

    # ------------------------------------------------------------------
    # Project folder & storage
    # ------------------------------------------------------------------

    def _project_base(self) -> Path:
        """Absolute project folder that all artifacts resolve under."""
        return self.config.resolve_path("history_db").parent

    def _project_tmp_dir(self) -> Path:
        """Project-local scratch dir (<project>/tmp), created on demand.

        Every intermediate/sensitive artifact (raw collection JSON, import
        staging) is written here rather than to the system temp dir, so nothing
        sensitive ever lands outside the operator's chosen project folder.
        """
        d = self._project_base() / "tmp"
        d.mkdir(parents=True, exist_ok=True)
        return d

    def _ensure_project(self) -> None:
        """On first run (no config file found), prompt for the project folder.

        The launch directory is offered as the default; the operator presses
        Enter to accept it or types another path.  The chosen folder is
        scaffolded (config + subdirs + databases) with ``base_dir`` pinned to
        its absolute path, then loaded so every subsequent artifact — sqlite
        databases, logs, reports, exports — lands inside it.

        When a config file was already discovered, this is a no-op.
        """
        if getattr(self.config, "source_path", None) is not None:
            return  # project already established via a discovered lazyhound.yml

        default = _load_last_project() or str(Path.cwd())
        console.print(
            "\n[bold]First-time setup[/bold] — choose your LazyHound project folder.\n"
            "[dim]All databases, logs, reports and templates will be stored here.[/dim]"
        )
        project = self._prompt_project_folder(default)

        from lazyhound.cli import _scaffold_project
        config_path = _scaffold_project(
            str(project), echo=lambda m: console.print(f"[dim]{m}[/dim]"))
        self.config = Config.load(path=config_path)
        _save_last_project(str(config_path.parent))
        console.print(f"[green]Project ready:[/green] {config_path.parent}\n")

    def _prompt_project_folder(self, default: str) -> Path:
        """Prompt (re-prompting on bad input) for a usable project folder.

        Enter accepts *default*. A typed value must resolve to a real filesystem
        path; a non-existent folder is confirmed before creation so a stray
        keypress (e.g. '?') can't silently create a junk directory under the cwd.
        Ctrl+C / Ctrl+D aborts.
        """
        from rich.markup import escape

        def _ask(prompt: str) -> str:
            try:
                return input(prompt).strip()
            except (EOFError, KeyboardInterrupt):
                console.print("\n[yellow]Cancelled — no project created.[/yellow]")
                raise SystemExit(130)

        while True:
            answer = _ask(f"Project folder [{default}]: ")

            if answer:
                if answer in ("?", "??", "help") or any(c in answer for c in "*?[]"):
                    console.print(
                        "[yellow]Enter a filesystem path (e.g. /opt/engagements/acme "
                        f"or ./acme) — '{escape(answer)}' isn't one.[/yellow]")
                    continue
                target = answer
            else:
                target = default

            try:
                project = Path(target).expanduser()
                if not project.is_absolute():
                    project = Path.cwd() / project
                project = project.resolve()
            except (OSError, ValueError) as exc:
                console.print(f"[yellow]Not a valid path: {escape(str(exc))}[/yellow]")
                continue

            if project.exists() and not project.is_dir():
                console.print(f"[yellow]{project} exists but is not a folder.[/yellow]")
                continue

            if not project.exists():
                confirm = _ask(f"Create new project folder {project}? [Y/n]: ").lower()
                if confirm in ("n", "no"):
                    continue

            try:
                project.mkdir(parents=True, exist_ok=True)
            except OSError as exc:
                console.print(f"[yellow]Can't use {project}: {escape(str(exc))}[/yellow]")
                continue

            return project

    def _open_storage(self) -> None:
        """Open the validation and finder history databases under base_dir."""
        db_path = self.config.resolve_path("history_db")
        self.history = HistoryStore(db_path)

        from lazyhound.finder.storage.history import ScanHistory
        finder_db = self._project_base() / "lazyhound_finder_history.db"
        self._finder_history = ScanHistory(finder_db)
        self._finder_history.open()

    # ------------------------------------------------------------------
    # Main loop
    # ------------------------------------------------------------------

    def run(self) -> None:
        """Start the interactive REPL."""
        show_banner()
        self._init_readline()
        self._ensure_project()
        self._open_storage()
        self._restore_state()

        console.print("[dim]Type 'help' or '?' for commands · a bare verb "
                      "(collect · analyze · scan · report · search) shows its "
                      "subcommands · add 'run' to launch (analyze run) or a "
                      "subcommand (analyze paths, search info)[/dim]\n")

        while True:
            try:
                prompt = self._prompt()
                line = input(prompt).strip()
                if not line:
                    # Empty Enter is a no-op — just re-prompt. Use 'back'/'b'/
                    # Ctrl+B to leave a submenu; 'help' or '?' for the menu.
                    continue
                self._dispatch(line)
            except (EOFError, KeyboardInterrupt):
                console.print("\n[dim]Saving state...[/dim]")
                break
            except Exception as e:
                console.print(f"[red]Error: {e}[/red]")

        self._persist_state()
        self._save_readline()
        self.history.close()
        try:
            self._finder_history.close()
        except Exception:
            pass

    def _restore_state(self) -> None:
        """Restore persisted shell state from previous session."""
        # Restore shell options — only recognised keys, so a stale DB from an
        # older build can't resurrect removed tool-path / screenshot keys.
        saved_opts = self.history.load_options()
        if saved_opts:
            restored = 0
            for k, v in saved_opts.items():
                if k not in _VALID_OPTION_KEYS:
                    continue
                if k not in self._options or not self._options[k]:
                    self._options[k] = v
                    restored += 1
            if restored:
                console.print(f"[dim]Restored {restored} options from previous session.[/dim]")

    def _persist_state(self) -> None:
        """Save shell state before exit."""
        # Save options
        self.history.save_options(self._options)

    def _prompt(self) -> str:
        label = self._active_domain_fqdn() if self._collection_data else self._collection_domain
        domain_tag = f" [{label}]" if label else ""
        return f"lazyhound{domain_tag}> "

    def _dispatch(self, line: str) -> None:
        p = parse_command(line)
        if p.kind == "noop":
            return
        if p.kind == "error":
            console.print(f"[yellow]{p.message}[/yellow]")
            return
        if p.kind == "unknown":
            console.print(f"[red]{p.message}[/red]")
            return

        # help / help <verb> / help all (== '??')
        if p.kind == "help":
            if p.verb:
                self._show_verb_help(p.verb)
            elif p.args and p.args[0].lower() == "all":
                self._show_full_help()
            else:
                self._show_main_help()
            return

        # globals (domain / exit / quit / version)
        if p.kind == "global":
            if p.verb in ("exit", "quit"):
                raise EOFError
            # Global commands take a different branch from the workflow verbs, so
            # wire their '--help' here too (options/domain/version).
            if ("--help" in p.args or "-h" in p.args) and \
                    p.verb in ("domain", "options", "version"):
                show_detailed_help(p.verb, _MAIN_COMMANDS, "")
                return
            if p.verb == "domain":
                self._cmd_domain(p.args)
            elif p.verb == "options":
                self._handle_options(p.args)
            elif p.verb == "version":
                from lazyhound.formatting import show_version
                show_version()
            return

        # workflow subcommand -> the verb's existing router, which maps the
        # subcommand string (incl. "run") to its handler.
        router = {
            "collect": self._collect_dispatch,
            "analyze": self._analyze_dispatch,
            "scan": self._scan_dispatch,
            "report": self._report_dispatch,
            "search": self._query_dispatch,
        }[p.verb]
        cmd = p.sub

        # <verb> <sub> --help -> detailed help for that specific subcommand
        if "--help" in p.args or "-h" in p.args:
            show_detailed_help(cmd, _VERB_TABLES[p.verb], p.verb)
            return

        start = time.monotonic()
        try:
            router(cmd, p.args)
        except KeyboardInterrupt:
            console.print("\n[yellow]Cancelled.[/yellow]")
        elapsed = time.monotonic() - start
        self.history.log_command(submenu=p.verb, command=cmd,
                                 args=" ".join(p.args), duration=elapsed)

    def _show_main_help(self):
        # Minimal top-level menu: the verbs + globals. Point users at the full
        # tree ('help all' / '??') and per-command help ('<command> --help').
        self._show_menu_help(
            _MAIN_COMMANDS, "LazyHound", groups=_MAIN_GROUPS, show_args=False,
            hint="Type a command to see its subcommands · '<command> --help' for "
                 "details · 'help all' (or '??') for every command & subcommand")

    def _show_full_help(self):
        # The full enchilada: every workflow verb expanded into its subcommands.
        subtrees = {
            verb: [c for c in _VERB_TABLES[verb] if c[0] in VERB_SUBCOMMANDS[verb]]
            for verb in WORKFLOW_VERBS
        }
        self._show_menu_help(
            _MAIN_COMMANDS, "LazyHound — all commands", groups=_MAIN_GROUPS,
            show_args=False, subtrees=subtrees,
            hint="Every command & subcommand · '<command> <sub> --help' for "
                 "parameters (e.g. 'scan run --help', 'search custom --help')")

    def _show_verb_help(self, verb):
        # Only this verb's real subcommands ('run' included; nav/help dropped).
        subs = VERB_SUBCOMMANDS[verb]
        rows = [c for c in _VERB_TABLES[verb] if c[0] in subs]
        self._show_menu_help(rows, f"{verb} — subcommands")

    # ------------------------------------------------------------------
    # Validate submenu
    # ------------------------------------------------------------------
    # Collect submenu (LDAP collection)
    # ------------------------------------------------------------------

    def _collect_dispatch(self, cmd: str, args: list[str]) -> None:
        if cmd == "run":
            self._collect_run(args)
        elif cmd == "crawl":
            if args and args[0] in ("status", "pause", "resume", "stop"):
                self._collect_crawl_dispatch(args[0])
            else:
                self._collect_crawl(args)
        elif cmd == "adcs":
            self._collect_adcs(args)
        elif cmd == "clear":
            self._collect_clear(args)
        elif cmd == "load":
            self._collect_load(args)
        elif cmd == "unload":
            self._collect_unload()
        elif cmd == "list":
            self._collect_list()
        elif cmd == "delete":
            self._collect_delete(args)
        elif cmd == "stats":
            # Quick summary on the collect menu; the detailed per-class view
            # lives on 'search > stats'.
            if not self._collection_data:
                console.print("[dim]No collection loaded.[/dim]")
            else:
                self._print_collection_stats(self._ensure_query_index().stats())
        elif cmd == "export":
            self._collect_export(args)
        elif cmd == "import":
            self._collect_import(args)
        elif cmd == "azure":
            self._collect_ingest_azure(args)
        elif cmd == "options":
            self._handle_options(args)
        elif cmd == "help":
            if args:
                show_detailed_help(args[0], _COLLECT_COMMANDS, "collect")
            else:
                self._show_menu_help(_COLLECT_COMMANDS, "Collect")
        else:
            console.print(f"[red]Unknown command: {cmd}[/red]")

    def _collect_run(self, args: list[str]) -> None:
        """Run LDAP collection from DC."""
        nodisabled = pop_flag(args, "--nodisabled")
        slim = pop_flag(args, "--slim")
        # Optional post-collection enrichment chained onto the DCOnly run.
        auto_adcs = pop_flag(args, "--adcs")
        auto_network = pop_flag(args, "--network")
        if not self._ensure_credentials(operation="collect"):
            return
        conn = self._connection_dict()
        dc = conn.get("dc", "")
        domain = conn.get("domain", "")

        # Default to 'low' when no --stealth is given, and always show the active
        # profile (abort on an invalid name rather than running at full speed).
        stealth = pop_option(args, "stealth", "") or "low"
        from lazyhound.finder.stealth import get_preset
        try:
            stealth_cfg = get_preset(stealth)
        except ValueError as e:
            console.print(f"[red]{e}[/red]")
            return
        console.print(
            f"\n[bold yellow]Stealth: {stealth.upper()}[/bold yellow] — "
            f"{stealth_cfg.summary()}"
        )

        # LDAP connection and auth prompts
        ldap_opts = self._prompt_ldap_connection()
        if ldap_opts is None:
            return
        port = ldap_opts["port"]
        use_ssl = ldap_opts["use_ssl"]
        use_start_tls = ldap_opts["use_start_tls"]
        auth_method = ldap_opts["auth_method"]

        auto_negotiate = ldap_opts.get("auto_negotiate", False)
        if auto_negotiate:
            mode_label = "auto-detect"
        elif use_ssl:
            mode_label = "SSL"
        elif use_start_tls:
            mode_label = "StartTLS"
        else:
            mode_label = "plaintext"
        console.print(
            f"\n[bold cyan]Starting LDAP collection from {dc}:{port} "
            f"({mode_label}) auth={self._effective_auth_label(auth_method)}...[/bold cyan]"
        )

        try:
            from lazyhound.finder.collect.collector import collect as finder_collect

            import tempfile

            with tempfile.TemporaryDirectory(
                prefix="lazyhound_collect_", dir=self._project_tmp_dir()
            ) as tmpdir:
                output_file = finder_collect(
                    dc_host=dc,
                    domain=domain,
                    username=conn.get("username", ""),
                    password=conn.get("password", ""),
                    output_dir=tmpdir,
                    use_ssl=use_ssl,
                    port=port,
                    auth_method=auth_method,
                    nthash=conn.get("nthash") or None,
                    ccache=conn.get("ccache", ""),
                    use_start_tls=use_start_tls,
                    auto_negotiate=ldap_opts.get("auto_negotiate", False),
                    stealth=stealth_cfg,
                )

                # Load collected data into memory
                data = json.loads(output_file.read_text(encoding="utf-8"))

            if nodisabled:
                from lazyhound.finder.collect.postprocess import drop_disabled
                n = drop_disabled(data)
                console.print(f"[dim]--nodisabled: dropped {n} disabled object(s).[/dim]")
            if slim:
                from lazyhound.finder.collect.postprocess import slim_objects
                n = slim_objects(data)
                console.print(f"[dim]--slim: dropped {n} unused property value(s).[/dim]")

            # Temp dir and JSON file cleaned up automatically.
            # Drop the previous collection + derived caches before loading the new one.
            self._reset_collection_state()
            self._collection_data = data
            self._collection_domain = domain
            self._collection_file = None

            # Count objects by class from the flat objects list
            objects = data.get("objects", [])
            meta = data.get("meta", {})
            counts: dict[str, int] = {}
            for obj in objects:
                oc = obj.get("object_class", "unknown")
                counts[oc] = counts.get(oc, 0) + 1

            total = meta.get("object_count", len(objects))
            parts = [f"{v} {k}(s)" for k, v in sorted(counts.items()) if v > 0]
            console.print(
                f"[green]Collection complete: {total} objects — "
                f"{', '.join(parts) if parts else 'no objects'}[/green]"
            )
            console.print("[dim]Collection available for search and scan.[/dim]")

            # Save to DB
            try:
                cid = self._finder_history.save_collection(data, log_path="")
                self._collection_id = cid
                console.print(f"[dim]Collection saved to DB ({cid}).[/dim]")
            except Exception as e:
                console.print(f"[red]Could not save to DB: {e}[/red]")

            # Chained enrichment: run ADCS and/or the full network crawl right
            # after the DCOnly collection, then persist the enriched result.
            if auto_adcs:
                self._collect_adcs([])
            if auto_network:
                self._collect_crawl(["--targets", "all"])

        except ImportError as e:
            console.print(f"[red]Missing dependency: {e}[/red]")
            console.print("[dim]Install it with: pip install ldap3[/dim]")
        except Exception as e:
            console.print(f"[red]Collection failed: {e}[/red]")

    # ------------------------------------------------------------------
    # Crawl — session + local group enumeration via SMB
    # ------------------------------------------------------------------

    def _crawl_select_from_file(self, path: str, summary) -> list[dict]:
        """Select crawl targets from a plaintext file of FQDNs/IPs.

        Matches each line (case-insensitive) against collection computers by
        dNSHostName (full or short label) or sAMAccountName. Reports skipped
        (unknown) entries. Returns matched computer dicts.
        """
        p = Path(path).expanduser()
        if not p.is_file():
            console.print(f"[red]File not found: {p}[/red]")
            return []
        try:
            lines = p.read_text(encoding="utf-8").splitlines()
        except Exception as e:
            console.print(f"[red]Could not read file: {e}[/red]")
            return []

        def _field(comp: dict, key: str) -> str:
            v = comp.get(key, "")
            if isinstance(v, list):
                v = v[0] if v else ""
            return str(v)

        by_key: dict[str, dict] = {}
        for comp in summary.all_computers:
            dns = _field(comp, "dNSHostName").lower()
            sam = _field(comp, "sAMAccountName").rstrip("$").lower()
            if dns:
                by_key.setdefault(dns, comp)
                by_key.setdefault(dns.split(".")[0], comp)
            if sam:
                by_key.setdefault(sam, comp)

        matched: list[dict] = []
        seen: set[int] = set()
        skipped: list[str] = []
        for raw in lines:
            entry = raw.strip()
            if not entry or entry.startswith("#"):
                continue
            key = entry.lower()
            comp = by_key.get(key) or by_key.get(key.split(".")[0])
            if comp is not None:
                if id(comp) not in seen:
                    seen.add(id(comp))
                    matched.append(comp)
            else:
                skipped.append(entry)

        console.print(f"  Matched {len(matched)} host(s) from {p.name}")
        if skipped:
            shown = ", ".join(skipped[:10]) + ("..." if len(skipped) > 10 else "")
            console.print(f"  [yellow]Skipped {len(skipped)} not in collection:[/yellow] {shown}")
        return matched

    def _collect_crawl(self, args: list[str]) -> None:
        """Network crawl: enumerate sessions and local groups on computers via SMB."""
        if self._collection_data is None:
            console.print("[red]No collection loaded. Run 'collect run' or 'collect load <id>' first.[/red]")
            return

        if not self._ensure_credentials(operation="smb"):
            return
        conn = self._connection_dict()

        from lazyhound.finder.collect.network_collector import (
            summarize_targets,
            format_ou_tree,
            NetworkCollectionJob,
            EnumerationTracker,
        )

        tokens = list(args)
        targets_opt = pop_option(tokens, "targets")
        ou_filter = pop_option(tokens, "ou")
        batch_size_str = pop_option(tokens, "batch-size", "50")
        smb_workers_str = pop_option(tokens, "smb-workers", "10")
        smb_timeout_str = pop_option(tokens, "smb-timeout", "5")
        recheck = pop_flag(tokens, "--recheck")
        background = pop_flag(tokens, "--background")

        console.print("\n[bold cyan]Network Crawl — session & local group enumeration via SMB[/bold cyan]\n")

        objects = self._collection_data.get("objects", [])
        summary = summarize_targets(objects)

        if summary.total == 0:
            console.print("[red]No computer objects in loaded collection.[/red]")
            return

        # Load tracker from collection (tracks previously crawled hosts)
        tracker = EnumerationTracker.from_collection(self._collection_data)
        ts = tracker.summary()

        # Display classification
        table = Table(title="Computer Targets", show_header=True, header_style="bold")
        table.add_column("Category", style="cyan", min_width=22)
        table.add_column("Count", justify="right", style="bold")
        table.add_row("Domain Controllers", str(len(summary.domain_controllers)))
        table.add_row("Servers", str(len(summary.servers)))
        table.add_row("Workstations", str(len(summary.workstations)))
        table.add_row("[bold]Total[/bold]", f"[bold]{summary.total}[/bold]")
        console.print(table)

        # Show previous crawl state
        if ts["total_tracked"] > 0:
            console.print()
            pt = Table(title="Previous Crawl State", show_header=True, header_style="bold")
            pt.add_column("Metric", style="cyan", min_width=22)
            pt.add_column("Value", justify="right", style="bold")
            pt.add_row("Hosts tracked", str(ts["total_tracked"]))
            pt.add_row("Reachable", str(ts["reachable"]))
            pt.add_row("Unreachable", str(ts["unreachable"]))
            pt.add_row("Sessions collected", str(ts["sessions_collected"]))
            pt.add_row("Local groups collected", str(ts["local_groups_collected"]))
            console.print(pt)
            if not recheck:
                console.print("  [dim]Use --recheck to re-enumerate already collected hosts[/dim]")

        # OU hierarchy
        ou_lines = format_ou_tree(summary.ou_roots)
        if ou_lines:
            console.print("\n[bold]OU Hierarchy (computer counts):[/bold]")
            for line in ou_lines:
                console.print(f"  {line}")

        console.print()

        # Target selection
        selected = summary.all_computers
        if targets_opt:
            selected = self._crawl_select_by_name(targets_opt, summary)
        elif ou_filter:
            selected = self._crawl_select_by_ou(ou_filter, summary)
        else:
            # Interactive menu
            console.print("[bold]Select targets:[/bold]")
            console.print(f"  1) All ({summary.total})")
            console.print(f"  2) Domain Controllers only ({len(summary.domain_controllers)})")
            console.print(f"  3) Servers only ({len(summary.servers)})")
            console.print(f"  4) Workstations only ({len(summary.workstations)})")
            console.print(f"  5) DCs + Servers ({len(summary.domain_controllers) + len(summary.servers)})")
            console.print("  6) Select by OU")
            console.print("  7) Import host FQDNs/IPs from a file")
            console.print()
            try:
                choice = input("Choice [1]: ").strip() or "1"
            except (EOFError, KeyboardInterrupt):
                console.print()
                return
            if choice == "1":
                selected = summary.all_computers
            elif choice == "2":
                selected = summary.domain_controllers
            elif choice == "3":
                selected = summary.servers
            elif choice == "4":
                selected = summary.workstations
            elif choice == "5":
                selected = summary.domain_controllers + summary.servers
            elif choice == "6":
                selected = self._crawl_interactive_ou(summary)
                if selected is None:
                    return
            elif choice == "7":
                try:
                    fpath = input("Path to host list file: ").strip()
                except (EOFError, KeyboardInterrupt):
                    console.print()
                    return
                if not fpath:
                    return
                selected = self._crawl_select_from_file(fpath, summary)
                if not selected:
                    console.print("[red]No targets matched the file.[/red]")
                    return
            else:
                console.print(f"[red]Invalid choice: {choice}[/red]")
                return

        if not selected:
            console.print("[red]No targets selected.[/red]")
            return

        # Filter pending hosts
        skipped_count = 0
        if recheck:
            pending = selected
            console.print(f"  [bold]--recheck:[/bold] re-enumerating all {len(selected)} host(s)")
        else:
            pending, already = tracker.filter_pending(selected, True, True)
            skipped_count = len(already)
            if already:
                console.print(f"  Skipping {len(already)} already-collected ({len(pending)} remaining)")
            if not pending:
                console.print("[green]All selected hosts already crawled. Use --recheck to force.[/green]")
                return

        batch_size = int(batch_size_str)
        total_batches = max(1, (len(pending) + batch_size - 1) // batch_size)
        console.print(
            f"\n[bold]Crawling {len(pending)} host(s) in {total_batches} batch(es) "
            f"(size {batch_size}, {smb_workers_str} workers)[/bold]"
        )

        # Build job
        job = NetworkCollectionJob(
            targets=pending,
            username=conn.get("username", ""),
            password=conn.get("password", ""),
            domain=conn.get("domain", ""),
            nthash=conn.get("nthash") or "",
            ccache=conn.get("ccache", ""),
            collect_sessions=True,
            collect_local_groups=True,
            max_workers=int(smb_workers_str),
            timeout=int(smb_timeout_str),
            batch_size=batch_size,
            tracker=tracker,
        )

        def _on_batch(progress):
            console.print(
                f"    Batch {progress.batch_number}/{progress.total_batches}: "
                f"{progress.hosts_scanned_total}/{progress.hosts_total} scanned, "
                f"reachable={progress.reachable}, "
                f"sessions={progress.sessions}, "
                f"local_members={progress.local_group_members}"
            )

        job.set_batch_callback(_on_batch)
        self._enum_job = job

        if background:
            job.start()
            console.print("[green]Crawl started in background.[/green]")
            console.print("  [dim]Use: crawl status | crawl pause | crawl resume | crawl stop[/dim]")
            return

        console.print("[dim]Starting crawl (Ctrl+C to cancel)...[/dim]\n")
        job.start()
        try:
            job.wait()
        except KeyboardInterrupt:
            console.print()
            job.stop()
            job.wait(timeout=5)
            self._finalize_crawl(job, tracker, skipped_count)
            s = job.status()
            console.print(
                f"[yellow]Crawl cancelled. Partial results saved: "
                f"{s['hosts_scanned']}/{s['hosts_total']} scanned, "
                f"{s['sessions']} sessions, "
                f"{s['local_group_members']} local group members[/yellow]"
            )
            return

        # Finalize
        self._finalize_crawl(job, tracker, skipped_count)

    def _collect_adcs(self, args: list[str]) -> None:
        """`collect adcs` — CA-host ADCS enrichment of the loaded collection."""
        if self._collection_data is None:
            console.print("[red]No collection loaded. Run 'collect run' or "
                          "'collect load <id>' first.[/red]")
            return
        if not self._ensure_credentials(operation="smb"):
            return
        tokens = list(args)
        timeout = int(pop_option(tokens, "smb-timeout", "5"))
        self._run_adcs_enrichment(self._connection_dict(), timeout)

    def _run_adcs_enrichment(self, conn: dict, timeout: int) -> None:
        """CA-host ADCS enrichment: gather ESC6/7/8/11 data and merge it into
        the loaded collection so analyze/report can surface it offline."""
        from lazyhound.finder.collect.adcs_enrich import (
            ca_hosts_from_collection, enrich_ca, merge_adcs_into_collection,
        )
        console.print("\n[bold cyan]ADCS Enrichment — CA-host ESC collection[/bold cyan]\n")
        cas = ca_hosts_from_collection(self._collection_data)
        if not cas:
            console.print("[yellow]No CA (pKIEnrollmentService) objects in the loaded "
                          "collection. Run 'collect run' against a domain with AD CS "
                          "first.[/yellow]")
            return
        console.print(f"[dim]Enriching {len(cas)} CA host(s): HTTP web-enrollment probe + "
                      f"registry (EDITF/InterfaceFlags/Security)...[/dim]\n")
        results: dict[str, dict] = {}
        for ca in cas:
            console.print(f"[*] {ca['ca_name']} @ {ca['host']} ...")
            try:
                block = enrich_ca(
                    ca,
                    username=conn.get("username", ""),
                    password=conn.get("password", ""),
                    domain=conn.get("domain", ""),
                    nthash=conn.get("nthash") or "",
                    ccache=conn.get("ccache", ""),
                    timeout=timeout,
                )
            except Exception as exc:  # noqa: BLE001 - report and continue
                console.print(f"    [red]enrichment failed: {exc}[/red]")
                continue
            results[ca["key"]] = block
            web = "reachable" if block["web_enrollment_http"] else "not reachable"
            if block["editf_san2"] is None:
                reg = "registry unreadable (Remote Registry off?)"
            else:
                reg = (f"EDITF_SAN2={block['editf_san2']}, "
                       f"RPC-encrypt-enforced={block['enforce_encrypt_rpc']}")
            console.print(f"    web enrollment: {web}  ·  {reg}")

        if not results:
            console.print("[yellow]No CA hosts enriched.[/yellow]")
            return

        merge_adcs_into_collection(self._collection_data, results)
        if hasattr(self, "_query_index"):
            self._query_index = None
        self._update_collection_in_db()
        enr = self._collection_data["meta"]["adcs_enrichment"]
        console.print(
            f"\n[green]ADCS enrichment complete: {enr['cas_enriched']}/{enr['cas_total']} "
            f"CA(s); registry {'reachable' if enr['registry_reachable'] else 'unreadable'}. "
            f"Method: {self._collection_data['meta']['collection_method']}[/green]"
        )
        console.print("[dim]Re-run 'analyze run' to see ESC6/7/8/11 findings.[/dim]")

    def _collect_crawl_dispatch(self, subcmd: str) -> None:
        """Handle crawl subcommands: status, pause, resume, stop."""
        if subcmd == "status":
            self._crawl_status()
        elif subcmd == "pause":
            if self._enum_job:
                self._enum_job.pause()
                console.print("[yellow]Crawl paused after current batch.[/yellow]")
            else:
                console.print("[dim]No crawl job active.[/dim]")
        elif subcmd == "resume":
            if self._enum_job:
                self._enum_job.resume()
                console.print("[green]Crawl resumed.[/green]")
            else:
                console.print("[dim]No crawl job active.[/dim]")
        elif subcmd == "stop":
            if self._enum_job:
                self._enum_job.stop()
                self._enum_job.wait(timeout=5)
                if self._collection_data and self._enum_job._tracker:
                    self._finalize_crawl(self._enum_job, self._enum_job._tracker)
                s = self._enum_job.status()
                console.print(
                    f"[yellow]Crawl cancelled. Partial results saved: "
                    f"{s['hosts_scanned']}/{s['hosts_total']} scanned, "
                    f"{s['sessions']} sessions, "
                    f"{s['local_group_members']} local group members[/yellow]"
                )
            else:
                console.print("[dim]No crawl job active.[/dim]")

    def _crawl_status(self) -> None:
        from lazyhound.finder.collect.network_collector import EnumerationTracker

        ts = None
        if self._collection_data:
            tracker = EnumerationTracker.from_collection(self._collection_data)
            ts = tracker.summary()
            if ts["total_tracked"] > 0:
                console.print("\n[bold]Crawl Tracker (persisted):[/bold]")
                console.print(f"  Hosts tracked:          {ts['total_tracked']}")
                console.print(f"  Reachable:              {ts['reachable']}")
                console.print(f"  Unreachable:            {ts['unreachable']}")
                console.print(f"  Sessions collected:     {ts['sessions_collected']}")
                console.print(f"  Local groups collected: {ts['local_groups_collected']}")

        if self._enum_job is None:
            if not (ts and ts["total_tracked"] > 0):
                console.print("[dim]No crawl job active.[/dim]")
            return

        s = self._enum_job.status()
        console.print(f"\n[bold]Active Crawl Job:[/bold]")
        console.print(f"  State:         {s['state'].upper()}")
        console.print(f"  Batch:         {s['batch']}/{s['total_batches']}")
        console.print(f"  Hosts scanned: {s['hosts_scanned']}/{s['hosts_total']}")
        console.print(f"  Reachable:     {s['hosts_reachable']}")
        console.print(f"  Sessions:      {s['sessions']}")
        console.print(f"  Local members: {s['local_group_members']}")

    def _finalize_crawl(self, job, tracker, skipped_count: int = 0) -> None:
        """Merge crawl results into loaded collection and update DB.

        *skipped_count* is the number of already-collected hosts skipped this
        run (0 when finalising from a job control command with no such context).
        """
        from lazyhound.finder.collect.network_collector import (
            resolve_member_names,
            merge_network_into_collection,
        )

        net_result = job.result
        tracker.save_to_collection(self._collection_data)

        if net_result.hosts_reachable > 0:
            sid_map = self._collection_data.get("sid_map", {})
            resolve_member_names(net_result, sid_map)
            merge_network_into_collection(self._collection_data, net_result)
            # Invalidate query index so it rebuilds with new data
            if hasattr(self, "_query_index"):
                self._query_index = None

        self._update_collection_in_db()

        ts = tracker.summary()
        for line in self._crawl_summary_lines(net_result, ts, skipped_count):
            console.print(line)

    @staticmethod
    def _crawl_summary_lines(net_result, ts: dict, skipped_count: int) -> list[str]:
        """Build the two crawl-summary lines, each labelled with its scope.

        The counts come from two different scopes and previously read as
        contradictory (e.g. '0/11 reachable' next to '1 reachable'):
          * 'this run' — only the hosts crawled just now (skipped hosts excluded)
          * 'all runs' — the cumulative tracker across every crawl of the
            loaded collection.
        Labelling each makes the divergence self-explanatory.
        """
        skipped_note = (
            f", {skipped_count} skipped (already collected)" if skipped_count else ""
        )
        return [
            f"\n[green]Crawl complete (this run): "
            f"{net_result.hosts_reachable}/{net_result.hosts_total} reachable, "
            f"{net_result.total_sessions} sessions, "
            f"{net_result.total_local_group_members} local group members"
            f"{skipped_note}[/green]",
            f"[dim]Cumulative (all runs): {ts['total_tracked']} hosts tracked — "
            f"{ts['reachable']} reachable, {ts['unreachable']} unreachable[/dim]",
        ]

    def _update_collection_in_db(self) -> None:
        """Update the DB entry for the loaded collection."""
        if not self._collection_id or not self._collection_data:
            return
        try:
            self._finder_history.update_collection(
                self._collection_id, self._collection_data
            )
        except Exception as e:
            console.print(f"[dim]Could not update collection in DB: {e}[/dim]")

    def _crawl_select_by_name(self, targets_opt: str, summary) -> list:
        mapping = {
            "all": summary.all_computers,
            "dcs": summary.domain_controllers,
            "domain-controllers": summary.domain_controllers,
            "servers": summary.servers,
            "workstations": summary.workstations,
        }
        selected = []
        for part in targets_opt.lower().split(","):
            part = part.strip()
            if part in mapping:
                selected.extend(mapping[part])
            else:
                console.print(f"[red]Unknown target: {part}. Valid: {', '.join(mapping.keys())}[/red]")
                return []
        return selected

    def _crawl_select_by_ou(self, ou_filter: str, summary) -> list:
        matched = [c for c in summary.all_computers if ou_filter.lower() in c.ou.lower()]
        if not matched:
            console.print(f"[red]No computers in OUs matching '{ou_filter}'[/red]")
        return matched

    def _crawl_interactive_ou(self, summary) -> list | None:
        ous = [(dn, node) for dn, node in summary.ou_map.items()
               if node.total_computer_count > 0]
        ous.sort(key=lambda x: x[1].name.lower())
        if not ous:
            console.print("[red]No OUs with computers found.[/red]")
            return None

        console.print("\n[bold]OUs with computers:[/bold]")
        for i, (dn, node) in enumerate(ous, 1):
            console.print(f"  {i:3d}) {node.name} ({node.total_computer_count} computers)  [dim]{node.dn}[/dim]")
        console.print("\nEnter OU number(s), comma-separated (e.g. 1,3,5), or 'all':")

        try:
            choice = input("OU selection: ").strip()
        except (EOFError, KeyboardInterrupt):
            console.print()
            return None

        if choice.lower() == "all":
            return summary.all_computers

        selected = []
        seen = set()
        for part in choice.split(","):
            part = part.strip()
            try:
                idx = int(part) - 1
                if 0 <= idx < len(ous):
                    dn, node = ous[idx]
                    for comp in summary.all_computers:
                        if comp.ou.lower() == node.dn.lower() or \
                                comp.dn.lower().endswith("," + node.dn.lower()):
                            key = comp.dn.lower()
                            if key not in seen:
                                seen.add(key)
                                selected.append(comp)
                else:
                    console.print(f"[red]Invalid OU number: {part}[/red]")
            except ValueError:
                console.print(f"[red]Invalid input: {part}[/red]")
        return selected if selected else None

    def _collect_clear(self, args: list[str]) -> None:
        """Strip session and/or local-admin data from the loaded collection."""
        if not self._collection_data:
            console.print("[red]No collection loaded.[/red]")
            return

        tokens = list(args)
        clear_sessions = pop_flag(tokens, "--sessions")
        clear_local_admins = pop_flag(tokens, "--local-admins")
        clear_adcs = pop_flag(tokens, "--adcs")
        clear_all = pop_flag(tokens, "--all")

        if clear_all:
            clear_sessions = True
            clear_local_admins = True
            clear_adcs = True

        if not clear_sessions and not clear_local_admins and not clear_adcs:
            # Interactive menu
            sess_count = len(self._collection_data.get("sessions", []))
            lg_count = len(self._collection_data.get("local_group_members", []))
            console.print("\n[bold]Clear network enumeration data:[/bold]")
            console.print(f"  1) All — sessions ({sess_count:,}) + local-admins ({lg_count:,}) + tracker")
            console.print(f"  2) Sessions only ({sess_count:,})")
            console.print(f"  3) Local-admins only ({lg_count:,})")
            console.print(f"  4) Cancel")
            try:
                choice = input("\nChoice [4]: ").strip() or "4"
            except (EOFError, KeyboardInterrupt):
                console.print()
                return
            if choice == "1":
                clear_sessions = True
                clear_local_admins = True
            elif choice == "2":
                clear_sessions = True
            elif choice == "3":
                clear_local_admins = True
            else:
                return

        cleared: list[str] = []
        meta = self._collection_data.get("meta", {})

        if clear_sessions:
            count = len(self._collection_data.get("sessions", []))
            self._collection_data["sessions"] = []
            cleared.append(f"{count:,} sessions")

        if clear_local_admins:
            count = len(self._collection_data.get("local_group_members", []))
            self._collection_data["local_group_members"] = []
            cleared.append(f"{count:,} local-admin entries")

        if clear_sessions and clear_local_admins:
            meta.pop("enumeration_tracker", None)
            meta.pop("network_stats", None)

        if clear_adcs:
            n = 0
            for o in self._collection_data.get("objects", []):
                if o.get("object_class") == "pki" and o.pop("adcs", None) is not None:
                    n += 1
            meta.pop("adcs_enrichment", None)
            cleared.append(f"ADCS enrichment on {n} CA(s)")

        # Recompose the method label from the remaining markers.
        from lazyhound.finder.collect.collection_meta import compose_collection_method
        meta["collection_method"] = compose_collection_method(meta)

        if hasattr(self, "_query_index"):
            self._query_index = None

        self._update_collection_in_db()
        console.print(f"[green]Cleared: {', '.join(cleared)}[/green]")

    def _collect_load(self, args: list[str]) -> None:
        if not args:
            console.print("[red]Usage: load <collection_id|file_path>[/red]")
            self._collect_list()
            return
        ref = args[0]

        # Try loading from DB by collection_id first
        try:
            data = self._finder_history.get_collection(ref)
            if data:
                # Drop the previous collection's derived caches (active domain,
                # query index, prior analyze/scan results) before switching —
                # otherwise a stale active domain scopes the new collection's
                # findings to the wrong realm ("No actionable findings in scope").
                self._reset_collection_state()
                self._collection_data = data
                self._collection_file = None
                self._collection_id = ref
                self._collection_domain = data.get("meta", {}).get("domain", "unknown")
                objects = data.get("objects", [])
                total = data.get("meta", {}).get("object_count", len(objects))
                console.print(
                    f"[green]Loaded from DB: {self._collection_domain} "
                    f"({total} objects)[/green]"
                )
                return
        except Exception:
            pass

        # Fall back to file path
        path = Path(ref).expanduser()
        if path.is_file():
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                self._reset_collection_state()
                self._collection_data = data
                self._collection_file = path
                self._collection_domain = data.get("meta", {}).get("domain", "unknown")
                objects = data.get("objects", [])
                total = data.get("meta", {}).get("object_count", len(objects))
                console.print(
                    f"[green]Loaded from file: {self._collection_domain} "
                    f"({total} objects)[/green]"
                )
            except Exception as e:
                console.print(f"[red]Load failed: {e}[/red]")
        else:
            console.print(f"[red]Collection not found: {ref}[/red]")

    def _reset_collection_state(self) -> None:
        """Clear the active collection and all derived per-collection caches."""
        self._collection_data = None
        self._collection_file = None
        self._collection_domain = ""
        self._active_domain_sid = ""
        self._collection_id = ""
        if hasattr(self, "_query_index"):
            self._query_index = None
        if hasattr(self, "_analysis_result"):
            self._analysis_result = None
        if hasattr(self, "_scan_results"):
            self._scan_results = None
        # The cached attack graph belongs to the previous collection — drop it.
        try:
            from lazyhound.finder.collect.analyzer import clear_graph_cache
            clear_graph_cache()
        except Exception:
            pass

    def _collect_unload(self) -> None:
        if self._collection_data:
            domain = self._collection_domain or "unknown"
            self._reset_collection_state()
            console.print(f"[green]Collection unloaded ({domain}).[/green]")
        else:
            console.print("[dim]No collection loaded.[/dim]")

    def _collect_list(self) -> None:
        try:
            db_collections = self._finder_history.list_collections()
        except Exception:
            db_collections = []

        if not db_collections:
            console.print("[dim]No stored collections found.[/dim]")
            return

        table = Table(title="Stored Collections", show_header=True, header_style="bold", expand=True)
        table.add_column("", width=3)
        table.add_column("ID", width=14)
        table.add_column("Domain", width=18)
        table.add_column("User", width=15)
        table.add_column("DC", width=16)
        table.add_column("Objects", width=8, justify="right")
        table.add_column("Method", width=10)
        table.add_column("Collected", width=20)

        for c in db_collections:
            cid = str(c.collection_id)[:14]
            loaded = self._collection_id and c.collection_id.startswith(self._collection_id)
            marker = "[bold green]*[/bold green]" if loaded else ""
            table.add_row(
                marker,
                cid,
                c.domain,
                c.run_as_user,
                c.dc or "",
                str(c.object_count),
                c.collection_method or "",
                (c.collected_at or "")[:19],
            )
        console.print(table)
        console.print(f"[dim]{len(db_collections)} collection(s). [green]*[/green] = loaded. Load with: collect load <collection_id>[/dim]")

    def _print_detailed_stats(self) -> None:
        """Detailed collection stats (search menu): per-class object breakdowns
        with enabled/disabled splits, realms, and OS inventory."""
        if not self._collection_data:
            console.print("[dim]No collection loaded.[/dim]")
            return

        objects = self._collection_data.get("objects", [])
        meta = self._collection_data.get("meta", {})
        total = meta.get("object_count", len(objects))

        # UAC flag constant (for the enabled/disabled split)
        UAC_DISABLED = 0x0002

        # Classify objects — AD (on-prem) vs Entra/Azure. The ingestor stores
        # Azure objects into 'objects' with aad_*/azure_* classes (also mirrored
        # into 'azure_objects'), so classify from 'objects' alone (no double-count).
        _AZ_PREFIXES = ("aad_", "azure_")
        _is_az = lambda o: str(o.get("object_class", "")).lower().startswith(_AZ_PREFIXES)
        ad_objs = [o for o in objects if not _is_az(o)]
        az_objs = [o for o in objects if _is_az(o)]
        users = [o for o in ad_objs if o.get("object_class") == "user"]
        computers = [o for o in ad_objs if o.get("object_class") == "computer"]
        groups = [o for o in ad_objs if o.get("object_class") == "group"]
        ous = sum(1 for o in ad_objs if o.get("object_class") == "ou")
        gpos = sum(1 for o in ad_objs if o.get("object_class") == "gpo")

        # Enabled/disabled split (for the object breakdown)
        enabled = disabled = 0
        for u in users:
            uac = u.get("properties", {}).get("userAccountControl", 0) or 0
            if uac & UAC_DISABLED:
                disabled += 1
            else:
                enabled += 1

        # Operating-system inventory (descriptive)
        os_counts: dict[str, int] = {}
        for c in computers:
            osys = c.get("properties", {}).get("operatingSystem", "") or "Unknown"
            os_counts[osys] = os_counts.get(osys, 0) + 1

        # Header panel
        collected_at = meta.get("collected_at", "")[:19].replace("T", " ")
        method = meta.get("collection_method", "")
        dc = meta.get("dc", "")
        run_as = meta.get("run_as_user", "")

        meta_bits = []
        if dc:
            meta_bits.append(f"DC: {dc}")
        if collected_at:
            meta_bits.append(f"Collected: {collected_at}")
        if method:
            meta_bits.append(method)
        if run_as:
            meta_bits.append(f"As: {run_as}")
        head = f"[bold cyan]{self._collection_domain}[/bold cyan]"
        if meta_bits:
            head += "\n[dim]" + "  ·  ".join(meta_bits) + "[/dim]"
        console.print()
        console.print(Panel(Text.from_markup(head),
                            title="[bold]Collection Overview[/bold]",
                            border_style="cyan", expand=False))

        # AD + Entra object breakdowns, stacked one-per-row, each bordered.
        obj_table = ent_table = None
        if ad_objs:
            obj_table = Table(title="Active Directory", title_style="bold green",
                              header_style="dim", box=box.ROUNDED,
                              border_style="green", expand=False)
            obj_table.add_column("Type", min_width=16)
            obj_table.add_column("Count", justify="right")
            obj_table.add_column("", style="dim")
            obj_table.add_row("Users", f"{len(users):,}",
                              f"{enabled:,} enabled · {disabled:,} disabled")
            obj_table.add_row("Computers", f"{len(computers):,}", "")
            obj_table.add_row("Groups", f"{len(groups):,}", "")
            obj_table.add_row("OUs", f"{ous:,}", "")
            obj_table.add_row("GPOs", f"{gpos:,}", "")
            obj_table.add_row("[dim]Total[/dim]", f"[bold]{len(ad_objs):,}[/bold]", "")
        if az_objs:
            _azn = lambda c: sum(1 for o in az_objs
                                 if str(o.get("object_class", "")).lower() == c)
            az_users = [o for o in az_objs
                        if str(o.get("object_class", "")).lower() == "aad_user"]
            az_enabled = sum(1 for o in az_users
                             if o.get("properties", {}).get("accountEnabled", True))
            ent_table = Table(title="Entra / Azure", title_style="bold blue",
                              header_style="dim", box=box.ROUNDED,
                              border_style="blue", expand=False)
            ent_table.add_column("Type", min_width=16)
            ent_table.add_column("Count", justify="right")
            ent_table.add_column("", style="dim")
            ent_table.add_row("Users", f"{len(az_users):,}",
                              f"{az_enabled:,} enabled · {len(az_users) - az_enabled:,} disabled")
            for label, cls in (("Groups", "aad_group"),
                               ("Service Principals", "aad_sp"),
                               ("Applications", "aad_app"),
                               ("Devices", "aad_device"),
                               ("Tenants", "azure_tenant"),
                               ("Subscriptions", "azure_sub"),
                               ("Resource Groups", "azure_rg"),
                               ("Virtual Machines", "azure_vm"),
                               ("Key Vaults", "azure_kv")):
                c = _azn(cls)
                if c:
                    ent_table.add_row(label, f"{c:,}", "")
            ent_table.add_row("[dim]Total[/dim]", f"[bold]{len(az_objs):,}[/bold]", "")
        for t in (obj_table, ent_table):
            if t is not None:
                console.print()
                console.print(t)

        # Realms / domains in this collection (forest + Entra tenant breakdown)
        try:
            realms = self._ensure_query_index().domains()
        except Exception:
            realms = []
        if len(realms) > 1:
            console.print()
            realm_table = Table(title=f"Realms / Domains ({len(realms)})",
                                title_style="bold", header_style="dim",
                                box=box.ROUNDED, border_style="dim",
                                expand=False)
            realm_table.add_column("Realm", min_width=24)
            realm_table.add_column("Type", width=13)
            realm_table.add_column("Objects", justify="right", width=9)
            realm_table.add_column("Users", justify="right", width=8)
            for d in realms:
                is_tenant = d.netbios.upper().startswith("ENTRA")
                # Uppercase domain-looking labels (AD FQDN / onmicrosoft); leave
                # a display-name or SID fallback as-is.
                name = d.label.upper() if "." in d.label else d.label
                rtype = "Entra tenant" if is_tenant else "AD domain"
                realm_table.add_row(name, rtype,
                                    f"{d.object_count:,}", f"{d.user_count:,}")
            console.print(realm_table)

        # OS breakdown (if any)
        if computers:
            console.print()
            os_table = Table(title="Computer Operating Systems",
                             title_style="bold", header_style="dim",
                             box=box.ROUNDED, border_style="dim",
                             expand=False)
            os_table.add_column("Operating System", min_width=30)
            os_table.add_column("Count", justify="right", width=8)
            for osys, cnt in sorted(os_counts.items(), key=lambda x: -x[1]):
                os_table.add_row(osys, str(cnt))
            console.print(os_table)

        # File info
        if self._collection_file:
            console.print(f"\n[dim]Source: {self._collection_file}[/dim]")

    def _pick_collection(self, prompt: str = "Select collection to export"):
        """Pick a stored collection to act on. Returns (data, domain) or None.

        Default is the currently loaded collection (Enter keeps it). Picking
        another collection does NOT change the active loaded collection.
        """
        try:
            cols = self._finder_history.list_collections()
        except Exception:
            cols = []

        if not cols and not self._collection_data:
            console.print("[dim]No collections available.[/dim]")
            return None

        if cols:
            table = Table(title="Stored Collections", show_header=True,
                          header_style="bold", expand=True)
            table.add_column("#", width=3, justify="right")
            table.add_column("", width=2)
            table.add_column("ID", width=14)
            table.add_column("Domain", width=18)
            table.add_column("Objects", width=8, justify="right")
            table.add_column("Collected", width=20)
            for i, c in enumerate(cols, 1):
                cid = str(getattr(c, "collection_id", "") or "")
                loaded = self._collection_id and cid.startswith(self._collection_id)
                table.add_row(
                    str(i),
                    "[bold green]*[/bold green]" if loaded else "",
                    cid[:14],
                    str(getattr(c, "domain", "") or ""),
                    str(getattr(c, "object_count", "") or ""),
                    str(getattr(c, "collected_at", "") or "")[:20],
                )
            console.print(table)

        default_label = (self._collection_domain or "current") if self._collection_data else "none"
        try:
            choice = input(f"\n{prompt} [#/id, Enter = {default_label}]: ").strip()
        except (EOFError, KeyboardInterrupt):
            console.print()
            return None

        if not choice:
            if self._collection_data:
                return (self._collection_data, self._collection_domain)
            console.print("[yellow]No collection loaded; nothing selected.[/yellow]")
            return None

        chosen_cid = None
        if choice.isdigit():
            idx = int(choice) - 1
            if 0 <= idx < len(cols):
                chosen_cid = str(getattr(cols[idx], "collection_id", "") or "")
        else:
            for c in cols:
                cid = str(getattr(c, "collection_id", "") or "")
                if cid.startswith(choice):
                    chosen_cid = cid
                    break

        if not chosen_cid:
            console.print(f"[yellow]No collection matched: {choice}[/yellow]")
            return None

        if (self._collection_id and chosen_cid.startswith(self._collection_id)
                and self._collection_data):
            return (self._collection_data, self._collection_domain)

        try:
            data = self._finder_history.get_collection(chosen_cid)
        except Exception as e:
            console.print(f"[red]Could not load collection {chosen_cid}: {e}[/red]")
            return None
        if not data:
            console.print(f"[yellow]Collection not found: {chosen_cid}[/yellow]")
            return None
        domain = data.get("meta", {}).get("domain", "unknown")
        return (data, domain)

    def _collect_export(self, args: list[str]) -> None:
        picked = self._pick_collection()
        if picked is None:
            return
        data, domain = picked

        tokens = list(args)
        output = pop_option(tokens, "o", "")
        fmt = pop_option(tokens, "format", "")

        # If flags passed directly, use them
        if pop_flag(tokens, "--bloodhound") or fmt == "bloodhound":
            fmt = "bloodhound"
        elif pop_flag(tokens, "--azurehound") or fmt == "azurehound":
            fmt = "azurehound"
        elif pop_flag(tokens, "--json") or pop_flag(tokens, "--raw") or fmt in ("json", "raw"):
            fmt = "json"

        # Interactive menu if no format specified
        if not fmt:
            console.print("\n[bold]Export format:[/bold]")
            console.print("  1) JSON (raw collection data)")
            console.print("  2) BloodHound CE (.zip for BloodHound Community Edition)")
            console.print("  3) AzureHound (.json for BloodHound CE / azurehound tools)")
            console.print("  4) Cancel")
            try:
                choice = input("\nChoice [1]: ").strip() or "1"
            except (EOFError, KeyboardInterrupt):
                console.print()
                return
            if choice == "1":
                fmt = "json"
            elif choice == "2":
                fmt = "bloodhound"
            elif choice == "3":
                fmt = "azurehound"
            else:
                return

        domain = domain or "collection"

        if fmt == "azurehound":
            from lazyhound.finder.utils_pkg.azure_export import (
                export_azurehound, build_azurehound_payload)
            payload, _ = build_azurehound_payload(data)
            if not payload["data"]:
                console.print("[yellow]Loaded collection has no Azure data — nothing "
                              "to export; use --bloodhound for on-prem.[/yellow]")
                return
            if not output:
                output = self._default_output_path("exports", f"azurehound_{domain}.json")
            output = self._prompt_export_path(output)
            if not output:
                return
            result = export_azurehound(data, output)
            note = (f" ({result.degraded} degraded)" if result.degraded else "")
            console.print(f"[green]AzureHound export: {result.path} "
                          f"({result.entries} entries{note})[/green]")
            return

        if fmt == "bloodhound":
            try:
                from lazyhound.finder.utils_pkg.bh_converter import export_zip
                if not output:
                    output = self._default_output_path("exports", f"{domain}_bloodhound.zip")
                output = self._prompt_export_path(output)
                if not output:
                    return
                out = export_zip(data, output)
                console.print(f"[green]BloodHound CE export: {out}[/green]")
            except ImportError:
                console.print("[red]BloodHound converter not available. Check dependencies.[/red]")
            except Exception as e:
                console.print(f"[red]Export failed: {e}[/red]")
        else:
            if not output:
                output = self._default_output_path("exports", f"collection_{domain}.json")
            output = self._prompt_export_path(output)
            if not output:
                return
            Path(output).write_text(
                json.dumps(data, indent=2, default=str),
                encoding="utf-8",
            )
            console.print(f"[green]Exported to: {output}[/green]")

    def _read_importable_collection(self, path: Path) -> dict:
        """Read an external file into a lazyhound collection dict (auto-detect).

        .zip / zipfile -> BloodHound CE; .json with a top-level ``objects`` list
        -> already a lazyhound collection (used directly); any other JSON
        (BH-shaped) -> routed through the BloodHound converter. Raises on
        unreadable/unconvertible input.
        """
        import tempfile
        import zipfile

        is_zip = path.suffix.lower() == ".zip" or zipfile.is_zipfile(str(path))
        if not is_zip:
            raw = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(raw, dict) and isinstance(raw.get("objects"), list):
                return raw  # already a lazyhound collection

        from lazyhound.finder.utils_pkg.bh_converter import import_bloodhound
        with tempfile.TemporaryDirectory(
            prefix="lazyhound_import_", dir=self._project_tmp_dir()
        ) as td:
            out = import_bloodhound(path, Path(td) / "collection.json")
            return json.loads(Path(out).read_text(encoding="utf-8"))

    def _collect_import(self, args: list[str]) -> None:
        nodisabled = pop_flag(args, "--nodisabled")
        slim = pop_flag(args, "--slim")
        if not args:
            console.print(
                "[red]Usage: import <bloodhound.zip | bloodhound.json | "
                "lazyhound_collection.json> [--nodisabled] [--slim][/red]"
            )
            console.print(
                "[dim]Imports an external collection as a new saved collection "
                "and loads it.[/dim]"
            )
            return

        path = Path(args[0]).expanduser()
        if not path.is_file():
            console.print(f"[red]File not found: {path}[/red]")
            return

        try:
            data = self._read_importable_collection(path)
        except Exception as e:
            console.print(f"[red]Import failed: {e}[/red]")
            return

        objects = data.get("objects", []) if isinstance(data, dict) else []
        if not objects:
            console.print("[red]Import produced no objects — not a recognized collection.[/red]")
            return

        if nodisabled:
            from lazyhound.finder.collect.postprocess import drop_disabled
            n = drop_disabled(data)
            objects = data.get("objects", [])
            console.print(f"[dim]--nodisabled: dropped {n} disabled object(s).[/dim]")
        if slim:
            from lazyhound.finder.collect.postprocess import slim_objects
            n = slim_objects(data)
            console.print(f"[dim]--slim: dropped {n} unused property value(s).[/dim]")

        try:
            cid = self._finder_history.save_collection(data, log_path="")
        except Exception as e:
            console.print(f"[red]Could not save imported collection: {e}[/red]")
            return

        # Success — drop the old collection + caches, make the import active.
        self._reset_collection_state()
        self._collection_data = data
        self._collection_id = cid
        self._collection_domain = data.get("meta", {}).get("domain", "unknown")
        console.print(
            f"[green]Imported {len(objects)} objects as collection {cid} "
            f"({self._collection_domain}) — loaded.[/green]"
        )

    def _azure_device_code(self, tenant: str, client_id: str) -> str:
        """Device-code sign-in: print the code/URL, then wait for approval."""
        from lazyhound.finder.collect.azure_auth import (
            acquire_token_device_code, GRAPH_SCOPE)
        return acquire_token_device_code(
            tenant, client_id, scope=GRAPH_SCOPE,
            on_prompt=lambda msg: console.print(f"[bold cyan]{msg}[/bold cyan]"))

    def _collect_azure_live(self, tokens: list[str]):
        """Authenticate to a tenant and pull an Entra collection via MS Graph.

        Writes the result as an azurehound-format .json and returns its path
        (so the caller can ingest it through the normal file path). Returns None
        on bad args or collection failure.
        """
        import json as _json
        try:
            from lazyhound.finder.collect.azure_auth import (
                acquire_token_client_credentials, acquire_token_password,
                acquire_token_device_code, GRAPH_SCOPE, PUBLIC_CLIENT_ID,
                AzureAuthError, AzureMfaRequired)
            from lazyhound.finder.collect.azure_collector import (
                GraphClient, collect_entra, AzureCollectError)
        except ModuleNotFoundError as e:
            console.print(f"[red]Live Azure collection needs the '{e.name}' "
                          f"package, which isn't installed.[/red]")
            console.print("[dim]Install it:  pip install requests   "
                          "(or reinstall lazyhound to pull current deps)[/dim]")
            return None

        tenant = pop_option(tokens, "tenant", "")
        client_id = pop_option(tokens, "client-id", "")
        secret = pop_option(tokens, "secret", "")
        username = pop_option(tokens, "username", "")
        password = pop_option(tokens, "password", "")
        use_device = pop_flag(tokens, "--device-code")
        output = pop_option(tokens, "o", "")
        if not tenant:
            console.print("[red]Usage: azure --run --tenant <id|domain> "
                          "(--username <upn> | --device-code | --client-id <id>)[/red]")
            console.print("[dim]User auth needs no app registration; service-principal "
                          "needs --client-id (+ secret). Omit secrets to be prompted.[/dim]")
            return None

        try:
            if use_device:
                token = self._azure_device_code(tenant, client_id or PUBLIC_CLIENT_ID)
            elif username:
                if not password:
                    import getpass
                    try:
                        password = getpass.getpass(f"Password for {username}: ")
                    except (EOFError, KeyboardInterrupt):
                        console.print()
                        return None
                console.print(f"[dim]Authenticating to {tenant} as {username}…[/dim]")
                try:
                    token = acquire_token_password(
                        tenant, username, password, client_id or PUBLIC_CLIENT_ID)
                except AzureMfaRequired:
                    console.print("[yellow]MFA/interaction required — falling back "
                                  "to device-code sign-in…[/yellow]")
                    token = self._azure_device_code(tenant, client_id or PUBLIC_CLIENT_ID)
            elif client_id:
                if not secret:
                    import getpass
                    try:
                        secret = getpass.getpass("Client secret: ")
                    except (EOFError, KeyboardInterrupt):
                        console.print()
                        return None
                if not secret:
                    console.print("[red]No client secret provided.[/red]")
                    return None
                console.print(f"[dim]Authenticating to {tenant} (service principal)…[/dim]")
                token = acquire_token_client_credentials(
                    tenant, client_id, secret, scope=GRAPH_SCOPE)
            else:
                console.print("[red]Choose an auth method: --username <upn> "
                              "(supplied creds), --device-code, or --client-id <id> "
                              "(service principal).[/red]")
                return None
            console.print("[dim]Collecting Entra objects via Microsoft Graph…[/dim]")
            entries = collect_entra(GraphClient(token))
        except (AzureAuthError, AzureCollectError) as e:
            console.print(f"[red]Azure collection failed: {e}[/red]")
            return None
        except Exception as e:  # network/unexpected
            console.print(f"[red]Azure collection error: {e}[/red]")
            return None

        if not entries:
            console.print("[yellow]Collection returned no Entra objects.[/yellow]")
            return None

        payload = {"meta": {"type": "azure", "count": len(entries)}, "data": entries}
        if not output:
            safe = tenant.replace("/", "_").replace(" ", "_")
            output = self._default_output_path("exports", f"azurehound_{safe}.json") \
                if hasattr(self, "_default_output_path") else f"azurehound_{safe}.json"
        out_path = Path(self._prompt_export_path(output) if hasattr(self, "_prompt_export_path")
                        else output)
        try:
            out_path.write_text(_json.dumps(payload, indent=2), encoding="utf-8")
        except Exception as e:
            console.print(f"[red]Could not write collected data: {e}[/red]")
            return None
        console.print(f"[green]Collected {len(entries)} Entra entries → {out_path}[/green]")
        return out_path

    def _collect_ingest_azure(self, args: list[str]) -> None:
        """Ingest AzureHound data — either collected live (--run) or from a file.

        With --run, lazyhound authenticates to the tenant and pulls the collection
        directly via Microsoft Graph (no external azurehound binary needed). The
        collected data is also written to an azurehound-format .json. Either way
        it is merged into a loaded AD collection (hybrid) or stood up standalone.
        """
        tokens = list(args)
        nodisabled = pop_flag(tokens, "--nodisabled")
        slim = pop_flag(tokens, "--slim")
        if pop_flag(tokens, "--run"):
            path = self._collect_azure_live(tokens)
            if not path:
                return
        elif not tokens:
            console.print("[red]Usage: azure <azurehound.json>   |   "
                          "azure --run --tenant <id> --client-id <id>[/red]")
            console.print("[dim]--run collects live via Microsoft Graph (service "
                          "principal). Without --run, imports an azurehound JSON "
                          "file. Either merges into a loaded AD collection (hybrid) "
                          "or creates a standalone Azure collection.[/dim]")
            return
        else:
            path = Path(tokens[0]).expanduser()
            if not path.is_file():
                console.print(f"[red]File not found: {path}[/red]")
                return
        from lazyhound.finder.utils_pkg.azure_ingestor import AzureHoundIngestor

        ing = AzureHoundIngestor()
        try:
            ing.load(path)
        except Exception as e:
            console.print(f"[red]AzureHound ingest failed: {e}[/red]")
            return

        if self._collection_data and self._collection_data.get("objects"):
            import copy
            data = ing.merge(copy.deepcopy(self._collection_data))
            mode = "hybrid (merged into loaded collection)"
        else:
            data = ing.to_standalone()
            mode = "standalone Azure"

        if nodisabled:
            from lazyhound.finder.collect.postprocess import drop_disabled
            n = drop_disabled(data)
            console.print(f"[dim]--nodisabled: dropped {n} disabled object(s).[/dim]")
        if slim:
            from lazyhound.finder.collect.postprocess import slim_objects
            n = slim_objects(data)
            console.print(f"[dim]--slim: dropped {n} unused property value(s).[/dim]")

        try:
            cid = self._finder_history.save_collection(data, log_path="")
        except Exception as e:
            console.print(f"[red]Could not save Azure collection: {e}[/red]")
            return

        self._reset_collection_state()
        self._collection_data = data
        self._collection_id = cid
        self._collection_domain = data.get("meta", {}).get("domain", "azure")
        stats = data.get("meta", {}).get("azure_stats", {})
        az_obj = stats.get("azure_objects", sum(
            1 for o in data.get("objects", []) if str(o.get("object_class", "")).startswith(("aad_", "azure_"))))
        console.print(
            f"[green]AzureHound ingested ({mode}) as collection {cid} "
            f"({self._collection_domain}) — {az_obj} Azure objects, loaded.[/green]")

    def _collect_delete(self, args: list[str]) -> None:
        if not args:
            console.print("[red]Usage: delete <collection_id> | --all[/red]")
            self._collect_list()
            return
        if args[0] == "--all":
            try:
                cols = self._finder_history.list_collections()
                if not cols:
                    console.print("[dim]No collections to delete.[/dim]")
                    return
                answer = _timed_prompt(f"Delete all {len(cols)} collections? [y]es / [n]o", default="n").lower()
                if answer not in ("y", "yes"):
                    console.print("[yellow]Cancelled.[/yellow]")
                    return
                count = 0
                for c in cols:
                    cid = c.collection_id if hasattr(c, 'collection_id') else c.get('collection_id', '')
                    if self._finder_history.delete_collection(cid):
                        count += 1
                console.print(f"[green]Deleted {count} collections.[/green]")
            except Exception as e:
                console.print(f"[red]Delete failed: {e}[/red]")
            return
        cid = args[0]
        try:
            deleted = self._finder_history.delete_collection(cid)
            if deleted:
                console.print(f"[green]Collection {cid} deleted.[/green]")
            else:
                console.print(f"[yellow]Collection not found: {cid}[/yellow]")
        except Exception as e:
            console.print(f"[red]Delete failed: {e}[/red]")

    # ------------------------------------------------------------------
    # Scan submenu (live security assessment)
    # ------------------------------------------------------------------

    def _scan_dispatch(self, cmd: str, args: list[str]) -> None:
        if cmd == "run":
            self._scan_run(args)
        elif cmd == "checks":
            self._scan_checks(args)
        elif cmd == "list":
            self._scan_list()
        elif cmd == "show":
            self._scan_show(args)
        elif cmd == "delete":
            self._scan_delete(args)
        elif cmd == "diff":
            self._scan_diff(args)
        elif cmd == "export":
            self._scan_export(args)
        elif cmd == "scoring":
            self._scan_scoring(args)
        elif cmd == "options":
            self._handle_options(args)
        elif cmd == "help":
            if args:
                show_detailed_help(args[0], _SCAN_COMMANDS, "scan")
            else:
                self._show_menu_help(_SCAN_COMMANDS, "Scan")
        else:
            console.print(f"[red]Unknown command: {cmd}[/red]")

    def _build_scoring_profile(self, override_name: str = ""):
        """Build the active ScoringProfile from the project's scoring config.

        A preset (strict/balanced/lenient) is the baseline; any override fields
        in the ``scoring:`` config replace the preset's values. ``override_name``
        (from ``scan run --profile``) wins over the configured profile. Invalid
        input warns and falls back — a scan is never blocked by bad config.
        """
        import copy
        from lazyhound.finder.finder_models import ScoringProfile, SCORING_PROFILES

        cfg = {}
        try:
            cfg = dict(self.config.scoring or {})
        except Exception:
            cfg = {}
        name = (override_name or cfg.get("profile") or "balanced").strip().lower()
        if name in SCORING_PROFILES:
            profile = copy.copy(SCORING_PROFILES[name])
        else:
            console.print(f"[yellow]Unknown scoring profile '{name}'; using "
                          f"balanced. (Available: {', '.join(SCORING_PROFILES)})[/yellow]")
            profile = copy.copy(SCORING_PROFILES["balanced"])

        # Apply optional overrides on top of the preset. Each is validated so a
        # malformed field is skipped (with a warning) rather than crashing.
        def _num(v):
            return v if isinstance(v, (int, float)) and not isinstance(v, bool) else None

        if cfg.get("curve") in ("linear", "sqrt", "log"):
            profile.curve = cfg["curve"]
        elif cfg.get("curve") is not None:
            console.print(f"[yellow]scoring.curve '{cfg['curve']}' invalid; "
                          "using profile default.[/yellow]")
        if _num(cfg.get("coefficient")) is not None:
            profile.coefficient = float(cfg["coefficient"])
        if _num(cfg.get("health_weight")) is not None:
            profile.health_weight = max(0.0, min(1.0, float(cfg["health_weight"])))
        if isinstance(cfg.get("grade_thresholds"), dict):
            try:
                profile.grade_thresholds = {str(k).upper(): int(v)
                                            for k, v in cfg["grade_thresholds"].items()}
            except (TypeError, ValueError):
                console.print("[yellow]scoring.grade_thresholds invalid; "
                              "using profile default.[/yellow]")
        if isinstance(cfg.get("severity_points"), dict):
            profile.severity_points = {str(k).lower(): v
                                       for k, v in cfg["severity_points"].items()}
        if isinstance(cfg.get("category_weights"), dict):
            profile.category_weights = {str(k).lower(): v
                                        for k, v in cfg["category_weights"].items()}
        return profile

    def _scan_scoring(self, args: list[str]) -> None:
        """Show the scoring/grading model that scans will use."""
        override = pop_option(args, "profile")
        p = self._build_scoring_profile(override)
        table = Table(title="Scan Scoring Profile", show_header=True, header_style="bold")
        table.add_column("Setting", width=18)
        table.add_column("Value")
        table.add_row("profile", str(p.name))
        table.add_row("curve", str(p.curve))
        table.add_row("coefficient", str(p.coefficient))
        table.add_row("health_weight", str(p.health_weight))
        gt = p.grade_thresholds or {}
        table.add_row("grade A/B/C/D",
                      "  ".join(f"{k}≥{gt.get(k, '?')}" for k in ("A", "B", "C", "D"))
                      + "   (below D = F)")
        if p.severity_points:
            table.add_row("severity_points", ", ".join(f"{k}={v}" for k, v in p.severity_points.items()))
        if p.category_weights:
            table.add_row("category_weights", ", ".join(f"{k}={v}" for k, v in p.category_weights.items()))
        console.print(table)
        console.print("[dim]  Edit the 'scoring:' section of lazyhound.yml, or use "
                      "'scan run --profile strict|balanced|lenient' for a one-off.[/dim]")

    def _scan_run(self, args: list[str]) -> None:
        """Run live security scan."""
        if not self._ensure_credentials(operation="scan"):
            return
        conn = self._connection_dict()

        category = pop_option(args, "category")
        check_id = pop_option(args, "check")
        exclude = pop_option(args, "exclude")
        profile_override = pop_option(args, "profile")
        no_collection = pop_flag(args, "--no-collection")

        # Apply the operator's scoring/grading config (project lazyhound.yml,
        # optionally overridden by --profile) before the scan computes scores.
        from lazyhound.finder.finder_models import set_scoring_profile
        set_scoring_profile(self._build_scoring_profile(profile_override))

        # LDAP connection and auth prompts
        ldap_opts = self._prompt_ldap_connection()
        if ldap_opts is None:
            return
        port = ldap_opts["port"]
        use_ssl = ldap_opts["use_ssl"]
        use_start_tls = ldap_opts["use_start_tls"]
        auth_method = ldap_opts["auth_method"]

        auto_negotiate = ldap_opts.get("auto_negotiate", False)
        if auto_negotiate:
            mode_label = "auto-detect"
        elif use_ssl:
            mode_label = "SSL"
        elif use_start_tls:
            mode_label = "StartTLS"
        else:
            mode_label = "plaintext"
        console.print(
            f"\n[bold cyan]Starting security scan against {conn.get('dc')}:{port} "
            f"({mode_label}) auth={self._effective_auth_label(auth_method)}...[/bold cyan]"
        )

        try:
            from lazyhound.finder.scan.scanner import Scanner
            from lazyhound.finder.finder_config import AppConfig, ConnectionConfig

            # Build AppConfig from options
            conn_cfg = ConnectionConfig(
                dc=conn.get("dc", ""),
                domain=conn.get("domain", ""),
                username=conn.get("username", ""),
                password=conn.get("password", ""),
                port=port,
                use_ssl=use_ssl,
                auth_method=auth_method,
                nthash=conn.get("nthash", ""),
                ccache=conn.get("ccache", ""),
                use_start_tls=use_start_tls,
                auto_negotiate=ldap_opts.get("auto_negotiate", False),
            )
            app_cfg = AppConfig(connection=conn_cfg)
            # Anchor scan logs / collection exports to the project folder so
            # the finder subsystem never writes to a stray CWD.
            app_cfg.paths.base_dir = str(self._project_base())
            app_cfg.paths.history_db = "lazyhound_finder_history.db"
            app_cfg.apply_paths()
            # Disable scanner's built-in history save — the shell saves
            # via self._finder_history to avoid "database is locked" from
            # two connections writing to the same SQLite DB.
            app_cfg.history.enabled = False

            if check_id:
                app_cfg.scan.include_checks = [c.strip() for c in check_id.split(",")]
            if exclude:
                app_cfg.scan.exclude_checks = [c.strip() for c in exclude.split(",")]
            if category:
                app_cfg.scan.categories = [c.strip() for c in category.split(",")]

            use_collection = None if no_collection else self._collection_data
            scanner = Scanner(app_cfg, collection=use_collection)
            result = scanner.run()
            if use_collection:
                console.print("[dim]  (collection-aware: findings touching "
                              "Tier-Zero-reachable principals were prioritised)[/dim]")

            self._scan_results = result

            # Save to finder history DB (matching lazyhound finder format)
            try:
                scan_dict = result.to_dict() if hasattr(result, "to_dict") else {}
                self._finder_history.save(scan_dict)
                console.print("[dim]Scan saved to history DB.[/dim]")
            except Exception as e:
                # Fallback to our own DB
                try:
                    scan_id = getattr(result, "scan_id", "") or datetime.utcnow().strftime("%Y%m%d%H%M%S")
                    score = getattr(result, "score", 0) or 0
                    grade = getattr(result, "grade", "") or ""
                    total_findings = sum(len(cr.findings) for cr in getattr(result, "check_results", []))
                    checks_run = len(getattr(result, "check_results", []))
                    self.history.save_scan(
                        scan_id=scan_id, domain=conn.get("domain", ""),
                        score=score, grade=grade, findings=total_findings,
                        checks_run=checks_run,
                        started_at=getattr(result, "started_at", datetime.utcnow().isoformat()),
                    )
                except Exception:
                    pass

            # Display summary
            try:
                from lazyhound.finder.reports.console import render_scan_result
                render_scan_result(result, style=int(self._options.get("style", "2") or 2))
            except Exception:
                # Fallback: basic summary
                console.print(f"\n[bold]Score:[/bold] {getattr(result, 'score', 'N/A')}")
                console.print(f"[bold]Grade:[/bold] {getattr(result, 'grade', 'N/A')}")

        except ImportError as e:
            console.print(f"[red]Missing dependency: {e}[/red]")
        except Exception as e:
            console.print(f"[red]Scan failed: {e}[/red]")

    def _scan_checks(self, args: list[str] | None = None) -> None:
        """List available scan checks, optionally filtered by category."""
        try:
            from lazyhound.finder.scan.checks.registry import CheckRegistry
            registry = CheckRegistry.get_instance()
            registry.discover_checks()
            checks = registry.all_checks()

            category_filter = args[0].lower() if args else None
            if category_filter:
                checks = [c for c in checks if c.category.value.lower() == category_filter]

            table = Table(title=f"Scan Checks ({len(checks)})", show_header=True, header_style="bold", expand=True)
            table.add_column("Check ID", width=18)
            table.add_column("Name", min_width=30)
            table.add_column("Category", width=18)

            for check in sorted(checks, key=lambda c: c.check_id):
                table.add_row(check.check_id, check.name, check.category.value)

            console.print(table)
        except Exception as e:
            console.print(f"[red]Error loading checks: {e}[/red]")

    def _scan_list(self) -> None:
        # Use finder history DB (matching lazyhound finder format)
        try:
            scans = self._finder_history.list_scans()
        except Exception:
            scans = []

        if not scans:
            # Fallback to our own DB
            rows = self.history.list_scans()
            if not rows:
                console.print("[dim]No past scans. Run a scan first.[/dim]")
                return
            table = Table(title="Past Scans", show_header=True, header_style="bold")
            table.add_column("Scan ID", width=14)
            table.add_column("Domain", width=18)
            table.add_column("Score", width=8, justify="right")
            table.add_column("Grade", width=6)
            table.add_column("Findings", width=10, justify="right")
            table.add_column("Date", width=20)
            for r in rows:
                table.add_row(
                    r["scan_id"][:14], r.get("domain", ""),
                    f"{r.get('score', 0):.0f}", r.get("grade", ""),
                    str(r.get("findings", 0)), (r.get("started_at") or "")[:19],
                )
            console.print(table)
            return

        table = Table(title="Past Scans", show_header=True, header_style="bold", expand=True)
        table.add_column("Scan ID", width=14)
        table.add_column("Domain", width=18)
        table.add_column("User", width=15)
        table.add_column("Score", width=8, justify="right")
        table.add_column("Grade", width=6)
        table.add_column("Findings", width=10, justify="right")
        table.add_column("Date", width=20)

        for s in scans:
            table.add_row(
                str(s.scan_id)[:14],
                s.domain,
                s.run_as_user,
                str(s.risk_score),
                s.grade,
                str(s.total_findings),
                (s.started_at or "")[:19],
            )
        console.print(table)
        console.print(f"[dim]{len(scans)} scan(s). View with: show <scan_id>[/dim]")

    def _scan_show(self, args: list[str]) -> None:
        scan_data = None

        if args:
            # Load from DB by scan_id
            scan_id = args[0]
            try:
                scan_data = self._finder_history.get_scan(scan_id)
            except Exception:
                pass
            if not scan_data:
                console.print(f"[red]Scan not found: {scan_id}[/red]")
                return
        elif self._scan_results:
            # Use in-memory results from last run
            scan_data = self._scan_results.to_dict() if hasattr(self._scan_results, "to_dict") else self._scan_results
        else:
            console.print("[dim]Usage: show <scan_id>[/dim]")
            return

        # Render scan summary
        domain = scan_data.get("target_domain", scan_data.get("domain", "?"))
        score = scan_data.get("risk_score", 0)
        grade = scan_data.get("grade", "?")
        total = scan_data.get("total_findings", 0)
        started = (scan_data.get("started_at") or "")[:19]

        console.print(f"\n[bold]Scan: {scan_data.get('scan_id', '?')}[/bold]")
        console.print(f"  Domain:   {domain}")
        console.print(f"  Score:    {score}  Grade: [bold]{grade}[/bold]")
        console.print(f"  Findings: {total}")
        console.print(f"  Date:     {started}\n")

        # Show findings by check
        check_results = scan_data.get("check_results", [])
        if not check_results:
            console.print("[dim]No check results in this scan.[/dim]")
            return

        table = Table(title="Findings", show_header=True, header_style="bold", expand=True)
        table.add_column("Check ID", width=16)
        table.add_column("Category", width=18)
        table.add_column("Severity", width=10)
        table.add_column("Finding", min_width=30)
        table.add_column("Affected", width=10, justify="right")

        for cr in check_results:
            for f in cr.get("findings", []):
                sev = f.get("severity", "?").upper()
                sev_style = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "green", "INFO": "dim"}.get(sev, "")
                table.add_row(
                    cr.get("check_id", "?"),
                    cr.get("category", "?"),
                    f"[{sev_style}]{sev}[/{sev_style}]" if sev_style else sev,
                    f.get("title", "?")[:60],
                    str(len(f.get("affected_objects", []))),
                )

        console.print(table)
        sid = scan_data.get("scan_id", "?")

    def _scan_delete(self, args: list[str]) -> None:
        if not args:
            console.print("[red]Usage: delete <scan_id> | --all[/red]")
            return
        if args[0] == "--all":
            try:
                scans = self._finder_history.list_scans()
                if not scans:
                    console.print("[dim]No scans to delete.[/dim]")
                    return
                answer = _timed_prompt(f"Delete all {len(scans)} scans? [y]es / [n]o", default="n").lower()
                if answer not in ("y", "yes"):
                    console.print("[yellow]Cancelled.[/yellow]")
                    return
                count = 0
                for s in scans:
                    sid = s.scan_id if hasattr(s, 'scan_id') else s.get('scan_id', '')
                    try:
                        if self._finder_history.delete_scan(sid):
                            count += 1
                    except Exception:
                        pass
                console.print(f"[green]Deleted {count} scans.[/green]")
            except Exception as e:
                console.print(f"[red]Delete failed: {e}[/red]")
            return
        scan_id = args[0]
        deleted = False
        try:
            deleted = self._finder_history.delete_scan(scan_id)
        except Exception:
            pass
        if not deleted:
            try:
                deleted = self.history.delete_scan(scan_id)
            except Exception:
                pass
        if deleted:
            console.print(f"[green]Scan {scan_id} deleted.[/green]")
        else:
            console.print(f"[yellow]Scan not found: {scan_id}[/yellow]")

    def _scan_diff(self, args: list[str]) -> None:
        if len(args) < 2:
            console.print("[red]Usage: diff <old_scan_id> <new_scan_id>[/red]")
            return
        old_id, new_id = args[0], args[1]
        try:
            result = self._finder_history.diff(old_id, new_id)
        except Exception as e:
            console.print(f"[red]Diff failed: {e}[/red]")
            return
        if not result:
            console.print("[red]One or both scans not found.[/red]")
            return

        # Score delta
        delta = result.score_delta
        delta_str = f"+{delta}" if delta > 0 else str(delta)
        delta_style = "red" if delta > 0 else "green" if delta < 0 else "dim"
        console.print(f"\n[bold]Scan Diff: {old_id} → {new_id}[/bold]")
        console.print(f"  Score delta: [{delta_style}]{delta_str}[/{delta_style}]")
        console.print(f"  Unchanged:   {result.unchanged_count}")

        # New findings
        if result.new_findings:
            console.print(f"\n[bold red]New findings ({len(result.new_findings)}):[/bold red]")
            for f in result.new_findings:
                console.print(f"  [red]+[/red] [{f.get('severity', '?')}] {f.get('check_id', '?')}: {f.get('title', '?')}")

        # Resolved findings
        if result.resolved_findings:
            console.print(f"\n[bold green]Resolved findings ({len(result.resolved_findings)}):[/bold green]")
            for f in result.resolved_findings:
                console.print(f"  [green]-[/green] [{f.get('severity', '?')}] {f.get('check_id', '?')}: {f.get('title', '?')}")

        if not result.new_findings and not result.resolved_findings:
            console.print("\n[dim]No changes between the two scans.[/dim]")

    def _pick_scan(self):
        """Pick a stored scan to export. Returns (scan_data, scan_id) or None.

        Default is the most recent scan (Enter keeps it).
        """
        try:
            scans = self._finder_history.list_scans()
        except Exception:
            scans = []

        if not scans:
            if self._scan_results:
                data = (self._scan_results.to_dict()
                        if hasattr(self._scan_results, "to_dict") else self._scan_results)
                sid = "current"
                if isinstance(data, dict):
                    sid = data.get("scan_id") or data.get("meta", {}).get("scan_id") or "current"
                return (data, sid)
            console.print("[dim]No scans available to export.[/dim]")
            return None

        table = Table(title="Select scan to export", show_header=True,
                      header_style="bold", expand=True)
        table.add_column("#", width=3, justify="right")
        table.add_column("Scan ID", width=16)
        table.add_column("Domain", width=18)
        table.add_column("Grade", width=6)
        table.add_column("Findings", width=10, justify="right")
        table.add_column("Date", width=20)
        for i, s in enumerate(scans, 1):
            marker = " (latest)" if i == 1 else ""
            table.add_row(
                str(i), str(s.scan_id)[:14] + marker, str(getattr(s, "domain", "")),
                str(getattr(s, "grade", "")), str(getattr(s, "total_findings", "")),
                str(getattr(s, "started_at", ""))[:19],
            )
        console.print(table)

        default = scans[0]
        try:
            choice = input(
                f"\nSelect scan to export [#/id, Enter = {str(default.scan_id)[:14]} (latest)]: "
            ).strip()
        except (EOFError, KeyboardInterrupt):
            console.print()
            return None

        chosen = default
        if choice:
            if choice.isdigit():
                idx = int(choice) - 1
                if 0 <= idx < len(scans):
                    chosen = scans[idx]
                else:
                    console.print(f"[yellow]Invalid selection: {choice}[/yellow]")
                    return None
            else:
                match = next((s for s in scans if str(s.scan_id).startswith(choice)), None)
                if match is None:
                    console.print(f"[yellow]No scan matched: {choice}[/yellow]")
                    return None
                chosen = match

        try:
            data = self._finder_history.get_scan(chosen.scan_id)
        except Exception as e:
            console.print(f"[red]Could not load scan {chosen.scan_id}: {e}[/red]")
            return None
        if not data:
            console.print(f"[yellow]Scan not found: {chosen.scan_id}[/yellow]")
            return None
        return (data, chosen.scan_id)

    def _scan_export(self, args: list[str]) -> None:
        from datetime import datetime

        tokens = list(args)
        fmt = pop_option(tokens, "format", "json")
        output = pop_option(tokens, "o", "")

        # Choose the scan: explicit id arg, else picker (default most recent).
        if tokens:
            scan_id = tokens[0]
            try:
                scan_data = self._finder_history.get_scan(scan_id)
            except Exception:
                scan_data = None
            if not scan_data:
                console.print(f"[red]Scan not found: {scan_id}[/red]")
                return
        else:
            picked = self._pick_scan()
            if picked is None:
                return
            scan_data, scan_id = picked

        # Default path: <base_dir>/exports/scan_results_<id>_<timestamp>.<fmt>
        if not output:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            sid = (str(scan_id) or "scan")[:14]
            output = self._default_output_path("exports", f"scan_results_{sid}_{ts}.{fmt}")

        output = self._prompt_export_path(output)
        if not output:
            return

        try:
            Path(output).write_text(
                json.dumps(scan_data, indent=2, default=str),
                encoding="utf-8",
            )
            console.print(f"[green]Exported to: {output}[/green]")
        except Exception as e:
            console.print(f"[red]Export failed: {e}[/red]")

    # ------------------------------------------------------------------
    # Query submenu (explore collected AD data)
    # ------------------------------------------------------------------

    def _query_dispatch(self, cmd: str, args: list[str]) -> None:
        if not self._collection_data and cmd not in ("back", "..", "help"):
            console.print("[red]No collection loaded. Run 'collect run' or 'collect load <id>' first.[/red]")
            return
        if cmd == "info":
            self._query_run("info", args)
        elif cmd == "members":
            self._query_run("members", args)
        elif cmd == "memberof":
            self._query_run("memberof", args)
        elif cmd == "acl":
            self._query_run("acl", args)
        elif cmd == "who-can":
            self._query_run("who-can", args)
        elif cmd == "custom":
            self._query_run("search", args)
        elif cmd == "graph":
            self._query_run("graph", args)
        elif cmd == "kerberoastable":
            self._query_run("kerberoastable", args)
        elif cmd == "delegation-map":
            self._query_run("delegation-map", args)
        elif cmd == "computers":
            self._query_run("computers", args)
        elif cmd == "trusts":
            self._query_run("trusts", args)
        elif cmd == "templates":
            self._query_run("templates", args)
        elif cmd == "spns":
            self._query_run("spns", args)
        elif cmd == "stats":
            # Detailed per-class breakdown (enabled/disabled, realms, OS); the
            # quick summary lives on 'collect > stats'.
            self._print_detailed_stats()
        elif cmd == "help":
            if args:
                show_detailed_help(args[0], _SEARCH_COMMANDS, "search")
            else:
                self._show_menu_help(_SEARCH_COMMANDS, "Search")
        else:
            console.print(f"[red]Unknown command: {cmd}[/red]")

    def _ensure_query_index(self):
        """Build (and cache) the CollectionIndex for the loaded collection."""
        from lazyhound.finder.collect.query import CollectionIndex
        if not getattr(self, "_query_index", None):
            self._query_index = CollectionIndex(self._collection_data)
        return self._query_index

    def _set_default_domain(self) -> None:
        """Pick the active domain: meta.domain if present, else the most-users
        domain. No-op for single/zero-domain collections (leaves it '')."""
        self._active_domain_sid = ""
        if not self._collection_data:
            return
        idx = self._ensure_query_index()
        doms = idx.domains()
        if not doms:
            return
        meta_dom = (self._collection_data.get("meta", {}).get("domain", "") or "").lower()
        chosen = next((d for d in doms if d.fqdn == meta_dom), None)
        if chosen is None:
            chosen = max(doms, key=lambda d: d.user_count)
        self._active_domain_sid = chosen.domain_sid

    def _active_domain_fqdn(self) -> str:
        """FQDN label of the active domain (for the prompt). Lazily defaults."""
        self._active_domain_sid = getattr(self, "_active_domain_sid", "")
        if not self._collection_data:
            return self._collection_domain
        idx = self._ensure_query_index()
        if not self._active_domain_sid and idx.domains():
            self._set_default_domain()
        for d in idx.domains():
            if d.domain_sid == self._active_domain_sid:
                return d.fqdn
        return self._collection_domain

    def _cmd_domain(self, args: list[str]) -> None:
        """Global 'domain' command: list domains or switch the active one."""
        self._active_domain_sid = getattr(self, "_active_domain_sid", "")
        if not self._collection_data:
            console.print("[red]No collection loaded.[/red]")
            return
        idx = self._ensure_query_index()
        if not self._active_domain_sid and idx.domains():
            self._set_default_domain()
        doms = idx.domains()
        if not doms:
            console.print("[dim]Collection has no AD domains.[/dim]")
            return
        if not args:
            for d in doms:
                mark = "[green]*[/green]" if d.domain_sid == self._active_domain_sid else " "
                console.print(f"  {mark} {d.label}  ({d.netbios or '-'})  {d.domain_sid}  "
                              f"[dim]{d.object_count} objs[/dim]")
            return
        d = idx.resolve_domain(args[0])
        if d is None:
            console.print(f"[red]Unknown domain: {args[0]}[/red]  "
                          f"[dim]known: {', '.join(x.label for x in doms)}[/dim]")
            return
        self._active_domain_sid = d.domain_sid
        self._collection_domain = d.fqdn
        console.print(f"[green]Active domain: {d.fqdn}[/green]")

    def _resolve_domain_scope(self, args: list[str]):
        """Consume --domain from args; return (domain_sid, is_all) or None on a
        bad value. 'all' is the all-domains keyword; otherwise resolve a domain,
        falling back to the active domain when omitted."""
        self._active_domain_sid = getattr(self, "_active_domain_sid", "")
        token = pop_option(args, "domain", "")
        if not getattr(self, "_collection_data", None):
            return ("", False)          # no collection -> nothing to scope
        if not self._active_domain_sid:
            self._set_default_domain()
        idx = self._ensure_query_index()
        if token.lower() == "all":
            return ("", True)
        if token:
            d = idx.resolve_domain(token)
            if d is None:
                console.print(f"[red]Unknown domain: {token}[/red]  "
                              f"[dim]known: {', '.join(x.label for x in idx.domains())}[/dim]")
                return None
            return (d.domain_sid, False)
        return (self._active_domain_sid, False)

    def _pathfind_scope(self, args: list[str], tokens: list[str]):
        """Realm filter for the --from/--to pathfinding commands: '' (all
        realms) unless the user passed an explicit --domain. `args` is the
        original arg list (to detect --domain); `tokens` is the working list
        `_resolve_domain_scope` consumes. Returns None only on a bad --domain."""
        had_domain = any(a in ("--domain", "-domain") for a in args)
        scope = self._resolve_domain_scope(tokens)
        if scope is None:
            return None
        if not had_domain or scope[1]:        # no --domain, or --domain all
            return ""
        return scope[0]

    def _name_in_domain(self, name: str, domain_sid: str) -> str:
        """Resolve a pathfinding NAME to a domain-scoped object SID, so a
        forest-ambiguous --from/--to picks the right domain's object. Returns the
        name unchanged when not scoping (empty domain_sid), no collection, or no
        match in that domain — callers keep `name` for display either way."""
        if not name or not domain_sid or not getattr(self, "_collection_data", None):
            return name
        obj = self._ensure_query_index().get_in_domain(name, domain_sid)
        return obj.get("object_sid") if obj else name

    def _print_forest_banner(self, findings: list) -> None:
        """For --domain all on a multi-domain collection: a one-line per-domain
        finding breakdown (by source principal) so the forest breadth is visible.
        Silent for single-domain collections."""
        idx = self._ensure_query_index()
        if len(idx.domains()) <= 1:
            return
        from lazyhound.finder.collect.query import _domain_sid_of
        counts: dict[str, int] = {}
        for f in findings:
            dsid = _domain_sid_of(getattr(f, "principal_sid", "") or "")
            counts[dsid] = counts.get(dsid, 0) + 1
        parts = []
        for dsid, n in sorted(counts.items(), key=lambda kv: -kv[1]):
            if not dsid:
                parts.append(f"cross-domain/well-known ({n})")
            else:
                d = idx.resolve_domain(dsid)
                parts.append(f"{(d.label if d else dsid).upper()} ({n})")
        ndoms = sum(1 for k in counts if k)
        total = sum(counts.values())
        console.print(f"[dim]Forest-wide: {total} findings across {ndoms} domain(s) — "
                      f"{', '.join(parts)}[/dim]")

    def _print_scope_header(self, domain_sid: str, is_all: bool, explicit: bool) -> None:
        """Header noting the active domain + which domains are filtered. Silent
        for single-domain collections and for --domain all."""
        idx = self._ensure_query_index()
        doms = idx.domains()
        if is_all or len(doms) <= 1:
            return
        active = next((d for d in doms if d.domain_sid == domain_sid), None)
        if active is None:
            return
        others = [d.label.upper() for d in doms if d.domain_sid != domain_sid]
        tag = "" if explicit else " (default)"
        console.print(f"[dim]Scope: {active.label.upper()}{tag} — filtered "
                      f"{len(others)} domain(s): {', '.join(others)}. "
                      f"Use --domain all for all.[/dim]")

    def _domain_label_for(self, obj: dict) -> str:
        """Display label of the object's domain ('?' if unknown)."""
        idx = self._ensure_query_index()
        d = idx.resolve_domain(idx.domain_of(obj))
        return d.label if d else "?"

    def _query_run(self, query_cmd: str, args: list[str]) -> None:
        """Execute a query command against the loaded collection."""
        try:
            from lazyhound.finder.collect.query import CollectionIndex
            import lazyhound.finder.collect.query_fmt as qfmt

            if not hasattr(self, '_query_index') or self._query_index is None:
                self._query_index = CollectionIndex(self._collection_data)

            idx = self._query_index

            scope = self._resolve_domain_scope(args)   # consumes --domain from args
            if scope is None:
                return
            domain_sid, is_all = scope
            explicit_domain = domain_sid != self._active_domain_sid or is_all
            target = args[0] if args else ""
            recursive = "--recursive" in args

            if query_cmd == "info":
                from lazyhound.finder.collect.query import object_info
                if is_all:
                    matches = idx.find_all_by_name(target)
                    if not matches:
                        console.print(f"[yellow]Object not found: {target}[/yellow]")
                        return
                    for o in matches:
                        info = object_info(idx, o.get("object_sid") or o.get("dn"))
                        if info:
                            qfmt.print_info_result(info)
                    return
                self._print_scope_header(domain_sid, is_all, explicit_domain)
                obj = idx.get_in_domain(target, domain_sid)
                if not obj:
                    elsewhere = {idx.domain_of(o) for o in idx.find_all_by_name(target)}
                    if elsewhere:
                        names = [d.label for d in idx.domains() if d.domain_sid in elsewhere]
                        console.print(f"[yellow]'{target}' not in the active domain; "
                                      f"exists in: {', '.join(names)} (use --domain).[/yellow]")
                    else:
                        console.print(f"[yellow]Object not found: {target}[/yellow]")
                    return
                qfmt.print_info_result(
                    object_info(idx, obj.get("object_sid") or obj.get("dn")))
            elif query_cmd == "members":
                if is_all:
                    rows = []
                    for g in idx.find_all_by_name(target):
                        if g.get("object_class") not in ("group", "aad_group"):
                            continue
                        for m in idx.members(g.get("object_sid"), recursive=recursive):
                            m = dict(m)
                            m["_domain"] = idx.domain_of(g)
                            rows.append(m)
                    qfmt.print_object_list(rows, f"Members of {target} (all domains)",
                                           idx, domain_col=True)
                    return
                self._print_scope_header(domain_sid, is_all, explicit_domain)
                g = idx.get_in_domain(target, domain_sid)
                if not g or g.get("object_class") not in ("group", "aad_group"):
                    console.print(f"[yellow]Group not found in scope: {target}[/yellow]")
                    return
                results = idx.members(g.get("object_sid"), recursive=recursive)
                qfmt.print_object_list(results, f"Members of {target}", idx)
            elif query_cmd == "memberof":
                if is_all:
                    matches = idx.find_all_by_name(target)
                    if not matches:
                        console.print(f"[yellow]Object not found: {target}[/yellow]")
                        return
                    for o in matches:
                        res = idx.memberof(o.get("object_sid"), recursive=recursive)
                        qfmt.print_object_list(
                            res, f"Groups for {target} @ {self._domain_label_for(o)}", idx)
                    return
                self._print_scope_header(domain_sid, is_all, explicit_domain)
                obj = idx.get_in_domain(target, domain_sid)
                if not obj:
                    console.print(f"[yellow]Not found in scope: {target}[/yellow]")
                    return
                results = idx.memberof(obj.get("object_sid"), recursive=recursive)
                qfmt.print_object_list(results, f"Groups for {target}", idx)
            elif query_cmd == "acl":
                if is_all:
                    matches = idx.find_all_by_name(target)
                    if not matches:
                        console.print(f"[yellow]Object not found: {target}[/yellow]")
                        return
                    for o in matches:
                        qfmt.print_acl(idx.acl(o.get("object_sid")),
                                       f"{target} @ {self._domain_label_for(o)}")
                    return
                self._print_scope_header(domain_sid, is_all, explicit_domain)
                obj = idx.get_in_domain(target, domain_sid)
                if not obj:
                    console.print(f"[yellow]Not found in scope: {target}[/yellow]")
                    return
                results = idx.acl(obj.get("object_sid"))
                qfmt.print_acl(results, target)
            elif query_cmd == "who-can":
                if len(args) >= 2:
                    if is_all:
                        matches = idx.find_all_by_name(args[1])
                        if not matches:
                            console.print(f"[yellow]Object not found: {args[1]}[/yellow]")
                            return
                        for o in matches:
                            res = idx.who_can(args[0], o.get("object_sid"))
                            qfmt.print_who_can(
                                res, args[0], f"{args[1]} @ {self._domain_label_for(o)}")
                        return
                    self._print_scope_header(domain_sid, is_all, explicit_domain)
                    tobj = idx.get_in_domain(args[1], domain_sid)
                    target_id = tobj.get("object_sid") if tobj else args[1]
                    results = idx.who_can(args[0], target_id)
                    qfmt.print_who_can(results, args[0], args[1])
                else:
                    console.print("[red]Usage: who-can <right> <target>[/red]")
            elif query_cmd == "search":
                if len(args) >= 1:
                    raw = args[0]
                    # Support LDAP-style filter: "(attr=value)" or "attr=value"
                    cleaned = raw.strip("()")
                    if "=" in cleaned and len(args) == 1:
                        attr, pattern = cleaned.split("=", 1)
                        pattern = pattern or "*"
                    else:
                        attr = raw
                        pattern = args[1] if len(args) > 1 else "*"
                    results = idx.search(attr, pattern)
                    if not is_all:
                        self._print_scope_header(domain_sid, is_all, explicit_domain)
                        results = idx.scope_rows(results, domain_sid)
                    qfmt.print_search_results(results, attr, pattern)
                else:
                    console.print("[red]Usage: search <attr> [pattern]  or  search <attr>=<value>[/red]")
            elif query_cmd == "kerberoastable":
                results = idx.kerberoastable()
                show_col = is_all and len(idx.domains()) > 1
                if not is_all:
                    self._print_scope_header(domain_sid, is_all, explicit_domain)
                    results = idx.scope_rows(results, domain_sid)
                qfmt.print_kerberoastable(results, idx=idx, domain_col=show_col)
            elif query_cmd == "delegation-map":
                results = idx.delegation_map()
                show_col = is_all and len(idx.domains()) > 1
                if not is_all:
                    self._print_scope_header(domain_sid, is_all, explicit_domain)
                    results = idx.scope_rows(results, domain_sid)
                qfmt.print_delegation_map(results, idx=idx, domain_col=show_col)
            elif query_cmd == "computers":
                os_filter = next((a for a in args if not a.startswith("--")), None)
                results = idx.computers(os_pattern=os_filter)
                show_col = is_all and len(idx.domains()) > 1
                if not is_all:
                    self._print_scope_header(domain_sid, is_all, explicit_domain)
                    results = idx.scope_objects(results, domain_sid)
                qfmt.print_object_list(results, "Computers", idx, domain_col=show_col)
            elif query_cmd == "trusts":
                results = idx.trusts()
                qfmt.print_trusts(results, idx)
            elif query_cmd == "templates":
                results = idx.certificate_templates()
                qfmt.print_templates(results)
            elif query_cmd == "spns":
                results = idx.spns()
                show_col = is_all and len(idx.domains()) > 1
                if not is_all:
                    self._print_scope_header(domain_sid, is_all, explicit_domain)
                    results = idx.scope_rows(results, domain_sid)
                qfmt.print_spns(results, idx=idx, domain_col=show_col)
            elif query_cmd == "graph":
                console.print("[dim]Use 'analyze' for attack path analysis (analyze, analyze shortest)[/dim]")
            else:
                console.print(f"[red]Unknown query command: {query_cmd}[/red]")

        except ImportError as e:
            console.print(f"[red]Missing dependency: {e}[/red]")
        except Exception as e:
            console.print(f"[red]Query error: {e}[/red]")

    # Friendly labels for object_class -> display name, split AD vs cloud.
    _AD_CLASS_LABELS = {
        "user": "Users", "computer": "Computers", "group": "Groups",
        "ou": "OUs", "gpo": "GPOs", "domain": "Domains",
        "trusteddomain": "Trusted Domains", "certtemplate": "Cert Templates",
        "pki": "PKI / CAs", "container": "Containers",
    }
    _CLOUD_CLASS_LABELS = {
        "aad_user": "Users", "aad_group": "Groups", "aad_sp": "Service Principals",
        "aad_app": "Applications", "aad_device": "Devices",
        "azure_tenant": "Tenants", "azure_sub": "Subscriptions",
        "azure_rg": "Resource Groups", "azure_vm": "Virtual Machines",
        "azure_kv": "Key Vaults",
    }

    def _print_collection_stats(self, s: dict) -> None:
        """Render the collection summary as organized tables instead of a dict."""

        def n(v):
            return f"{v:,}" if isinstance(v, int) else str(v)

        # -- Overview panel --
        when = str(s.get("collected_at", "") or "")
        if "T" in when:
            date, _, rest = when.partition("T")
            when = f"{date} {rest[:5]} UTC"
        lines = [f"[bold cyan]{s.get('domain', 'unknown')}[/bold cyan]"]
        dc = s.get("dc", "") or ""
        if dc and dc != "unknown":
            lines[0] += f"   [dim]·  DC:[/dim] {dc}"
        if when:
            lines.append(f"[dim]Collected:[/dim] {when}")
        method = s.get("collection_method", "") or ""
        if method and method != "unknown":
            lines.append(f"[dim]Method:[/dim] {method}")
        if s.get("tenant_name"):
            tid = str(s.get("tenant_id", "")).replace("/tenants/", "")
            lines.append(f"[dim]Tenant:[/dim] {s['tenant_name']}"
                         + (f"  [dim]{tid}[/dim]" if tid else ""))
        console.print(Panel("\n".join(lines), title="[bold]Collection Overview[/bold]",
                            border_style="cyan", expand=False))

        # -- Objects by class, split into AD and cloud tables. Classify by
        # prefix so unknown/future classes are still shown (never dropped), and
        # fall back to the raw class name when there's no friendly label. --
        by_class = s.get("by_class", {}) or {}

        def _is_cloud(cls):
            c = (cls or "").lower()
            return c.startswith(("aad_", "azure_", "az"))

        def _label(cls):
            return (self._CLOUD_CLASS_LABELS.get(cls)
                    or self._AD_CLASS_LABELS.get(cls) or cls)

        def _obj_table(title, cloud, style):
            rows = [(_label(c), cnt) for c, cnt in by_class.items()
                    if cnt and _is_cloud(c) == cloud]
            if not rows:
                return None
            rows.sort(key=lambda r: -r[1])
            t = Table(title=title, title_style=f"bold {style}", header_style="dim",
                      box=box.ROUNDED, border_style=style, expand=False)
            t.add_column("Type", min_width=16)
            t.add_column("Count", justify="right")
            for label, count in rows:
                t.add_row(label, n(count))
            t.add_row("[dim]Total[/dim]", f"[bold]{n(sum(r[1] for r in rows))}[/bold]")
            return t

        ad = _obj_table("Active Directory", False, "green")
        cloud = _obj_table("Entra / Azure", True, "blue")
        # Stacked one-per-row, each bordered.
        for t in (ad, cloud):
            if t is not None:
                console.print()
                console.print(t)

        # -- Totals / relationship metrics as a compact key/value grid --
        metrics = [
            ("Total objects", s.get("total_objects", 0)),
            ("Disabled accounts", s.get("disabled_accounts", 0)),
            ("SID map entries", s.get("sid_map_entries", 0)),
            ("Sessions", s.get("sessions", 0)),
            ("Local-admin rows", s.get("local_group_members", 0)),
        ]
        if s.get("azure_objects") is not None:
            metrics += [
                ("Azure objects", s.get("azure_objects", 0)),
                ("Azure edges", s.get("azure_edges", 0)),
                ("Hybrid edges", s.get("hybrid_edges", 0)),
                ("Synced users", s.get("synced_users", 0)),
            ]
        grid = Table(title="Totals", title_style="bold", box=box.ROUNDED,
                     border_style="dim", show_header=False, expand=False)
        # two label/value pairs per row
        grid.add_column("k1", style="dim"); grid.add_column("v1", justify="right")
        grid.add_column("gap", width=4); grid.add_column("k2", style="dim")
        grid.add_column("v2", justify="right")
        for i in range(0, len(metrics), 2):
            k1, v1 = metrics[i]
            if i + 1 < len(metrics):
                k2, v2 = metrics[i + 1]
                grid.add_row(k1, n(v1), "", k2, n(v2))
            else:
                grid.add_row(k1, n(v1), "", "", "")
        console.print()
        console.print(grid)

    # ------------------------------------------------------------------
    # Analyze submenu – attack path analysis via graph engine
    # ------------------------------------------------------------------

    def _analyze_dispatch(self, cmd: str, args: list[str]) -> None:
        if not self._collection_data and cmd not in ("back", "..", "help"):
            console.print("[red]No collection loaded. Run 'collect run' or 'collect load <id>' first.[/red]")
            return
        if cmd == "run":
            self._analyze_run(args)
        elif cmd == "shortest":
            self._analyze_shortest(args)
        elif cmd == "trace":
            self._analyze_trace(args)
        elif cmd == "find":
            self._analyze_find(args)
        elif cmd == "paths":
            self._analyze_paths(args)
        elif cmd == "graph":
            self._analyze_graph(args)
        elif cmd == "export":
            self._analyze_export(args)
        elif cmd == "checks":
            self._analyze_checks()
        elif cmd == "help":
            if args:
                show_detailed_help(args[0], _ANALYZE_COMMANDS, "analyze")
            else:
                self._show_menu_help(_ANALYZE_COMMANDS, "Analyze – Attack Path Analysis")
        else:
            console.print(f"[red]Unknown command: {cmd}[/red]")

    def _ensure_analysis(self) -> bool:
        """Ensure a cached analysis result exists for the view subcommands.
        Computes it once (via the normal run path) if absent. Returns False
        when there is no collection to analyze."""
        if getattr(self, "_analysis_result", None) is not None:
            return True
        if not getattr(self, "_collection_data", None):
            console.print("[red]No collection loaded. Run 'collect run' or "
                          "'collect load <id>' first.[/red]")
            return False
        console.print("[dim]No analysis yet — running 'analyze' first…[/dim]")
        self._analyze_run([])
        return getattr(self, "_analysis_result", None) is not None

    def _analyze_run(self, args: list[str]) -> None:
        """Run the full attack-path analyzer on the loaded collection."""
        from lazyhound.finder.collect.analyzer import (
            analyze, get_active_checks, set_show_tier_zero_actors,
        )
        from rich.progress import Progress, SpinnerColumn, TextColumn

        tokens = list(args)
        # Tier-Zero-actor / low-signal findings are shown by default; --notier0 hides them.
        hide_tier_zero = pop_flag(tokens, "--notier0")
        set_show_tier_zero_actors(not hide_tier_zero)
        category = pop_option(tokens, "category", "")
        checks = pop_option(tokens, "checks", "")
        exclude = pop_option(tokens, "exclude", "")
        owned_str = pop_option(tokens, "owned", "")
        # Scale controls (opt-in): --prune to the Tier-Zero-reachable subgraph,
        # --aggregate <slug,slug> to collapse per-object findings.
        prune = pop_flag(tokens, "--prune")
        noexpand = pop_flag(tokens, "--noexpand")
        # Expansion rollup cap: --expand-cap N (0 = never roll up); falls back to
        # LAZYHOUND_EXPAND_CAP; flag wins over env. Invalid -> default.
        from lazyhound.finder.collect.analyzer import _DEFAULT_EXPAND_CAP
        _cap_str = pop_option(tokens, "expand-cap", "")
        if not _cap_str:
            _cap_str = os.environ.get("LAZYHOUND_EXPAND_CAP", "")
        try:
            expand_cap = int(_cap_str) if _cap_str.strip() != "" else _DEFAULT_EXPAND_CAP
            if expand_cap < 0:
                expand_cap = _DEFAULT_EXPAND_CAP
        except (ValueError, AttributeError):
            console.print(f"[yellow]Invalid --expand-cap '{_cap_str}'; using default "
                          f"{_DEFAULT_EXPAND_CAP}.[/yellow]")
            expand_cap = _DEFAULT_EXPAND_CAP
        aggregate_str = pop_option(tokens, "aggregate", "")

        categories = {c.strip() for c in category.split(",") if c.strip()} or None
        check_set = {c.strip() for c in checks.split(",") if c.strip()} or None
        exclude_set = {c.strip() for c in exclude.split(",") if c.strip()} or None
        owned = [o.strip() for o in owned_str.split(",") if o.strip()] or None
        aggregate = {c.strip() for c in aggregate_str.split(",") if c.strip()} or None
        if aggregate:
            from lazyhound.finder.collect.analyzer import Category
            valid = {c.slug for c in Category}
            unknown = {s for s in aggregate if s not in valid}
            if unknown:
                console.print(f"[yellow]Ignoring unknown --aggregate categor(y/ies): "
                              f"{', '.join(sorted(unknown))}[/yellow]")
                aggregate = {s for s in aggregate if s in valid} or None

        console.print(f"\n[bold cyan]Running attack path analysis on {self._collection_domain}...[/bold cyan]")
        if categories:
            console.print(f"  [dim]Categories: {', '.join(sorted(categories))}[/dim]")
        if owned:
            console.print(f"  [dim]Owned principals: {', '.join(owned)}[/dim]")
        if prune:
            console.print("  [dim]Prune: keeping only Tier-Zero-reachable findings[/dim]")
        if aggregate:
            console.print(f"  [dim]Aggregate: {', '.join(sorted(aggregate))}[/dim]")
        if noexpand:
            console.print("  [dim]No-expand: skipping per-member group expansion[/dim]")

        try:
            with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}")) as progress:
                task = progress.add_task("Analyzing…", total=None)

                def progress_cb(name: str, done: int, total: int) -> None:
                    # Show the running check so a slow/large collection reveals
                    # exactly where it's spending time (the last name = the hotspot).
                    progress.update(task, description=f"Analyzing… [{done}/{total}] {name}")

                result = analyze(
                    self._collection_data,
                    checks=check_set,
                    exclude=exclude_set,
                    owned=owned,
                    categories=categories,
                    aggregate=aggregate,
                    prune=prune,
                    expand=not noexpand,
                    expand_cap=expand_cap,
                    progress_callback=progress_cb,
                )
                progress.update(task, completed=True)

            self._analysis_result = result

            if result.expansion_rolled_up:
                console.print(
                    f"[yellow]Expansion rolled up: projected ~{result.expansion_projected:,} "
                    f"effective findings exceeded cap {result.expansion_cap:,} — showing "
                    f"per-(member,right,class) counts. Raise with --expand-cap.[/yellow]")

            # Compact summary by default — drill in with 'paths' / 'shortest'.
            n = len(result.actionable)
            console.print(f"\n[bold green]Analysis complete: {n} actionable findings[/bold green]")
            # --domain scopes the SUMMARY only; the full result is stored above so
            # 'paths' can re-slice without re-running.
            scope = self._resolve_domain_scope(args)
            domain_sid = "" if (scope is None or scope[1]) else scope[0]
            if scope is not None and scope[1]:           # --domain all
                self._print_forest_banner(result.actionable)
            elif scope is not None:                      # scoped to one domain
                self._print_scope_header(domain_sid, scope[1], False)
            self._analyze_summary(result, domain_sid=domain_sid)
            if getattr(result, "tier_zero_suppressed", 0):
                console.print(
                    f"[dim]  (--notier0: hiding {result.tier_zero_suppressed} low-signal findings — "
                    f"Tier-Zero actors and Exchange system objects; "
                    f"drop --notier0 to include)[/dim]")

        except Exception as e:
            console.print(f"[red]Analysis failed: {e}[/red]")

    def _analyze_shortest(self, args: list[str]) -> None:
        """Show shortest attack paths, re-running scoped when --from is given."""
        from lazyhound.finder.collect.analyzer import analyze, Category

        tokens = list(args)
        from_user = pop_option(tokens, "from", "")
        to_target = pop_option(tokens, "to", "")
        depth_str = pop_option(tokens, "depth", "")
        domain_sid = self._pathfind_scope(args, tokens)   # all realms unless --domain
        if domain_sid is None:
            return

        # Describe the query so the operator can see the values are used.
        scope = []
        if from_user:
            scope.append(f"from [bold]{from_user}[/bold]")
        if to_target:
            scope.append(f"to [bold]{to_target}[/bold]")
        if depth_str:
            scope.append(f"max depth {depth_str}")
        scope_str = (" " + " ".join(scope)) if scope else ""

        # Ensure a canonical FULL analysis exists — the one 'run' stores and
        # 'paths' slices. Nothing below may overwrite it.
        if self._analysis_result is None:
            console.print("[cyan]Running attack path analysis...[/cyan]")
            self._analysis_result = analyze(self._collection_data)

        # A source principal needs its OWN owned-scoped pass (owned-scoping
        # changes the graph, it's not just a filter). That pass is EPHEMERAL —
        # used only to render this view — and must NOT replace the canonical
        # result, or a later 'paths' would show only these scoped findings
        # (repro: run → paths → shortest --from bob → paths showed 108 not 449).
        if from_user:
            console.print(f"[cyan]Running shortest-path analysis{scope_str}...[/cyan]")
            source = analyze(
                self._collection_data,
                checks={"shortest-path"},
                owned=[from_user],
            )
        else:
            console.print(f"[dim]Shortest attack paths{scope_str}[/dim]")
            source = self._analysis_result

        # Filter findings
        path_findings = [
            f for f in source.findings
            if f.category == Category.SHORTEST_PATH
        ]
        if from_user:
            from_lower = from_user.lower()
            path_findings = [f for f in path_findings if from_lower in f.principal_name.lower()]
        if to_target:
            to_lower = to_target.lower()
            path_findings = [f for f in path_findings if to_lower in f.target_name.lower()]
        path_findings = self._scope_findings(path_findings, domain_sid)
        if depth_str:
            try:
                max_d = int(depth_str)
                path_findings = [f for f in path_findings if f.details.get("depth", 99) <= max_d]
            except ValueError:
                console.print(f"[yellow]Ignoring non-numeric --depth: {depth_str}[/yellow]")

        if not path_findings:
            if from_user:
                console.print(self._no_path_from_hint(from_user))
            else:
                console.print("[dim]No attack paths to high-value targets in this collection.[/dim]")
            return

        # Render using the existing path table formatter
        from lazyhound.finder.finder_formatting import _print_path_table
        console.print(f"\n[bold]Shortest Attack Paths ({len(path_findings)})[/bold]\n")
        _print_path_table(path_findings, idx=self._ensure_query_index()
                          if getattr(self, "_collection_data", None) else None)

    def _principal_status(self, identifier: str) -> str:
        """Classify a --from identifier: 'tier_zero' | 'exists' | 'missing'."""
        from lazyhound.finder.tier_zero import is_tier_zero_object
        ident = (identifier or "").lower()
        for o in (self._collection_data or {}).get("objects", []):
            name = (o.get("name") or "").lower()
            sam = (o.get("properties", {}).get("sAMAccountName") or "").lower()
            short = name.split("@", 1)[0]
            if ident in (name, sam, short) or (name and ident in name):
                return "tier_zero" if is_tier_zero_object(o) else "exists"
        return "missing"

    def _no_path_from_hint(self, identifier: str) -> str:
        """Explain why `shortest --from <identifier>` produced nothing."""
        status = self._principal_status(identifier)
        if status == "missing":
            return f"[yellow]No principal matching '{identifier}' in this collection.[/yellow]"
        if status == "tier_zero":
            return (
                f"[yellow]'{identifier}' is already a Tier-Zero / high-value target.[/yellow]\n"
                "[dim]Shortest-path finds routes TO Tier Zero, so a Tier-Zero principal is "
                "never the start of a path.[/dim]"
            )
        return (
            f"[yellow]'{identifier}' has no attack path to a high-value target in this collection.[/yellow]\n"
            "[dim]Its privileges may stop at non-Tier-Zero hosts. Bridging to Tier Zero usually "
            "needs session data (collect sessions) or LAPS/RBCD edges.[/dim]"
        )

    def _analyze_find(self, args: list[str]) -> None:
        """Ad-hoc graph query: objects by attribute and/or reachability."""
        if not self._collection_data:
            console.print("[red]No collection loaded.[/red]")
            return
        from lazyhound.finder.collect.analyzer import query_graph

        tokens = list(args)
        reaches = pop_option(tokens, "reaches", "")
        src = pop_option(tokens, "from", "")
        preds: list[str] = []
        for t in tokens:
            preds.extend(p for p in t.split(",") if p)
        if not preds and not reaches and not src:
            console.print("[yellow]Usage: find <predicates> [--reaches <target|tier0>] [--from <source>][/yellow]")
            console.print("[dim]predicates: type:user|computer|group|ou|gpo, kerberoastable, "
                          "asrep, unconstrained, enabled, disabled, admincount, tier0, name:<substr>[/dim]")
            return
        try:
            rows = query_graph(self._collection_data, preds,
                               reaches=(reaches or None), reachable_from=(src or None))
        except ValueError as e:
            console.print(f"[red]{e}[/red]")
            return
        if not rows:
            console.print("[dim]No objects match.[/dim]")
            return
        table = Table(title=f"Query results ({len(rows)})", show_header=True, header_style="bold")
        table.add_column("Name")
        table.add_column("Type", width=10)
        table.add_column("Tags")
        for r in rows[:500]:
            table.add_row(r["name"], r["type"], ", ".join(r["tags"]))
        console.print(table)
        if len(rows) > 500:
            console.print(f"[dim]... {len(rows) - 500} more (refine the query)[/dim]")

    def _analyze_trace(self, args: list[str]) -> None:
        """Shortest path(s) to an arbitrary target object (any node)."""
        if not self._collection_data:
            console.print("[red]No collection loaded.[/red]")
            return
        from lazyhound.finder.collect.analyzer import paths_to_target

        tokens = list(args)
        to_target = pop_option(tokens, "to", "")
        from_user = pop_option(tokens, "from", "")
        domain_sid = self._pathfind_scope(args, tokens)   # all realms unless --domain
        if domain_sid is None:
            return
        # search by the domain-scoped SID; keep the names for display
        to_id = self._name_in_domain(to_target, domain_sid)
        from_id = self._name_in_domain(from_user, domain_sid)
        depth_str = pop_option(tokens, "depth", "")
        if not to_target:
            console.print("[yellow]Specify a target: path --to <name|SID> [--from <source>][/yellow]")
            return
        kwargs: dict = {}
        if depth_str:
            try:
                kwargs["max_depth"] = int(depth_str)
            except ValueError:
                console.print(f"[yellow]Ignoring non-numeric --depth: {depth_str}[/yellow]")

        findings = paths_to_target(
            self._collection_data, to_id, source=(from_id or None), **kwargs)
        if not findings:
            if self._principal_status(to_target) == "missing":
                console.print(f"[yellow]No object matching '{to_target}' in this collection.[/yellow]")
            elif from_user and self._principal_status(from_user) == "missing":
                console.print(f"[yellow]No principal matching '{from_user}'.[/yellow]")
            else:
                scope = f" from '{from_user}'" if from_user else ""
                console.print(f"[dim]No path found to '{to_target}'{scope}.[/dim]")
            return

        from lazyhound.finder.finder_formatting import _print_path_table
        scope = f" to {to_target}" + (f" from {from_user}" if from_user else "")
        console.print(f"\n[bold]Paths{scope} ({len(findings)})[/bold]\n")
        _print_path_table(findings, idx=self._ensure_query_index()
                          if getattr(self, "_collection_data", None) else None)

    _SEV_RANK = ["critical", "high", "medium", "low", "info"]

    def _scope_findings(self, findings: list, domain_sid: str) -> list:
        """Filter findings to those whose SOURCE principal belongs to the realm
        `domain_sid` (AD domain or Entra tenant). Synced identities span both
        realms; well-known/BUILTIN sources (empty realm set) are always kept.
        Empty domain_sid -> no filtering."""
        if not domain_sid:
            return list(findings)
        idx = self._ensure_query_index()
        out = []
        for f in findings:
            realms = idx.realms_of_sid(getattr(f, "principal_sid", "") or "")
            if (not realms) or domain_sid in realms:
                out.append(f)
        return out

    def _analyze_summary(self, result, domain_sid: str = "") -> None:
        """Compact overview: findings-by-category + top attack paths + drill-in hint."""
        from lazyhound.finder.collect.analyzer import Category
        actionable = self._scope_findings(result.actionable, domain_sid)
        if not actionable:
            console.print("[green]No actionable findings in scope.[/green]")
            return

        def rank(v: str) -> int:
            return self._SEV_RANK.index(v) if v in self._SEV_RANK else len(self._SEV_RANK)

        cats: dict[Category, list] = {}
        for f in actionable:
            cats.setdefault(f.category, []).append(f)

        table = Table(title=f"Findings by Category ({len(actionable)} actionable)",
                      show_header=True, header_style="bold")
        table.add_column("Category", style="cyan")  # slug: copy-paste into --category
        table.add_column("Count", justify="right")
        table.add_column("Worst")
        table.add_column("Crit", justify="right")
        table.add_column("High", justify="right")
        for cat, fs in sorted(cats.items(),
                              key=lambda kv: (min(rank(x.severity.value) for x in kv[1]),
                                              -len(kv[1]))):
            worst = min((x.severity.value for x in fs), key=rank)
            crit = sum(1 for x in fs if x.severity.value == "critical")
            high = sum(1 for x in fs if x.severity.value == "high")
            table.add_row(cat.slug, str(len(fs)), worst.upper(),
                          str(crit) if crit else "", str(high) if high else "")
        console.print(table)

        console.print("[dim]Drill in (Tab-completes):[/dim] "
                      "[bold]analyze paths --show[/bold] · "
                      "[bold]analyze paths --show --category <slug[,slug2]>[/bold] · "
                      "[bold]analyze paths --severity critical[/bold] · "
                      "[bold]analyze paths --top 20[/bold]")

    def _analyze_paths(self, args: list[str]) -> None:
        """Summary of attack paths/findings; --show / filters expand to tables."""
        if not self._ensure_analysis():
            return

        from lazyhound.finder.collect.analyzer import AnalysisResult
        import lazyhound.finder.finder_formatting as fmt

        tokens = list(args)
        scope = self._resolve_domain_scope(tokens)   # consumes --domain
        if scope is None:
            return
        domain_sid = "" if scope[1] else scope[0]
        if scope[1] and self._analysis_result:        # --domain all
            self._print_forest_banner(self._analysis_result.actionable)
        elif domain_sid:                               # scoped to a real domain
            explicit = domain_sid != getattr(self, "_active_domain_sid", "")
            self._print_scope_header(domain_sid, scope[1], explicit)
        # Label shown in the drill-in panel: the scoped domain, not the collection.
        scope_label = self._analysis_result.domain
        if domain_sid:
            d = self._ensure_query_index().resolve_domain(domain_sid)
            scope_label = d.label if d else self._analysis_result.domain
        # --show (alias: --all) expands the summary to the full per-category
        # finding tables; --category narrows to one or more categories.
        show = pop_flag(tokens, "--show") or pop_flag(tokens, "--all")
        show_inherited = pop_flag(tokens, "--show-inherited")
        category_filter = pop_option(tokens, "category", "")
        severity_filter = pop_option(tokens, "severity", "")
        top = pop_option(tokens, "top", "")

        # Default (no --show and no filter) → compact summary (the default view).
        if not (show or category_filter or severity_filter or top):
            self._analyze_summary(self._analysis_result, domain_sid=domain_sid)
            return

        findings = self._scope_findings(self._analysis_result.actionable, domain_sid)
        if category_filter:
            from lazyhound.finder.collect.analyzer import Category
            # --category accepts a comma-separated list (e.g. dcsync,shortest_path).
            cats: set = set()
            subs: list[str] = []
            for tok in (t.strip() for t in category_filter.split(",")):
                if not tok:
                    continue
                c = Category.from_token(tok)
                if c is not None:
                    cats.add(c)
                else:
                    subs.append(tok.lower().replace("-", "_"))

            def _match(f):
                if f.category in cats:
                    return True
                slug = f.category.slug
                val = f.category.value.lower().replace(" ", "_")
                return any(s in slug or s in val for s in subs)

            findings = [f for f in findings if _match(f)]
        if severity_filter:
            sl = severity_filter.lower()
            findings = [f for f in findings if f.severity.value == sl]
        if top:
            try:
                n = int(top)
                findings = sorted(
                    findings,
                    key=lambda f: (self._SEV_RANK.index(f.severity.value)
                                   if f.severity.value in self._SEV_RANK else 9,
                                   f.details.get("depth", 99)))[:n]
            except ValueError:
                console.print(f"[yellow]Ignoring non-numeric --top: {top}[/yellow]")

        if not findings:
            console.print("[dim]No attack paths matching criteria.[/dim]")
            return

        filtered = AnalysisResult(
            domain=scope_label,
            source_file=self._analysis_result.source_file,
            owned_sids=self._analysis_result.owned_sids,
            total_objects=self._analysis_result.total_objects,
        )
        filtered.findings = findings
        # If you drilled into a filter and EVERY match is an inherited ACE,
        # hiding them all would leave an empty table — show them automatically.
        auto_inh = all(getattr(f, "inherited", False) for f in findings)
        fmt.print_analysis_results(filtered, style=2, top=0,
                                   show_inherited=show_inherited or auto_inh,
                                   idx=self._ensure_query_index()
                                   if getattr(self, "_collection_data", None) else None)

    def _analyze_graph(self, args: list[str]) -> None:
        """Render an attack diagram as ASCII in the terminal."""
        if not self._ensure_analysis():
            return
        kind = (args[0] if args else "paths").lower()
        from lazyhound.finder.reports.visualize.extract import build_visual_graph, KINDS
        from lazyhound.finder.reports.visualize.ascii import render_ascii
        if kind in ("delegation", "graph"):
            console.print(
                f"[yellow]'{kind}' is too dense for ASCII — "
                f"use 'export --format svg --type {kind}'.[/yellow]")
            return
        if kind not in KINDS:
            console.print(f"[red]Unknown type: {kind}. Choose from: {', '.join(KINDS)}[/red]")
            return
        try:
            g = build_visual_graph(kind, self._analysis_result, self._collection_data)
            if not g.nodes:
                console.print(self._empty_graph_hint(kind))
                return
            console.print(render_ascii(g))
        except Exception as e:  # pragma: no cover - defensive
            console.print(f"[red]Render failed: {e}[/red]")

    @staticmethod
    def _empty_graph_hint(kind: str) -> str:
        """Actionable message when a diagram has nothing to draw."""
        hints = {
            "paths": (
                "[yellow]No attack paths to high-value targets in the current analysis.[/yellow]\n"
                "[dim]Run 'analyze run' to compute paths. If you already have, this "
                "collection has no multi-hop path to a Tier-Zero target "
                "(direct ACL/kerberoast findings can still exist — see 'paths').[/dim]"
            ),
            "blast": (
                "[yellow]No blast-radius data.[/yellow]\n"
                "[dim]Blast radius is computed from owned principals — run "
                "'analyze run --owned <user>[,<user>...]' first.[/dim]"
            ),
            "trusts": (
                "[yellow]No domain trust relationships found in this collection.[/yellow]"
            ),
        }
        return hints.get(kind, "[dim](no data to display)[/dim]")

    def _filter_findings(self, findings, category="", severity="",
                         from_user="", domain_sid=""):
        """Apply export's --category / --severity / --from / --domain filters to
        a findings list. Shared by the diagram and the json/csv data export
        paths so both honor the same flags."""
        from lazyhound.finder.collect.analyzer import Category
        out = list(findings)
        if category:
            cat = Category.from_token(category)
            if cat is not None:
                out = [f for f in out if f.category == cat]
            else:
                cl = category.lower().replace("-", "_")
                out = [f for f in out if cl in f.category.slug]
        if severity:
            sl = severity.lower()
            out = [f for f in out if f.severity.value == sl]
        if from_user:
            fl = from_user.lower()
            out = [f for f in out if fl in (f.principal_name or "").lower()]
        return self._scope_findings(out, domain_sid)

    def _analyze_export(self, args: list[str]) -> None:
        """Export analysis results."""
        if not self._ensure_analysis():
            return

        tokens = list(args)
        fmt = pop_option(tokens, "format", "json")
        dtype = pop_option(tokens, "type", "paths")
        from_user = pop_option(tokens, "from", "")
        to_target = pop_option(tokens, "to", "")
        category_filter = pop_option(tokens, "category", "")
        severity_filter = pop_option(tokens, "severity", "")
        export_domain_sid = self._pathfind_scope(args, tokens)   # all realms unless --domain
        if export_domain_sid is None:
            return
        # PATH mode disambiguates the --from/--to name to a domain SID (display
        # keeps the name); findings mode filters findings by domain.
        from_id = self._name_in_domain(from_user, export_domain_sid)
        to_id = self._name_in_domain(to_target, export_domain_sid)
        output = pop_option(tokens, "o", "")
        if not output:
            ext = {"ascii": "txt", "mermaid": "mmd"}.get(fmt, fmt)
            if category_filter:
                who = f"_{from_user.replace(' ', '_')}" if from_user else ""
                fname = f"findings_{category_filter}{who}.{ext}"
            elif from_user or to_target:
                who = (from_user or "all").replace(" ", "_")
                tgt = (to_target or "TierZero").replace(" ", "_")
                fname = f"path_{who}_to_{tgt}.{ext}"
            else:
                fname = f"analysis_{self._collection_domain}.{ext}"
            output = self._default_output_path("exports", fname)
        output = self._prompt_export_path(output)
        if not output:
            return

        result = self._analysis_result

        graphical = {"ascii", "mermaid", "dot", "svg", "png"}
        if fmt in graphical:
            from lazyhound.finder.reports.visualize.extract import build_visual_graph, KINDS
            if dtype not in KINDS:
                console.print(f"[red]Unknown --type: {dtype}. Choose from: {', '.join(KINDS)}[/red]")
                return
            theme = self._options.get("mermaid_theme", "dark") if hasattr(self, "_options") else "dark"
            try:
                # --category/--severity: render a diagram of those findings
                # directly (each becomes a principal -[right]-> target edge),
                # so single-edge findings like LAPS read / ACL abuse / ownership
                # — which aren't Tier-Zero paths — can still be exported.
                # Optional --from narrows to one principal.
                if category_filter or severity_filter:
                    from lazyhound.finder.reports.visualize.extract import (
                        build_findings_graph)
                    findings = self._filter_findings(
                        result.actionable, category_filter, severity_filter,
                        from_user, export_domain_sid)
                    if not findings:
                        console.print("[yellow]No findings match those filters "
                                      "to render.[/yellow]")
                        return
                    label = category_filter or severity_filter
                    g = build_findings_graph(
                        findings, self._collection_data or {"objects": []},
                        owned=getattr(result, "owned_sids", set()),
                        title=f"{findings[0].category.value} — {result.domain}"
                              if category_filter else f"{label} findings — {result.domain}",
                        subtitle=f"{len(findings)} finding(s)"
                                 + (f" · {from_user}" if from_user else ""))
                # --from/--to: scope the diagram to one account's path. With
                # --to, route to that named target; without it, route to the
                # account's NEAREST Tier-Zero target of ANY kind (DA, DC, the
                # Entra tenant via hybrid sync, an ADCS CA, …) so any principal
                # that appears on a path can be exported — even if not to DA.
                elif from_user or to_target:
                    from lazyhound.finder.collect.analyzer import (
                        paths_to_target, paths_to_tier_zero, AnalysisResult)
                    if not self._collection_data:
                        console.print("[red]No collection loaded — needed for "
                                      "--from/--to scoping.[/red]")
                        return
                    if to_target:
                        findings = paths_to_target(
                            self._collection_data, to_id,
                            source=(from_id or None))
                        no_path = (f"[yellow]No path to '{to_target}'"
                                   + (f" from '{from_user}'" if from_user else "")
                                   + " to render.[/yellow]")
                    elif from_user:
                        findings = paths_to_tier_zero(
                            self._collection_data, from_id)
                        no_path = (f"[yellow]No attack path from '{from_user}' "
                                   f"to any Tier-Zero target.[/yellow]")
                    else:
                        findings = []
                        no_path = "[yellow]Nothing to render.[/yellow]"
                    if not findings:
                        console.print(no_path)
                        return
                    scoped = AnalysisResult(domain=result.domain, source_file="")
                    scoped.findings = findings
                    scoped.owned_sids = getattr(result, "owned_sids", set())
                    g = build_visual_graph(dtype, scoped, self._collection_data)
                    # Descriptive, self-explanatory title for a single pathway.
                    src_name = (from_user or
                                (findings[0].principal_name if findings else "?"))
                    tgt_name = (findings[0].target_name if findings
                                else (to_target or "Tier Zero"))
                    hops = min((f.details.get("depth", 0) for f in findings),
                               default=0)
                    g.title = f"Elevated Access: {src_name} → {tgt_name}"
                    g.subtitle = (
                        f"Shortest privilege-escalation path "
                        f"({hops} hop{'s' if hops != 1 else ''}) "
                        f"in {result.domain or 'the domain'}")
                else:
                    g = build_visual_graph(dtype, result, self._collection_data)
                if fmt == "ascii":
                    from lazyhound.finder.reports.visualize.ascii import render_ascii
                    Path(output).write_text(render_ascii(g), encoding="utf-8")
                elif fmt == "mermaid":
                    from lazyhound.finder.reports.visualize.mermaid import render_mermaid
                    Path(output).write_text(render_mermaid(g, theme), encoding="utf-8")
                elif fmt == "dot":
                    from lazyhound.finder.reports.visualize.dot import render_dot
                    Path(output).write_text(render_dot(g, theme), encoding="utf-8")
                else:  # svg / png
                    from lazyhound.finder.reports.visualize.dot import render_image
                    output = render_image(g, fmt, output, theme)
                console.print(f"[green]Exported to: {output}[/green]")
            except Exception as e:
                console.print(f"[red]Export failed: {e}[/red]")
            return

        # json/csv/data formats dump the actionable findings — honor the same
        # --category/--severity/--from/--domain filters as the diagram modes, so
        # e.g. `export --format csv --category dcsync` writes only dcsync rows.
        rows = self._filter_findings(
            result.actionable, category_filter, severity_filter,
            from_user, export_domain_sid)
        if (category_filter or severity_filter or from_user) and not rows:
            console.print("[yellow]No findings match those filters to export.[/yellow]")
            return

        try:
            if fmt == "json":
                import json
                data = {
                    "domain": result.domain,
                    "total_findings": len(result.findings),
                    "actionable": len(rows),
                    "findings": [
                        {
                            "category": f.category.value,
                            "severity": f.severity.value,
                            "principal": f.principal_name,
                            "target": f.target_name,
                            "description": f.description,
                            "rights": f.rights,
                            "details": f.details,
                        }
                        for f in rows
                    ],
                }
                Path(output).write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
            elif fmt == "csv":
                import csv
                with open(output, "w", newline="", encoding="utf-8") as fh:
                    writer = csv.writer(fh)
                    writer.writerow(["Category", "Severity", "Principal", "Target", "Description", "Rights"])
                    for f in rows:
                        writer.writerow([
                            f.category.value, f.severity.value,
                            f.principal_name, f.target_name,
                            f.description, "|".join(f.rights),
                        ])
            elif fmt in ("html", "md"):
                # Use JSON export as fallback for these formats
                import json
                data = {
                    "domain": result.domain, "format": fmt,
                    "total_findings": len(result.findings),
                    "actionable": len(rows),
                    "findings": [
                        {
                            "category": f.category.value, "severity": f.severity.value,
                            "principal": f.principal_name, "target": f.target_name,
                            "description": f.description, "rights": f.rights,
                            "details": {k: v for k, v in f.details.items() if k != "path_sids"},
                        }
                        for f in rows
                    ],
                }
                Path(output).write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
            else:
                console.print(f"[red]Unsupported format: {fmt}[/red]")
                return
            console.print(f"[green]Exported to: {output}[/green] "
                          f"[dim]· {len(rows)} finding(s)[/dim]")
        except Exception as e:
            console.print(f"[red]Export failed: {e}[/red]")

    def _analyze_checks(self) -> None:
        """List available analysis checks."""
        from lazyhound.finder.collect.analyzer import (
            list_checks, finding_category_slug)

        checks = list_checks()
        table = Table(title=f"Attack Path Analysis Checks ({len(checks)})", show_header=True, header_style="bold", expand=True)
        table.add_column("Check (run --checks)", width=20)
        table.add_column("Finding Category\n(paths --category)", width=20)
        table.add_column("Description", min_width=44)

        for c in checks:
            slug = finding_category_slug(c.name) or "[dim]—[/dim]"
            table.add_row(c.name, slug, c.description)
        console.print(table)
        console.print(
            "[dim]Run one check:[/dim] analyze run --checks <check>    "
            "[dim]·[/dim]    [dim]Drill into results:[/dim] analyze paths --category <finding category>")

    # ------------------------------------------------------------------
    # Report submenu
    # ------------------------------------------------------------------

    def _report_dispatch(self, cmd: str, args: list[str]) -> None:
        if cmd == "run":
            self._cmd_report_run(args)
        elif cmd == "help":
            if args:
                show_detailed_help(args[0], _REPORT_COMMANDS, "report")
            else:
                self._show_menu_help(_REPORT_COMMANDS, "Report Menu")
        else:
            console.print(f"[red]Unknown command: {cmd}[/red]")

    def _analysis_for_report(self):
        """The analyze result to report on. Reuses 'analyze run' if it was run
        (self._analysis_result); otherwise offers to run it now and caches the
        result (so the report — and later 'paths'/'shortest' — reuse it instead
        of recomputing on every 'report run')."""
        if self._analysis_result is not None:
            return self._analysis_result
        if not self._collection_data:
            return None
        try:
            ans = input("  No analysis yet — run 'analyze run' now to build the "
                        "report? [Y/n]: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            console.print()
            return None
        if ans in ("n", "no"):
            console.print("[dim]Skipped — run 'analyze run' first, then re-run the report.[/dim]")
            return None
        from lazyhound.finder.collect.analyzer import analyze
        console.print("[dim]Running attack path analysis…[/dim]")
        self._analysis_result = analyze(self._collection_data)
        return self._analysis_result

    def _report_template_context(self, rtype: str, domain: str,
                                 scan, analysis) -> dict:
        """Scalar {{placeholders}} available to a report template. Best-effort:
        any value that can't be derived is left blank, never raising."""
        from lazyhound.finder.reports.report_template import REPORT_TYPES
        ctx = {
            "domain": domain,
            "date": datetime.now().strftime("%Y-%m-%d"),
            "datetime": datetime.now().strftime("%Y-%m-%d %H:%M"),
            "report_type": rtype,
            "report_title": REPORT_TYPES.get(rtype, "LazyHound Report"),
            "operator": str(self._options.get("username", "") or ""),
            "tool": "LazyHound",
        }
        sev_keys = ("critical", "high", "medium", "low", "info")
        counts = {k: 0 for k in sev_keys}
        try:
            if rtype == "scan" and scan is not None:
                sd = scan.to_dict() if hasattr(scan, "to_dict") else (
                    scan if isinstance(scan, dict) else {})
                ctx["rating"] = str(sd.get("rating", ""))
                ctx["grade"] = str(sd.get("grade", ""))
                ctx["score"] = str(sd.get("risk_score", ""))
                ctx["finding_count"] = str(sd.get("total_findings", ""))
                for f in sd.get("findings", []) or []:
                    sev = str(f.get("severity", "")).lower()
                    if sev in counts:
                        counts[sev] += 1
            elif analysis is not None:
                actionable = getattr(analysis, "actionable", None)
                findings = actionable if actionable is not None else getattr(analysis, "findings", [])
                ctx["finding_count"] = str(len(findings))
                for f in findings:
                    sev = getattr(getattr(f, "severity", None), "value", "")
                    if sev in counts:
                        counts[sev] += 1
        except Exception:
            pass
        for k in sev_keys:
            ctx[f"{k}_count"] = str(counts[k])
        ctx.setdefault("finding_count", str(sum(counts.values())))
        return ctx

    def _cmd_report_run(self, args: list[str]) -> None:
        """Build a report from the loaded analyze OR scan data.

        report run [--type analyze|scan|heatmap|dashboard|graph|killchain|radar|target|leaderboard]
                   [--id <scan_id>] [--format html|pdf|markdown] [--style 1-5] [-o <path>]

        --type analyze  (default) the attack-path report from the analyze-run
                        findings (Findings Matrix + attack paths + offense/defense)
        --type scan     the security-scan findings (the scan's own report). By
                        default uses the last 'scan run'; pass --id <scan_id>
                        (see 'scan list') to report on a stored scan instead.
        --type heatmap  a standalone landscape MITRE ATT&CK matrix heatmap
                        (techniques colored by finding count; uses analyze data)
        --type dashboard  executive risk dashboard (gauge, KPIs, charts)
        --type graph      attack-path node-link graph (SVG)
        --type killchain  kill-chain flow diagram (SVG)
        --type radar      coverage radar of findings by category (SVG)
        --type target     Tier-Zero bullseye rings (SVG)
        --type leaderboard  top risks ranked board; all use analyze data
        """
        tokens = list(args)
        rtype = (pop_option(tokens, "type", "") or "analyze").lower()
        _TYPE_ALIASES = {"attackpaths": "analyze", "attack-paths": "analyze",
                         "paths": "analyze", "scanresults": "scan", "scan-results": "scan",
                         "heat": "heatmap", "mitre": "heatmap", "attack-heatmap": "heatmap",
                         "dash": "dashboard", "exec": "dashboard", "executive": "dashboard",
                         "attackgraph": "graph", "attack-graph": "graph", "paths-graph": "graph",
                         "kill-chain": "killchain", "flow": "killchain", "sankey": "killchain",
                         "spider": "radar", "coverage": "radar",
                         "rings": "target", "bullseye": "target",
                         "toprisks": "leaderboard", "top-risks": "leaderboard", "board": "leaderboard"}
        rtype = _TYPE_ALIASES.get(rtype, rtype)
        if rtype not in ("analyze", "scan", "heatmap", "dashboard", "graph", "killchain",
                         "radar", "target", "leaderboard"):
            console.print(f"[red]Unknown --type '{rtype}'. Use analyze, scan, heatmap, "
                          f"dashboard, graph, killchain, radar, target, or leaderboard.[/red]")
            return
        fmt = (pop_option(tokens, "format", "") or "html").lower()
        if fmt in ("md", "markdown"):
            fmt = "markdown"
        elif fmt in ("htm", "html"):
            fmt = "html"
        if fmt not in ("html", "pdf", "markdown"):
            console.print(f"[red]Unknown format '{fmt}'. Use html, pdf, or markdown.[/red]")
            return
        try:
            style = int(pop_option(tokens, "style", "1") or 1)
        except ValueError:
            style = 1
        if not 1 <= style <= 5:
            console.print("[yellow]--style must be 1-5; using 1.[/yellow]")
            style = 1

        # Optional stored-scan id: report on a past scan instead of the last
        # in-memory run (scan reports only). See 'scan list' for ids.
        scan_id = pop_option(tokens, "id", "").strip()

        # Each type uses exactly one data source.
        scan = getattr(self, "_scan_results", None)
        analysis = self._analysis_result
        if rtype in ("analyze", "heatmap", "dashboard", "graph", "killchain",
                     "radar", "target", "leaderboard"):
            if scan_id:
                console.print("[yellow]--id only applies to --type scan; ignoring.[/yellow]")
            if analysis is None:
                analysis = self._analysis_for_report()
            if not analysis:
                console.print("[yellow]No analysis — run 'analyze run' first (or load a "
                              "collection).[/yellow]")
                return
        else:  # scan
            if scan_id:
                try:
                    scan_dict = self._finder_history.get_scan(scan_id)
                except Exception:
                    scan_dict = None
                if not scan_dict:
                    console.print(f"[yellow]No stored scan matching '{scan_id}' "
                                  f"(see 'scan list').[/yellow]")
                    return
                from lazyhound.finder.scan.scan_cli import _reconstruct_scan_result
                try:
                    scan = _reconstruct_scan_result(scan_dict)
                except Exception as e:
                    console.print(f"[red]Could not load scan {scan_id}: {e}[/red]")
                    return
            elif not scan:
                console.print("[yellow]No scan in memory. Run 'scan run' first, or pass "
                              "--id <scan_id> to report on a stored scan "
                              "(see 'scan list').[/yellow]")
                return

        domain = self._collection_domain or "report"
        # A scan (in-memory or loaded by --id) carries its own target domain;
        # prefer it so the report and filename match the scanned realm.
        if rtype == "scan" and scan is not None:
            sd = scan.to_dict() if hasattr(scan, "to_dict") else (
                scan if isinstance(scan, dict) else {})
            domain = sd.get("target_domain") or sd.get("domain") or domain
        ext = {"html": "html", "pdf": "pdf", "markdown": "md"}[fmt]
        out = pop_option(tokens, "o", "") or self._default_output_path(
            "reports", f"report_{domain}_{rtype}.{ext}")
        out = self._prompt_export_path(out)
        if not out:
            return

        # Build the report body: either markdown/plain `text` or an `html_doc`.
        def _build_body() -> tuple[str | None, str | None]:
            if rtype == "analyze":
                if fmt == "markdown":
                    from lazyhound.finder.reports.attackpaths_report import build_attackpaths_markdown
                    return build_attackpaths_markdown(analysis, domain), None
                from lazyhound.finder.reports.attackpaths_report import build_attackpaths_html
                return None, build_attackpaths_html(analysis, domain, style=style)
            if rtype == "heatmap":
                if fmt == "markdown":
                    from lazyhound.finder.reports.heatmap_report import build_heatmap_markdown
                    return build_heatmap_markdown(analysis, domain), None
                from lazyhound.finder.reports.heatmap_report import build_heatmap_html
                return None, build_heatmap_html(analysis, domain, style=style)
            if rtype == "dashboard":
                from lazyhound.finder.reports.dashboard_report import (
                    build_dashboard_html, build_dashboard_markdown)
                if fmt == "markdown":
                    return build_dashboard_markdown(analysis, domain), None
                return None, build_dashboard_html(analysis, domain, style=style)
            if rtype == "graph":
                from lazyhound.finder.reports.graph_report import (
                    build_graph_html, build_graph_markdown)
                if fmt == "markdown":
                    return build_graph_markdown(analysis, domain), None
                return None, build_graph_html(analysis, domain, style=style)
            if rtype == "killchain":
                from lazyhound.finder.reports.killchain_report import (
                    build_killchain_html, build_killchain_markdown)
                if fmt == "markdown":
                    return build_killchain_markdown(analysis, domain), None
                return None, build_killchain_html(analysis, domain, style=style)
            if rtype == "radar":
                from lazyhound.finder.reports.radar_report import (
                    build_radar_html, build_radar_markdown)
                if fmt == "markdown":
                    return build_radar_markdown(analysis, domain), None
                return None, build_radar_html(analysis, domain, style=style)
            if rtype == "target":
                from lazyhound.finder.reports.target_report import (
                    build_target_html, build_target_markdown)
                if fmt == "markdown":
                    return build_target_markdown(analysis, domain), None
                return None, build_target_html(analysis, domain, style=style)
            if rtype == "leaderboard":
                from lazyhound.finder.reports.leaderboard_report import (
                    build_leaderboard_html, build_leaderboard_markdown)
                if fmt == "markdown":
                    return build_leaderboard_markdown(analysis, domain), None
                return None, build_leaderboard_html(analysis, domain, style=style)
            # scan — the scan's own report
            if fmt == "markdown":
                from lazyhound.finder.reports.markdown_report import MarkdownReport
                return MarkdownReport.to_string(scan), None
            from lazyhound.finder.reports.html_report import HTMLReport
            return None, HTMLReport.to_string(scan)

        try:
            text, html_doc = _build_body()
            # Apply the operator's editable template for this report type, if
            # one exists in the project's templates/ folder. Missing template →
            # the generated output is used verbatim (fully backward compatible).
            from lazyhound.finder.reports.report_template import ReportTemplate
            try:
                tmpl = ReportTemplate.load(rtype, self._project_base() / "templates")
            except Exception:
                tmpl = None
            if tmpl is not None:
                ctx = self._report_template_context(rtype, domain, scan, analysis)
                try:
                    if fmt == "markdown":
                        text = tmpl.render("markdown", text, ctx)
                    else:
                        html_doc = tmpl.render(fmt, html_doc, ctx)
                except Exception as te:
                    console.print(f"[yellow]Template render skipped ({te}); "
                                  f"using default layout.[/yellow]")
            if fmt == "markdown":
                Path(out).write_text(text, encoding="utf-8")
            elif fmt == "html":
                Path(out).write_text(html_doc, encoding="utf-8")
            else:  # pdf
                try:
                    from weasyprint import HTML
                except ImportError:
                    console.print("[red]PDF export needs WeasyPrint — install with "
                                  "'pip install lazyhound[reports]'.[/red]")
                    return
                HTML(string=html_doc).write_pdf(out)
            extra = (f", style {style}"
                     if rtype in ("analyze", "heatmap", "dashboard", "graph", "killchain",
                                  "radar", "target", "leaderboard") else "")
            console.print(f"[green]Report written: {out}[/green] "
                          f"[dim]({rtype}, {fmt}{extra})[/dim]")
        except Exception as e:
            console.print(f"[red]Failed to write report: {e}[/red]")

    # ------------------------------------------------------------------
    # Utils submenu
    # ------------------------------------------------------------------

    # All known external tools, grouped by source/install method.
    _TOOLS: list[dict[str, str]] = [
        # -- Python libraries (bundled with pip install) --
        {"name": "ldap3",                "check": "python3 -c 'import ldap3; print(ldap3.__version__)'",           "pkg": "ldap3",       "method": "pip", "cat": "python"},
        {"name": "impacket",             "check": "python3 -c 'import impacket; print(impacket.version.BANNER)'", "pkg": "impacket",    "method": "pip", "cat": "python"},
        {"name": "dnspython",            "check": "python3 -c 'import dns; print(dns.version.version)'",          "pkg": "dnspython",   "method": "pip", "cat": "python"},
        {"name": "pycryptodome",         "check": "python3 -c 'from Crypto import __version__; print(__version__)'","pkg": "pycryptodome","method": "pip","cat": "python"},
        {"name": "Pillow (PIL)",         "check": "python3 -c 'from PIL import Image; print(Image.__version__)'", "pkg": "Pillow",      "method": "pip", "cat": "python"},
        {"name": "rich",                 "check": "python3 -c 'import rich; print(rich.__version__)'",            "pkg": "rich",        "method": "pip", "cat": "python"},
        {"name": "click",                "check": "python3 -c 'import click; print(click.__version__)'",          "pkg": "click",       "method": "pip", "cat": "python"},
        {"name": "PyYAML",               "check": "python3 -c 'import yaml; print(yaml.__version__)'",            "pkg": "pyyaml",      "method": "pip", "cat": "python"},
        {"name": "python-docx",          "check": "python3 -c 'import docx; print(docx.__version__)'",            "pkg": "python-docx", "method": "pip", "cat": "python"},
        {"name": "weasyprint",           "check": "python3 -c 'import weasyprint; print(weasyprint.__version__)'","pkg": "weasyprint",  "method": "pip", "cat": "python"},
        {"name": "markdown",             "check": "python3 -c 'import markdown; print(markdown.__version__)'",    "pkg": "markdown",    "method": "pip", "cat": "python"},
        # -- Impacket CLI tools (installed with impacket) --
        {"name": "impacket-GetUserSPNs", "check": "impacket-GetUserSPNs -h",   "pkg": "impacket", "method": "pip", "cat": "impacket"},
        {"name": "impacket-GetNPUsers",  "check": "impacket-GetNPUsers -h",    "pkg": "impacket", "method": "pip", "cat": "impacket"},
        {"name": "impacket-secretsdump", "check": "impacket-secretsdump -h",   "pkg": "impacket", "method": "pip", "cat": "impacket"},
        {"name": "impacket-findDelegation", "check": "impacket-findDelegation -h", "pkg": "impacket", "method": "pip", "cat": "impacket"},
        {"name": "impacket-getST",       "check": "impacket-getST -h",         "pkg": "impacket", "method": "pip", "cat": "impacket"},
        {"name": "impacket-addcomputer", "check": "impacket-addcomputer -h",   "pkg": "impacket", "method": "pip", "cat": "impacket"},
        {"name": "impacket-rbcd",        "check": "impacket-rbcd -h",          "pkg": "impacket", "method": "pip", "cat": "impacket"},
        {"name": "impacket-rpcdump",     "check": "impacket-rpcdump -h",       "pkg": "impacket", "method": "pip", "cat": "impacket"},
        {"name": "impacket-dacledit",    "check": "impacket-dacledit -h",      "pkg": "impacket", "method": "pip", "cat": "impacket"},
        {"name": "impacket-owneredit",   "check": "impacket-owneredit -h",     "pkg": "impacket", "method": "pip", "cat": "impacket"},
        {"name": "impacket-Get-GPPPassword", "check": "impacket-Get-GPPPassword -h", "pkg": "impacket", "method": "pip", "cat": "impacket"},
        # -- External offensive tools (installed separately) --
        {"name": "certipy",              "check": "certipy -h",                "pkg": "certipy-ad", "method": "pip",  "cat": "external"},
        {"name": "nxc",                  "check": "nxc --version",             "pkg": "netexec",    "method": "pip",  "cat": "external"},
        {"name": "coercer",              "check": "coercer --help",            "pkg": "coercer",    "method": "pip",  "cat": "external"},
        {"name": "bloodhound-python",    "check": "bloodhound-python --help",  "pkg": "bloodhound", "method": "pip",  "cat": "external"},
        {"name": "ldapdomaindump",       "check": "ldapdomaindump --help",     "pkg": "ldapdomaindump", "method": "pip", "cat": "external"},
        {"name": "adidnsdump",           "check": "adidnsdump --help",         "pkg": "adidnsdump", "method": "pip",  "cat": "external"},
        {"name": "pywhisker",            "check": "python3 -c 'import pywhisker'", "pkg": "pywhisker", "method": "pip", "cat": "external"},
        {"name": "enum4linux-ng",        "check": "enum4linux-ng --help",      "pkg": "git+https://github.com/cddmp/enum4linux-ng", "method": "pip", "cat": "external"},
        {"name": "kerbrute",             "check": "kerbrute --help",           "pkg": "kerbrute",   "method": "go",   "cat": "external"},
        {"name": "evil-winrm",           "check": "evil-winrm --help",         "pkg": "evil-winrm", "method": "gem",  "cat": "external"},
        # -- System tools (apt / brew) --
        {"name": "rpcclient",            "check": "rpcclient --version",       "pkg": "smbclient",  "method": "apt",  "cat": "system"},
        {"name": "smbclient",            "check": "smbclient --version",       "pkg": "smbclient",  "method": "apt",  "cat": "system"},
        {"name": "ldapsearch",           "check": "ldapsearch -VV",            "pkg": "ldap-utils", "method": "apt",  "cat": "system"},
        {"name": "dig",                  "check": "dig -v",                    "pkg": "dnsutils",   "method": "apt",  "cat": "system"},
        {"name": "curl",                 "check": "curl --version",            "pkg": "curl",       "method": "apt",  "cat": "system"},
        {"name": "john",                 "check": "john --help",               "pkg": "john",       "method": "apt",  "cat": "system"},
        {"name": "hashcat",              "check": "hashcat --version",         "pkg": "hashcat",    "method": "apt",  "cat": "system"},
        {"name": "xfreerdp",             "check": "xfreerdp --version",        "pkg": "freerdp3-x11","method": "apt", "cat": "system"},
        {"name": "proxychains",          "check": "proxychains4 --help",       "pkg": "proxychains4","method": "apt", "cat": "system"},
    ]

    # ------------------------------------------------------------------
    # Options management
    # ------------------------------------------------------------------

    def _options_defaults(self) -> dict[str, Any]:
        """Shipped connection defaults, the baseline for 'is this set?'."""
        return Config().connection

    def _option_is_set(self, key: str) -> bool:
        """True if *key* has an explicit, non-default value."""
        cur = self._options.get(key, "")
        if cur in (None, ""):
            return False
        return str(cur) != str(self._options_defaults().get(key, ""))

    @staticmethod
    def _mask_option(key: str, val: Any) -> Any:
        if key in ("password", "nthash") and val not in (None, ""):
            return "********"
        return val

    def _show_options(self, full: bool = False) -> None:
        """Render the options view. Default = only explicitly-set keys; the
        full view shows every settable key with its current/default value."""
        defaults = self._options_defaults()

        if full:
            table = Table(title="All Options", show_header=True, header_style="bold")
            table.add_column("Key", width=16)
            table.add_column("Value", min_width=18)
            table.add_column("", style="dim", width=8)
            for group, keys in (("Connection", _CORE_OPTION_KEYS),
                                ("Transport", _TRANSPORT_OPTION_KEYS)):
                table.add_row(f"[bold cyan]{group}[/bold cyan]", "", "")
                for key in keys:
                    cur = self._options.get(key, defaults.get(key, ""))
                    marker = "" if self._option_is_set(key) else "default"
                    table.add_row(f"  {key}", str(self._mask_option(key, cur)), marker)
            console.print(table)
            console.print("[dim]  options <key>=<value>  set · options <key>=  clear one · "
                          "options clear  reset connection[/dim]")
            return

        # Concise: only explicitly-set connection keys.
        rows = [(k, self._mask_option(k, self._options.get(k)))
                for k in _CORE_OPTION_KEYS
                if self._option_is_set(k)]
        if not rows:
            console.print("[dim]No options set — all at defaults.  "
                          "'options <key>=<value>' to set · 'options all' to view every setting.[/dim]")
            return
        table = Table(title="Options (set)", show_header=True, header_style="bold")
        table.add_column("Key", width=16)
        table.add_column("Value", min_width=18)
        for k, v in rows:
            table.add_row(k, str(v))
        console.print(table)
        hidden = sum(1 for k in _CORE_OPTION_KEYS + _TRANSPORT_OPTION_KEYS
                     if not self._option_is_set(k))
        console.print(f"[dim]  {hidden} more at defaults · 'options all' to show them · "
                      "'options --help' for every settable key[/dim]")

    def _handle_options(self, args: list[str]) -> None:
        if not args:
            self._show_options(full=False)
            return
        if len(args) == 1 and args[0].lower() in ("all", "advanced", "-a", "--all"):
            self._show_options(full=True)
            return

        # Handle 'options clear'
        if len(args) == 1 and args[0].lower() == "clear":
            # Reset connection keys to their defaults. Identity/credential keys
            # default to empty; transport keys (auth_method, port, ...) reset to
            # their shipped defaults so, e.g., auth_method stays 'ntlm' rather
            # than becoming empty (which would fall back to a SIMPLE bind).
            # dc_fqdn is derived from dc+domain, so it clears too.
            defaults = self._options_defaults()
            conn_keys = list(_CORE_OPTION_KEYS) + list(_TRANSPORT_OPTION_KEYS) + ["dc_fqdn"]
            cleared = []
            for key in conn_keys:
                default = defaults.get(key, "")
                if str(self._options.get(key, "")) not in ("", str(default)):
                    cleared.append(key)
                self._options[key] = default
            if cleared:
                console.print(f"[green]Cleared: {', '.join(sorted(cleared))}[/green]")
            else:
                console.print("[dim]No connection options to clear.[/dim]")
            self.history.save_options(self._options)
            return

        # Validate every arg up front — if any token is malformed (e.g. a stray
        # 'set'), apply NOTHING. A partial apply that also errors is confusing.
        bad = [a for a in args if "=" not in a]
        if bad:
            console.print(
                f"[red]Invalid format: {' '.join(bad)} — use key=value "
                f"(e.g. dc=10.0.0.1). No changes made.[/red]")
            return

        for arg in args:
            key, _, value = arg.partition("=")
            key = key.strip().lower()
            value = value.strip()

            # Empty value = clear the key
            if not value:
                old = self._options.get(key, "")
                self._options[key] = ""
                # dc_fqdn is derived from dc+domain — invalidate the cache so
                # it re-derives instead of lingering as a stale realm.
                if key in ("dc", "domain"):
                    self._options["dc_fqdn"] = ""
                if old:
                    console.print(f"[green]{key} cleared[/green]")
                else:
                    console.print(f"[dim]{key} already empty[/dim]")
                continue

            # Type coercion
            if value.lower() in ("true", "yes"):
                value = True
            elif value.lower() in ("false", "no"):
                value = False
            elif value.isdigit():
                value = int(value)
            self._options[key] = value
            # Changing dc/domain invalidates the derived dc_fqdn cache.
            if key in ("dc", "domain"):
                self._options["dc_fqdn"] = ""
            # password, nthash, and ccache are mutually exclusive credentials —
            # only one auth method applies at a time, so setting one clears the
            # other two (matches manual entry).
            _cred_keys = {"password", "nthash", "ccache"}
            if key in _cred_keys:
                others = [k for k in _cred_keys
                          if k != key and self._options.get(k)]
                for k in others:
                    self._options[k] = ""
                if others:
                    labels = {"password": "password", "nthash": "NT hash",
                              "ccache": "ccache"}
                    cleared = ", ".join(labels[k] for k in others)
                    console.print(f"[dim]  ({cleared} cleared — "
                                  f"{labels[key]} takes over)[/dim]")
            # ccache is a file path, not a secret — show it; mask the rest.
            display = "********" if key in ("password", "nthash") else value
            console.print(f"[green]{key} = {display}[/green]")
        # Auto-persist options after any change
        self.history.save_options(self._options)

    def _ask(self, prompt: str, default: str = "") -> str:
        """Readline-friendly prompt.

        rich's ``Prompt.ask`` pre-prints the prompt and then calls a bare
        ``input()``; with GNU readline active (as it is in the shell) the first
        line edit — e.g. a backspace — redraws from column 0 and erases that
        pre-printed prompt. Passing the prompt straight to ``input()`` lets
        readline own it, so it survives editing. Returns *default* on empty
        input; EOFError/KeyboardInterrupt propagate to the caller.
        """
        suffix = f" [{default}]" if default else ""
        return input(f"{prompt}{suffix}: ").strip() or default

    def _ensure_credentials(self, operation: str = "validate") -> bool:
        """Ensure credentials are available. Prompts operator if not.

        Args:
            operation: What the creds are for — "collect", "scan", "validate",
                       "smb", "ldap", etc. Used to filter compatible identities.

        Returns True if credentials are ready, False if cancelled.
        """
        conn = self._connection_dict()
        has_dc = bool(conn.get("dc"))
        has_domain = bool(conn.get("domain"))
        has_creds = bool(
            conn.get("ccache")
            or (conn.get("username") and (conn.get("password") or conn.get("nthash")))
        )

        if has_dc and has_domain and has_creds:
            return True

        console.print("\n[bold yellow]Credentials required for this check.[/bold yellow]\n")

        # Show what's missing
        if not has_dc:
            console.print("  [red]Missing: DC IP/hostname[/red]")
        if not has_domain:
            console.print("  [red]Missing: Domain FQDN[/red]")
        if not has_creds:
            console.print("  [red]Missing: Username + password or NT hash[/red]")
        console.print()

        # Build options list
        options = []
        options.append(("manual", "Enter options manually"))
        options.append(("cancel", "Cancel"))

        for i, (key, desc) in enumerate(options, 1):
            console.print(f"  [bold][{i}][/bold] {desc}")

        console.print()
        choice = self._ask("  Choose", default="1")

        try:
            choice_idx = int(choice) - 1
        except ValueError:
            choice_idx = -1

        if 0 <= choice_idx < len(options):
            chosen_key = options[choice_idx][0]
        else:
            chosen_key = "cancel"

        # -- Manual entry ---------------------------------------------------
        if chosen_key == "manual":
            return self._enter_credentials_manually()

        # -- Cancel ---------------------------------------------------------
        return False

    def _enter_credentials_manually(self) -> bool:
        """Prompt operator for credentials inline."""
        dc = self._ask("  DC IP/hostname", default=str(self._options.get("dc", "")))
        if not dc:
            return False
        self._options["dc"] = dc

        # Domain prompt with '.' autodetect support
        current_domain = str(self._options.get("domain", ""))
        domain = self._prompt_domain(dc, current_domain)
        if not domain:
            console.print("[red]  Domain is required.[/red]")
            return False
        self._options["domain"] = domain

        username = self._ask("  Username", default=str(self._options.get("username", "")))
        if not username:
            return False
        self._options["username"] = username

        # If a credential is already set, Enter keeps it; only require entry when
        # none exists. This lets 'manual' fill in just the missing DC/domain
        # without forcing the operator to re-type a credential.
        existing_pw = str(self._options.get("password", ""))
        existing_hash = str(self._options.get("nthash", ""))
        existing_ccache = str(self._options.get("ccache", ""))
        has_existing_cred = bool(existing_pw or existing_hash or existing_ccache)
        cred_prompt = "  Password, NT hash, or Kerberos ccache path"
        if has_existing_cred:
            kind = ("Kerberos ccache" if existing_ccache
                    else "NT hash" if existing_hash else "password")
            cred_prompt += f" (Enter to keep current {kind})"
        cred = self._ask(cred_prompt)

        if not cred:
            if has_existing_cred:
                # Keep the existing credential as-is.
                self.history.save_options(self._options)
                console.print(f"[green]Credentials set: {username}@{domain}[/green]")
                return True
            return False

        # Classify the entry: an existing file path is a Kerberos ccache; a
        # 32-hex value (or LM:NT pair) is an NT hash; anything else a password.
        import os as _os
        parts = cred.split(":")
        is_hash = len(parts) in (1, 2) and all(
            len(p) == 32 and all(c in "0123456789abcdefABCDEF" for c in p)
            for p in parts)
        is_ccache = not is_hash and _os.path.isfile(_os.path.expanduser(cred))
        if is_ccache:
            self._options["ccache"] = _os.path.expanduser(cred)
            self._options["nthash"] = ""
            self._options["password"] = ""
        elif is_hash:
            self._options["nthash"] = cred
            self._options["password"] = ""
            self._options["ccache"] = ""
        else:
            self._options["password"] = cred
            self._options["nthash"] = ""
            self._options["ccache"] = ""

        # Save identity for future use (ccache is a file ref, not stored here).
        self.history.save_identity(
            domain=domain,
            username=username,
            password="" if (is_hash or is_ccache) else cred,
            nthash=cred if is_hash else "",
            source="manual",
        )

        self.history.save_options(self._options)
        console.print(f"[green]Credentials set: {username}@{domain}[/green]")
        return True

    def _show_connection_settings(self) -> None:
        """Display current connection settings from options."""
        dc = self._options.get("dc", "?")
        domain = self._options.get("domain", "?")
        username = self._options.get("username", "?")
        ccache = str(self._options.get("ccache", "") or "")
        has_hash = bool(self._options.get("nthash"))
        has_pw = bool(self._options.get("password"))
        # A ccache forces Kerberos; an NT hash forces NTLM (pass-the-hash);
        # otherwise fall back to the configured auth_method.
        auth_method = str(self._options.get("auth_method", "") or "").lower()
        if ccache:
            auth = "kerberos (ccache)"
        elif has_hash:
            auth = "ntlm (pass-the-hash)"
        else:
            auth = auth_method or "ntlm"
        if ccache:
            import os as _os
            secret = f"[cyan]{_os.path.basename(ccache)} (Kerberos ccache)[/cyan]"
        elif has_hash:
            secret = "[cyan]******** (NT hash)[/cyan]"
        elif has_pw:
            secret = "[cyan]******** (password)[/cyan]"
        else:
            secret = "[yellow]not set[/yellow]"
        # Always show auto-detect as the method — the actual negotiation
        # handles the protocol selection silently
        method = "Auto-detect (LDAPS → StartTLS → plaintext)"

        identity = f"{username}@{domain} [dim](from options)[/dim]"

        console.print(
            f"\n[bold]Connection Settings:[/bold]\n"
            f"  Identity: [cyan]{identity}[/cyan]\n"
            f"  DC:       [cyan]{dc}[/cyan]\n"
            f"  Domain:   [cyan]{domain}[/cyan]\n"
            f"  Auth:     [cyan]{auth}[/cyan]\n"
            f"  Method:   [cyan]{method}[/cyan]\n"
            f"  Secret:   {secret}"
        )

    def _prompt_ldap_connection(self) -> dict[str, Any] | None:
        """Show connection settings, then prompt: Enter=run, e=edit, Ctrl+C=cancel.

        Returns the LDAP opts dict to proceed, or None if cancelled.
        """
        while True:
            self._show_connection_settings()

            current_auth = str(self._options.get("auth_method", "simple")).lower()
            try:
                current_port = int(self._options.get("port", 389) or 389)
            except (ValueError, TypeError):
                current_port = 389

            console.print(
                "\n  [bold][Enter][/bold] run  ·  [bold]e[/bold] edit  ·  "
                "[bold]Ctrl+C[/bold] cancel"
            )
            try:
                choice = input("  > ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                console.print("\n[yellow]Cancelled.[/yellow]")
                return None

            if choice in ("e", "edit"):
                console.print(
                    "\n[bold]Edit settings:[/bold] [dim]type key=value to set · "
                    "'done' or Enter to finish · Ctrl+C to cancel[/dim]"
                )
                self._handle_options([])  # show current options table
                console.print()
                while True:
                    try:
                        line = input("  options (Enter = done)> ").strip()
                    except (EOFError, KeyboardInterrupt):
                        console.print()
                        break
                    if not line or line.lower() in ("done", "back", "b", "exit", "q"):
                        break
                    self._handle_options(line.split())
                self.history.save_options(self._options)
                console.print("[dim]  Settings saved.[/dim]")
                continue  # re-show settings + prompt

            if choice == "":
                return {
                    "port": current_port,
                    "use_ssl": False,
                    "use_start_tls": False,
                    "auth_method": current_auth,
                    "auto_negotiate": True,
                }

            console.print(
                f"  [dim]Unrecognized: {choice!r} — Enter to run, e to edit, "
                f"Ctrl+C to cancel[/dim]"
            )

    def _auto_detect_domain(self, dc: str) -> str:
        """Try to auto-detect domain FQDN from DC via LDAP RootDSE query."""
        try:
            import ldap3
            server = ldap3.Server(dc, get_info=ldap3.DSA)
            conn = ldap3.Connection(server, auto_bind=True)
            if server.info and server.info.other:
                default_nc = server.info.other.get("defaultNamingContext", [None])[0]
                # Convert DN to FQDN: DC=corp,DC=local → corp.local
                if default_nc:
                    parts = [p.split("=")[1] for p in default_nc.split(",") if p.startswith("DC=")]
                    if parts:
                        return ".".join(parts)
            conn.unbind()
        except Exception:
            pass
        return ""

    def _prompt_domain(self, dc: str, current_domain: str) -> str:
        """Interactive domain prompt with autodetect support.

        Shows current value (if any), allows '.' for autodetect, Enter to
        accept, or typing a new value — loops until confirmed.
        """
        domain = current_domain
        while True:
            if domain:
                hint = f"  Domain (Enter to accept '{domain}', '.' to auto-detect, or type new)"
            else:
                hint = "  Domain (enter '.' to auto-detect from DC, or type domain)"
            try:
                answer = self._ask(hint)
            except (EOFError, KeyboardInterrupt):
                console.print()
                return domain or ""

            if answer == "":
                # Accept current value
                if domain:
                    return domain
                # Nothing set yet — nudge
                console.print("  [yellow]No domain set. Enter a domain or '.' to auto-detect.[/yellow]")
                continue
            elif answer == ".":
                if not dc:
                    console.print("  [red]Cannot auto-detect: no DC host set. Set with: options dc=<host>[/red]")
                    continue
                console.print(f"  [dim]Auto-detecting domain from {dc}...[/dim]")
                detected = self._auto_detect_domain(dc)
                if detected:
                    domain = detected
                    console.print(f"  [green]Detected: {domain}[/green]")
                    # Loop back so user can accept, re-detect, or override
                    continue
                else:
                    console.print("  [red]Auto-detection failed. Enter the domain manually.[/red]")
                    continue
            else:
                domain = answer
                return domain

    def _default_output_path(self, subdir: str, filename: str) -> str:
        """Default output location for reports/exports: <base_dir>/<subdir>/<file>.

        Reports default to ./reports and exports to ./exports (relative to the
        project base_dir, or the cwd when no config is loaded). Creates the
        directory. Used only when the operator did not pass an explicit -o path.
        """
        base_dir = "."
        cfg = getattr(self, "config", None)
        if cfg is not None:
            try:
                base_dir = cfg.paths.get("base_dir", ".") or "."
            except Exception:
                base_dir = "."
        base = Path(base_dir).expanduser()
        # A relative base_dir must be pinned to a fixed location, otherwise it
        # tracks whatever directory the process happens to be in.
        if not base.is_absolute():
            base = base.resolve()
        d = base / subdir
        try:
            d.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass
        return str(d / filename)

    def _prompt_export_path(self, default_path: str) -> str | None:
        """Prompt the user to confirm or change an export file path.

        Shows the default path and lets the operator press Enter to accept
        or type a new path.  Returns the chosen path, or None if cancelled.
        """
        resolved = str(Path(default_path).resolve())
        try:
            answer = input(
                f"\n  Export to: {resolved}\n"
                f"  Press Enter to confirm, type a new path, or 'c' to cancel: "
            ).strip()
        except (EOFError, KeyboardInterrupt):
            console.print()
            return None
        if answer.lower() in ("c", "cancel"):
            console.print("[yellow]Export cancelled.[/yellow]")
            return None
        # Return the resolved absolute path so callers' "Exported to: …" shows
        # the full path + filename (matching the prompt above).
        if answer:
            return str(Path(answer).resolve())
        return resolved

    def _connection_dict(self) -> dict[str, str]:
        """Build a string-valued connection dict for template interpolation.

        Adds shell-safe password quoting for command templates.
        """
        import shlex
        d = {k: str(v) for k, v in self._options.items() if v}
        # Auto-derive base_dn from domain if not explicitly set
        if not d.get("base_dn") and d.get("domain"):
            d["base_dn"] = ",".join(f"DC={p}" for p in d["domain"].split("."))
        # Default target_host to dc if not set
        if not d.get("target_host") and d.get("dc"):
            d["target_host"] = d["dc"]
        # Auto-derive dc_fqdn from dc + domain if not explicitly set
        if not d.get("dc_fqdn") and d.get("dc") and d.get("domain"):
            d["dc_fqdn"] = self._resolve_dc_fqdn(d["dc"], d["domain"])
        # Kerberos SPNs are host-based (ldap/<fqdn>, cifs/<fqdn>), so a ccache
        # bind must target the DC by FQDN, not IP. Prefer the resolved FQDN, and
        # make sure krb5 can locate the KDC for the realm.
        if d.get("ccache"):
            kdc = d.get("dc")  # raw DC IP/host, before the FQDN override below
            if d.get("dc_fqdn"):
                d["dc"] = d["dc_fqdn"]
            elif d.get("dc"):
                console.print(
                    "[yellow]Kerberos needs the DC FQDN (for the SPN); could not "
                    "resolve one from "
                    f"{d['dc']}. Set 'options dc=<dc-fqdn>'.[/yellow]")
            if d.get("domain") and kdc:
                self._ensure_krb5_config(d["domain"], kdc)
        return d

    def _effective_auth_label(self, auth_method: str) -> str:
        """Human label for the auth actually used: a ccache means Kerberos and
        an nthash means pass-the-hash, regardless of the stored auth_method."""
        if self._options.get("ccache"):
            return "kerberos"
        if self._options.get("nthash"):
            return "ntlm (pass-the-hash)"
        return auth_method or "ntlm"

    def _ensure_krb5_config(self, realm: str, kdc: str) -> None:
        """Point krb5 at the target realm's KDC when using a ccache.

        GSSAPI needs to reach the KDC to obtain a service ticket for the LDAP
        SPN — a valid TGT alone is not enough. When the operator has not set
        KRB5_CONFIG themselves, generate a minimal config in the project folder
        mapping the realm to the DC and export KRB5_CONFIG (this overrides
        /etc/krb5.conf without touching system files). Idempotent per session.
        """
        if os.environ.get("KRB5_CONFIG") and not getattr(self, "_krb5_generated", False):
            return  # respect an explicit operator-provided KRB5_CONFIG
        realm_up = realm.upper()
        realm_lo = realm.lower()
        content = (
            "[libdefaults]\n"
            f"    default_realm = {realm_up}\n"
            "    dns_lookup_kdc = false\n"
            "    dns_lookup_realm = false\n"
            "    rdns = false\n\n"
            "[realms]\n"
            f"    {realm_up} = {{\n"
            f"        kdc = {kdc}\n"
            f"        admin_server = {kdc}\n"
            "    }\n\n"
            "[domain_realm]\n"
            f"    .{realm_lo} = {realm_up}\n"
            f"    {realm_lo} = {realm_up}\n"
        )
        try:
            path = self._project_base() / "krb5.conf"
            if not (path.exists() and path.read_text() == content):
                path.write_text(content)
                console.print(f"[dim]  Generated krb5.conf for {realm_up} "
                              f"(kdc {kdc}) → {path}[/dim]")
            os.environ["KRB5_CONFIG"] = str(path)
            self._krb5_generated = True
        except OSError as exc:
            console.print(f"[yellow]Could not write krb5.conf: {exc}. "
                          f"Set KRB5_CONFIG or /etc/krb5.conf manually.[/yellow]")

    def _resolve_dc_fqdn(self, dc_ip: str, domain: str) -> str:
        """Resolve the DC IP to an FQDN, prompting the operator if needed.

        1. Try reverse DNS on the DC IP.
        2. If that fails, try common DC names (DC01.<domain>, etc.).
        3. If nothing resolves, prompt the operator for the FQDN.
        4. If the chosen FQDN doesn't resolve, offer to add a /etc/hosts entry.

        The result is cached in self._options['dc_fqdn'] so this only runs once.
        """
        import socket
        import subprocess

        # Already cached?
        cached = str(self._options.get("dc_fqdn", "")).strip()
        if cached:
            return cached

        fqdn = ""

        # 1. Try reverse DNS
        try:
            hostname, _, _ = socket.gethostbyaddr(dc_ip)
            if "." in hostname:
                fqdn = hostname
            elif domain:
                fqdn = f"{hostname}.{domain}"
        except (socket.herror, socket.gaierror):
            pass

        # 2. Try common DC naming conventions
        if not fqdn:
            for prefix in ["DC01", "DC1", "DC", "WIN-DC", "AD01", "AD1"]:
                candidate = f"{prefix}.{domain}"
                try:
                    socket.gethostbyname(candidate)
                    fqdn = candidate
                    break
                except socket.gaierror:
                    continue

        # 3. Prompt operator
        if fqdn:
            console.print(f"  [dim]DC FQDN resolved: {fqdn}[/dim]")
            answer = _timed_prompt(f"DC FQDN [{fqdn}]", default=fqdn)
            fqdn = answer or fqdn
        else:
            console.print(f"  [yellow]Could not resolve FQDN for DC {dc_ip}[/yellow]")
            try:
                fqdn = input(f"  Enter DC FQDN (e.g. DC01.{domain}): ").strip()
            except (EOFError, KeyboardInterrupt):
                fqdn = f"DC01.{domain}"
            if not fqdn:
                fqdn = f"DC01.{domain}"

        # 4. Check if the FQDN resolves — if not, offer to add hosts entry
        try:
            socket.gethostbyname(fqdn)
        except socket.gaierror:
            console.print(f"  [yellow]{fqdn} does not resolve in DNS.[/yellow]")
            add_hosts = _timed_prompt(
                f"Add '{dc_ip} {fqdn}' to /etc/hosts? [y]es / [n]o",
                default="y",
            ).lower()
            if add_hosts in ("y", "yes", ""):
                try:
                    # Check if entry already exists
                    with open("/etc/hosts", "r") as f:
                        hosts_content = f.read()
                    if fqdn not in hosts_content:
                        entry = f"{dc_ip} {fqdn}\n"
                        console.print(f"  [dim]Adding: {dc_ip} {fqdn}[/dim]")
                        subprocess.run(
                            ["sudo", "tee", "-a", "/etc/hosts"],
                            input=entry.encode(),
                            stdout=subprocess.DEVNULL,
                            check=True,
                        )
                        console.print(f"  [green]Added {fqdn} → {dc_ip} to /etc/hosts[/green]")
                    else:
                        console.print(f"  [dim]{fqdn} already in /etc/hosts[/dim]")
                except Exception as e:
                    console.print(f"  [red]Failed to update /etc/hosts: {e}[/red]")

        # Cache it
        self._options["dc_fqdn"] = fqdn
        return fqdn

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _show_menu_help(self, commands: list[tuple[str, str, str]], title: str,
                        groups: list[tuple[str, list[str]]] | None = None,
                        show_args: bool = True, hint: str | None = None,
                        subtrees: dict[str, list[tuple[str, str, str]]] | None = None
                        ) -> None:
        from rich.console import Group

        # A real table keeps columns aligned no matter how long an arg-hint is:
        # an over-long hint wraps *within* its column instead of shoving the
        # description column out of line. Cells are Text() so bracketed hints
        # (e.g. "[key=value ...]") render literally, not as Rich markup.
        table = Table(box=None, show_header=False, pad_edge=False,
                      padding=(0, 2), expand=False)
        table.add_column("cmd", style="bold", no_wrap=True)
        if show_args:
            table.add_column("args", overflow="fold", max_width=40)
        table.add_column("desc", overflow="fold")

        def _name_cell(name: str, indent: int = 2) -> Text:
            return Text(f"{' ' * indent}{name}", style="bold")

        def _add(entry: tuple[str, str, str], indent: int = 2) -> None:
            name, args_hint, desc = entry
            if show_args:
                table.add_row(_name_cell(name, indent), Text(args_hint), Text(desc))
            else:
                table.add_row(_name_cell(name, indent), Text(desc))

        def _add_subtree(name: str) -> None:
            for sn, _sa, sd in (subtrees.get(name) if subtrees else None) or []:
                # subtrees are only used by the no-args (main) view
                table.add_row(_name_cell(sn, indent=6), Text(sd))

        def _header(text: str) -> None:
            cell = Text.from_markup(f"[bold cyan]{text}[/bold cyan]")
            table.add_row(cell, Text(""), Text("")) if show_args else \
                table.add_row(cell, Text(""))

        def _spacer() -> None:
            table.add_row("", "", "") if show_args else table.add_row("", "")

        if groups:
            by_name = {c[0]: c for c in commands}
            used: set[str] = set()
            for i, (header, names) in enumerate(groups):
                if i:
                    _spacer()
                _header(header)
                for n in names:
                    if n in by_name:
                        _add(by_name[n])
                        _add_subtree(n)
                        used.add(n)
            leftover = [c for c in commands if c[0] not in used]
            if leftover:
                _spacer()
                _header("General")
                for c in leftover:
                    _add(c)
                    _add_subtree(c[0])
        else:
            for c in commands:
                _add(c)
                _add_subtree(c[0])

        body: list = []
        if hint:
            body.append(Text(hint, style="dim"))
            body.append(Text(""))
        body.append(table)

        console.print(Panel(
            Group(*body),
            title=f"[bold cyan]{title}[/bold cyan]",
            border_style="cyan",
        ))

    def _init_readline(self) -> None:
        try:
            if self._history_path.exists():
                readline.read_history_file(str(self._history_path))
        except Exception:
            pass
        readline.set_history_length(5000)
        readline.set_completer(self._completer)
        readline.set_completer_delims(" \t\n")
        self._saved_termios = None
        # Support both GNU readline and libedit (macOS). The flat menu has no
        # submenu navigation, so the old Ctrl+B/Ctrl+S shortcuts are gone.
        if "libedit" in (readline.__doc__ or ""):
            readline.parse_and_bind("bind ^I rl_complete")
        else:
            readline.parse_and_bind("tab: complete")

    def _save_readline(self) -> None:
        # Restore terminal flow-control settings changed in _init_readline.
        if getattr(self, "_saved_termios", None) is not None:
            try:
                import termios
                termios.tcsetattr(sys.stdin.fileno(), termios.TCSANOW,
                                  self._saved_termios)
            except Exception:
                pass
        try:
            readline.write_history_file(str(self._history_path))
        except Exception:
            pass

    def _completer(self, text: str, state: int) -> str | None:
        try:
            if state == 0:
                line = readline.get_line_buffer().lstrip()
                parts = line.split()
                first_word = len(parts) <= 1 and not line.endswith(" ")
                if first_word:
                    pool = sorted(WORKFLOW_VERBS | GLOBAL_CMDS)
                    self._completion_matches = [c for c in pool if c.startswith(text)]
                else:
                    verb, _ = _resolve_prefix(parts[0].lower(), WORKFLOW_VERBS)
                    on_second = ((len(parts) == 1 and line.endswith(" ")) or
                                 (len(parts) == 2 and not line.endswith(" ")))
                    if verb and on_second and VERB_SUBCOMMANDS.get(verb):
                        subs = sorted(VERB_SUBCOMMANDS[verb])
                        self._completion_matches = [s for s in subs if s.startswith(text)]
                    elif verb:
                        sub = parts[1].lower() if len(parts) >= 2 else ""
                        self._completion_matches = self._complete_arguments(verb, sub, text)
                    else:
                        self._completion_matches = []
            return self._completion_matches[state] if state < len(self._completion_matches) else None
        except Exception:
            return None

    def _complete_arguments(self, verb: str, sub: str, text: str) -> list[str]:
        """Complete flag values / IDs for a verb's arguments. ``sub`` is the
        subcommand token (or a flag/empty when the bare verb runs)."""
        completions: list[str] = []
        line = readline.get_line_buffer().lstrip()
        parts = line.split()
        is_run = sub == "run"                        # 'run' flag completion
        prev = (parts[-1] if parts else "") if line.endswith(" ") else (
            parts[-2] if len(parts) >= 2 else "")

        if verb == "report":
            if prev == "--type":
                completions = ["analyze", "scan"]
            elif prev == "--format":
                completions = ["html", "pdf", "markdown"]
            elif prev == "--style":
                completions = ["1", "2", "3", "4", "5"]
            elif text.startswith("-"):
                completions = ["--type", "--format", "--style", "-o"]

        elif verb == "collect":
            if sub in ("load", "delete"):
                try:
                    ids = [c.collection_id for c in self._finder_history.list_collections()]
                    completions = [i for i in ids if i.startswith(text)]
                except Exception:
                    pass
            elif sub in ("import", "azure"):
                completions = self._complete_filepath(text)

        elif verb == "scan":
            if sub in ("show", "delete", "export", "diff"):
                try:
                    ids = [s.scan_id for s in self._finder_history.list_scans()]
                    main_scans = self.history.list_scans()
                    ids.extend(s.get("scan_id", "") for s in main_scans if s.get("scan_id"))
                    completions = [i for i in ids if i.startswith(text)]
                except Exception:
                    pass
            elif is_run:
                flags = ["--category", "--check", "--exclude", "--no-collection"]
                completions = [f for f in flags if f.startswith(text)]

        elif verb == "search":
            if self._collection_data and sub in (
                "info", "members", "memberof", "acl", "who-can", "spns",
            ):
                try:
                    if not getattr(self, "_query_index", None):
                        from lazyhound.finder.collect.analyzer import CollectionIndex
                        self._query_index = CollectionIndex(self._collection_data)
                    idx = self._query_index
                    names = sorted(idx._by_name.keys()) if hasattr(idx, "_by_name") else []
                    completions = [n for n in names if n.lower().startswith(text.lower())][:20]
                except Exception:
                    pass

        elif verb == "analyze":
            if sub == "paths":
                if prev == "--category":
                    from lazyhound.finder.collect.analyzer import Category
                    completions = [c.slug for c in Category if c.slug.startswith(text.lower())]
                elif prev == "--severity":
                    completions = [s for s in ["critical", "high", "medium", "low", "info"]
                                   if s.startswith(text.lower())]
                elif text.startswith("-") or text == "":
                    flags = ["--category", "--severity", "--top", "--show", "--show-inherited"]
                    completions = [f for f in flags if f.startswith(text)]
            elif sub == "export":
                if prev == "--format":
                    completions = [f for f in ["json", "csv", "ascii", "mermaid", "dot", "svg", "png"]
                                   if f.startswith(text.lower())]
                elif prev == "--type":
                    from lazyhound.finder.reports.visualize.extract import KINDS
                    completions = [k for k in KINDS if k.startswith(text.lower())]
                elif prev == "-o":
                    completions = self._complete_filepath(text)
                elif text.startswith("-") or text == "":
                    completions = [f for f in ["--format", "--type", "--from", "--to", "-o"]
                                   if f.startswith(text)]
            elif is_run:
                if prev == "--category":
                    from lazyhound.finder.collect.analyzer import _CHECK_CATEGORIES
                    tags = sorted(set(_CHECK_CATEGORIES.values()))
                    completions = [t for t in tags if t.startswith(text.lower())]
                elif text.startswith("-") or text == "":
                    flags = ["--category", "--checks", "--exclude", "--owned", "--notier0",
                             "--prune", "--aggregate", "--noexpand", "--expand-cap"]
                    completions = [f for f in flags if f.startswith(text)]

        if not completions and text.startswith("-"):
            completions = [f for f in ["--help"] if f.startswith(text)]
        return completions

    @staticmethod
    def _complete_filepath(text: str) -> list[str]:
        """Basic file path completion."""
        import glob
        if not text:
            text = "./"
        pattern = text + "*"
        matches = glob.glob(pattern)
        result = []
        for m in matches:
            if os.path.isdir(m):
                result.append(m + "/")
            else:
                result.append(m)
        return result
