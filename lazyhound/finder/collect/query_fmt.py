"""Rich console formatters for query results."""

from __future__ import annotations

import json
import sys
from typing import Callable

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.tree import Tree

from .analyzer import _acl_edge_labels
from .query import CollectionIndex, _resolve_name, _domain_sid_of


def _row_domain_label(row: dict, idx) -> str:
    """Short domain label (NetBIOS, else label) for a result row, reading
    whichever SID key it uses. '' when not resolvable / idx missing."""
    if idx is None or not isinstance(row, dict):
        return ""
    sid = (row.get("object_sid") or row.get("sid")
           or row.get("principal_sid") or "")
    d = idx.resolve_domain(_domain_sid_of(sid)) if sid else None
    return (d.netbios or d.label) if d else ""

console = Console()

# Default page size for unbounded query results
DEFAULT_TOP = 50


def _interactive_pager(
    items: list,
    render_page: Callable[[list, int], None],
    top: int | None = None,
    skip: int = 0,
) -> None:
    """Page through *items* interactively.

    *render_page(page_items, start_index)* is called for each page to
    print the output.  After each page the user is prompted to continue.

    ``top=0`` disables paging and renders everything at once.
    ``top=None`` uses the default page size (DEFAULT_TOP).
    """
    total = len(items)
    if not items:
        render_page([], 0)
        return

    page_size = top if top is not None else DEFAULT_TOP
    if page_size <= 0:
        # --top 0 means "show all"
        render_page(items, 0)
        return

    # When skip is provided but items fit in one page from offset 0, skip paging
    if total <= page_size and skip == 0:
        render_page(items, 0)
        return

    offset = skip
    while True:
        page = items[offset : offset + page_size]
        if not page:
            break

        render_page(page, offset)

        start = offset + 1
        end = min(offset + page_size, total)
        on_first = offset == 0
        on_last = end >= total

        if on_first and on_last:
            # Entire result fits on this page (e.g. skip jumped to end)
            break

        # Build prompt options
        opts: list[str] = []
        if not on_first:
            opts.append("[bold][p][/bold] previous")
        if not on_last:
            opts.append("[bold][n/Enter][/bold] next")
        opts.append("[bold][q][/bold] quit")
        prompt = f"[dim]Showing {start}\u2013{end} of {total:,}.[/dim]  {' | '.join(opts)}: "
        console.print(prompt, end="")

        try:
            choice = input().strip().lower()
        except (KeyboardInterrupt, EOFError):
            console.print()
            break

        if choice in ("q", "quit"):
            break
        elif choice in ("p", "prev", "previous"):
            offset = max(0, offset - page_size)
        else:
            # n, next, Enter (empty), or anything else → next page
            if on_last:
                break
            offset = end


# ---------------------------------------------------------------------------
# JSON output helper
# ---------------------------------------------------------------------------
def _dump_json(obj: object) -> None:
    json.dump(obj, sys.stdout, indent=2, default=str)
    sys.stdout.write("\n")


# ---------------------------------------------------------------------------
# info
# ---------------------------------------------------------------------------
def _section(lines: list[str], heading: str) -> None:
    """Append a section heading separator."""
    lines.append("")
    lines.append(f"[bold underline]{heading}[/]")


def _field(lines: list[str], label: str, value: object, width: int = 18) -> None:
    """Append a key-value line, skipping empty/None values."""
    if value is None or value == "" or value == []:
        return
    padded = f"{label}:"
    lines.append(f"[bold]{padded:<{width}}[/] {value}")


def print_info_result(info: dict, as_json: bool = False) -> None:
    if as_json:
        _dump_json(info)
        return

    cls = info.get("object_class", "")
    title = f"{info['name']}  ({cls})"

    lines: list[str] = []

    # -- Identity section (all object types) -----------------------------------
    _section(lines, "Identity")
    # sAMAccountName is relevant for users, computers, groups — not OUs/GPOs
    if cls in ("user", "computer", "group", "gmsa"):
        _field(lines, "sAMAccountName", info.get("sam_account_name"))
    if cls == "user":
        _field(lines, "Display Name", info.get("display_name"))
        _field(lines, "UPN", info.get("user_principal_name"))
    if cls.startswith(("aad_", "azure_")):
        _field(lines, "Object ID", info.get("object_sid"))
    else:
        _field(lines, "DN", info.get("dn"))
        _field(lines, "SID", info.get("object_sid"))
    _field(lines, "Class", cls)
    wc = info.get("when_created", "")
    if wc and wc != "never":
        _field(lines, "Created", wc)
    owner = info.get("owner", "")
    owner_sid = info.get("owner_sid", "")
    if owner:
        _field(lines, "Owner", owner)
        if owner_sid:
            lines.append(f"{'':>19} [dim]({owner_sid})[/]")

    # -- User directory info ---------------------------------------------------
    if cls == "user":
        has_dir_info = any(info.get(k) for k in ("mail", "title", "department", "manager"))
        if has_dir_info:
            _section(lines, "Directory")
            _field(lines, "Email", info.get("mail"))
            _field(lines, "Title", info.get("title"))
            _field(lines, "Department", info.get("department"))
            _field(lines, "Manager", info.get("manager"))

    # -- Account status (user / computer) --------------------------------------
    if cls in ("user", "computer"):
        _section(lines, "Account Status")
        enabled = info.get("enabled", True)
        status = "[green]Enabled[/]" if enabled else "[red]Disabled[/]"
        _field(lines, "Status", status)
        _field(lines, "UAC Flags", ", ".join(info.get("uac_flags", [])) or "none")
        _field(lines, "adminCount", info.get("admin_count", 0))
        desc = info.get("description", "")
        if desc:
            _field(lines, "Description", desc)

    # -- Password & Logon (user / computer) ------------------------------------
    if cls in ("user", "computer"):
        _section(lines, "Password & Logon")
        pwd_set = info.get("pwd_last_set", "N/A")
        pwd_age = info.get("pwd_age_days", "?")
        _field(lines, "pwdLastSet", f"{pwd_set}  ({pwd_age} days ago)")
        last_logon = info.get("last_logon", "")
        last_logon_days = info.get("last_logon_days")
        if last_logon and last_logon != "never":
            _field(lines, "lastLogon", f"{last_logon}  ({last_logon_days} days ago)")
        elif last_logon == "never" or not last_logon:
            _field(lines, "lastLogon", "[dim]never[/]")
        if cls == "user":
            _field(lines, "Logon Count", info.get("logon_count"))
            acct_exp = info.get("account_expires", "")
            if acct_exp:
                _field(lines, "Account Expires", acct_exp)

    # -- Kerberos & Delegation -------------------------------------------------
    if cls in ("user", "computer"):
        enc = info.get("supported_enc_types", [])
        spns = info.get("spns", [])
        dt = info.get("delegation_targets", [])
        rbcd = info.get("rbcd_configured", False)
        sh = info.get("sid_history", [])
        has_kerb = enc or spns or dt or rbcd or sh

        if has_kerb:
            _section(lines, "Kerberos & Delegation")
            if enc:
                _field(lines, "Enc Types", ", ".join(enc))
            if spns:
                lines.append(f"[bold]{'SPNs:':<18}[/] {len(spns)}")
                for s in spns:
                    lines.append(f"{'':>19} {s}")
            if dt:
                lines.append(f"[bold]{'Constrained To:':<18}[/]")
                for t in dt:
                    lines.append(f"{'':>19} {t}")
            if rbcd:
                lines.append(f"[bold red]{'RBCD:':<18}[/] Configured")
            if sh:
                _field(lines, "SID History", ", ".join(str(s) for s in sh))

    # -- Computer-specific fields ----------------------------------------------
    if cls == "computer":
        _section(lines, "System Info")
        os_str = info.get("os", "")
        os_ver = info.get("os_version", "")
        os_sp = info.get("os_service_pack", "")
        os_full = os_str
        if os_ver:
            os_full += f" {os_ver}"
        if os_sp:
            os_full += f" ({os_sp})"
        _field(lines, "OS", os_full)
        _field(lines, "DNS Hostname", info.get("dns_hostname"))
        _field(lines, "Managed By", info.get("managed_by"))

    # -- Group-specific fields -------------------------------------------------
    if cls == "group":
        _section(lines, "Group Details")
        _field(lines, "Type", f"{info.get('group_type', '')} / {info.get('group_scope', '')}")
        _field(lines, "Direct Members", info.get("direct_member_count", 0))
        _field(lines, "adminCount", info.get("admin_count", 0))
        _field(lines, "Managed By", info.get("managed_by"))
        _field(lines, "Email", info.get("mail"))
        desc = info.get("description", "")
        if desc:
            _field(lines, "Description", desc)

    # -- OU --------------------------------------------------------------------
    if cls == "ou":
        desc = info.get("description", "")
        if desc:
            _field(lines, "Description", desc)
        gpl = info.get("gp_link", "")
        if gpl:
            _field(lines, "GPLink", gpl)

    # -- GPO -------------------------------------------------------------------
    if cls == "gpo":
        _field(lines, "SysVol Path", info.get("gpc_path"))

    # -- Trust -----------------------------------------------------------------
    if cls == "trusteddomain":
        _section(lines, "Trust Details")
        _field(lines, "Direction", info.get("trust_direction"))
        _field(lines, "Type", info.get("trust_type"))
        _field(lines, "Flat Name", info.get("flat_name"))
        _field(lines, "Attributes", info.get("trust_attributes"))

    # -- Certificate Template --------------------------------------------------
    if cls == "certtemplate":
        _section(lines, "Certificate Template")
        _field(lines, "Display Name", info.get("display_name"))
        _field(lines, "Schema Version", info.get("schema_version"))
        _field(lines, "Name Flag", info.get("name_flag"))
        _field(lines, "Enrollment Flag", info.get("enrollment_flag"))
        _field(lines, "RA Signature", info.get("ra_signature"))
        eku = info.get("eku", [])
        if eku:
            _field(lines, "EKU", ", ".join(str(e) for e in eku))
        app_policy = info.get("app_policy", [])
        if app_policy:
            _field(lines, "App Policy", ", ".join(str(p) for p in app_policy))

    # -- gMSA ------------------------------------------------------------------
    if cls == "gmsa":
        _section(lines, "gMSA Details")
        _field(lines, "Display Name", info.get("display_name"))
        enabled = info.get("enabled", True)
        status = "[green]Enabled[/]" if enabled else "[red]Disabled[/]"
        _field(lines, "Status", status)
        _field(lines, "UAC Flags", ", ".join(info.get("uac_flags", [])) or "none")
        _field(lines, "adminCount", info.get("admin_count", 0))
        _field(lines, "Description", info.get("description"))
        _field(lines, "Pwd Interval", f"{info.get('password_interval', '?')} days")
        if info.get("gmsa_membership_configured"):
            lines.append(f"[bold yellow]{'gMSA Readers:':<18}[/] Configured (use 'acl' command for details)")
        spns = info.get("spns", [])
        if spns:
            lines.append(f"[bold]{'SPNs:':<18}[/] {len(spns)}")
            for s in spns:
                lines.append(f"{'':>19} {s}")

    # -- PKI Enrollment Service ------------------------------------------------
    if cls == "pki":
        _section(lines, "PKI Enrollment Service")
        _field(lines, "Display Name", info.get("display_name"))
        _field(lines, "DNS Hostname", info.get("dns_hostname"))
        _field(lines, "Flags", info.get("flags"))
        templates = info.get("certificate_templates", [])
        if templates:
            lines.append(f"[bold]{'Templates:':<18}[/] {len(templates)}")
            for t in templates:
                lines.append(f"{'':>19} {t}")

    # -- OID Object ------------------------------------------------------------
    if cls == "oidobject":
        _section(lines, "OID Object")
        _field(lines, "Display Name", info.get("display_name"))
        _field(lines, "Template OID", info.get("cert_template_oid"))
        _field(lines, "Group Link", info.get("oid_group_link"))

    # -- Entra / Azure object details ------------------------------------------
    if cls.startswith(("aad_", "azure_")):
        _section(lines, "Entra / Azure")
        _field(lines, "Display Name", info.get("display_name"))
        if cls == "aad_user":
            _field(lines, "UPN", info.get("user_principal_name"))
            if info.get("mail"):
                _field(lines, "Email", info.get("mail"))
            enabled = info.get("enabled", True)
            _field(lines, "Status", "[green]Enabled[/]" if enabled else "[red]Disabled[/]")
            if info.get("user_type"):
                _field(lines, "User Type", info.get("user_type"))
            if info.get("on_prem_sync"):
                syn = "[yellow]Yes[/]"
                if info.get("on_prem_sid"):
                    syn += f"  [dim]({info['on_prem_sid']})[/]"
                _field(lines, "Synced from AD", syn)
        elif cls == "aad_group":
            _field(lines, "Security Enabled", info.get("security_enabled"))
            if info.get("mail"):
                _field(lines, "Email", info.get("mail"))
        elif cls == "aad_sp":
            _field(lines, "SP Type", info.get("service_principal_type"))
            _field(lines, "App ID", info.get("app_id"))
        elif cls == "aad_app":
            _field(lines, "App ID", info.get("app_id"))
        _field(lines, "Tenant", info.get("tenant_name") or info.get("tenant_id"))

        # Directory roles + other Entra relationships (from Azure edges)
        edges = info.get("azure_edges", [])
        roles = [e for e in edges if e.get("direction") == "outbound"
                 and "hasrole" in (e.get("type", "") or "").lower()]
        rels = [e for e in edges if e not in roles]
        if roles:
            _section(lines, f"Directory Roles ({len(roles)})")
            for e in roles:
                t = e.get("type", "")
                detail = t.split(": ", 1)[1] if ": " in t else t
                scope = e.get("peer_name") or e.get("peer_id", "")
                scope = "tenant-wide" if scope in ("/", "") else scope
                lines.append(f"  [bold red]{detail}[/]  [dim]({scope})[/]")
        if rels:
            from lazyhound.finder.reports.visualize.model import humanize_edge
            _section(lines, f"Entra Relationships ({len(rels)})")
            for e in rels:
                phrase = humanize_edge(e.get("type", "")) or e.get("type", "")
                peer = e.get("peer_name") or e.get("peer_id", "")
                arrow = "→" if e.get("direction") == "outbound" else "←"
                lines.append(f"  {arrow} {phrase}  [dim]{peer}[/]")

    # -- Group memberships (all types) -----------------------------------------
    groups = info.get("member_of", [])
    if groups:
        _section(lines, f"Member Of ({len(groups)} groups)")
        for g in groups:
            lines.append(f"  {g['name']}  [dim]({g['sid']})[/]")

    # -- DACL summary (AD objects only; Azure objects have no DACL) -------------
    if not cls.startswith(("aad_", "azure_")):
        lines.append("")
        lines.append(f"[dim]DACL entries: {info.get('dacl_entry_count', 0)}[/]")

    console.print(Panel("\n".join(lines), title=title, border_style="cyan"))


# ---------------------------------------------------------------------------
# resolve
# ---------------------------------------------------------------------------
def print_resolve_result(sid: str, name: str, as_json: bool = False) -> None:
    if as_json:
        _dump_json({"sid": sid, "name": name})
        return
    console.print(f"[bold]SID:[/]  {sid or '[dim]not found[/]'}")
    console.print(f"[bold]Name:[/] {name}")


# ---------------------------------------------------------------------------
# members / memberof
# ---------------------------------------------------------------------------
def print_object_list(
    objects: list[dict],
    title: str,
    idx: CollectionIndex,
    as_json: bool = False,
    show_details: bool = False,
    top: int | None = None,
    skip: int = 0,
    domain_col: bool = False,
) -> None:
    # `domain_col` renders a per-row Domain column for --domain all (Task 7);
    # accepted here so callers can pass it uniformly.
    if as_json:
        rows = []
        for obj in objects:
            row = {
                "name": obj.get("name", ""),
                "sid": obj.get("object_sid", ""),
                "class": obj.get("object_class", ""),
                "dn": obj.get("dn", ""),
            }
            if show_details:
                props = obj.get("properties", {})
                row["enabled"] = not bool(_get_uac_safe(obj) & 0x0002)
                row["description"] = props.get("description", "")
            rows.append(row)
        _dump_json({"title": title, "count": len(rows), "results": rows})
        return

    if not objects:
        console.print(f"[dim]{title}: no results[/]")
        return

    total = len(objects)

    def _domain_label(obj: dict) -> str:
        dsid = obj.get("_domain") or idx.domain_of(obj)
        d = idx.resolve_domain(dsid) if dsid else None
        return d.netbios if d else ""

    def _render(page: list[dict], start: int) -> None:
        table = Table(title=f"{title} ({total})", show_lines=False, pad_edge=False)
        table.add_column("Name", style="bold", min_width=20)
        table.add_column("Class", min_width=10)
        if domain_col:
            table.add_column("Domain", min_width=10)
        table.add_column("SID", min_width=15)
        if show_details:
            table.add_column("Status", min_width=8)
            table.add_column("Description", min_width=30)
        for obj in page:
            name = obj.get("name", "")
            cls = obj.get("object_class", "")
            sid = obj.get("object_sid", "")
            prefix = (name, cls, _domain_label(obj)) if domain_col else (name, cls)
            if show_details:
                uac = _get_uac_safe(obj)
                enabled = "enabled" if not (uac & 0x0002) else "[red]disabled[/]"
                desc = obj.get("properties", {}).get("description", "") or ""
                if isinstance(desc, list):
                    desc = desc[0] if desc else ""
                table.add_row(*prefix, sid, enabled, str(desc)[:60])
            else:
                table.add_row(*prefix, sid)
        console.print(table)

    _interactive_pager(objects, _render, top=top, skip=skip)


def _get_uac_safe(obj: dict) -> int:
    raw = obj.get("properties", {}).get("userAccountControl", 0)
    try:
        return int(raw)
    except (ValueError, TypeError):
        return 0


# ---------------------------------------------------------------------------
# who-can
# ---------------------------------------------------------------------------
def print_who_can(results: list[dict], right: str, target: str, as_json: bool = False,
                   top: int | None = None, skip: int = 0) -> None:
    if as_json:
        _dump_json({"right": right, "target": target, "count": len(results), "entries": results})
        return

    if not results:
        console.print(f"[dim]No principals have {right} on {target}[/]")
        return

    total = len(results)

    def _render(page: list[dict], start: int) -> None:
        table = Table(
            title=f"Who has {right} on {target} ({total})",
            show_lines=False, pad_edge=False,
        )
        table.add_column("Trustee", style="bold", min_width=20)
        table.add_column("SID", min_width=15)
        table.add_column("Rights", min_width=15)
        table.add_column("Inherited", justify="center", min_width=3)
        for e in page:
            table.add_row(
                e.get("trustee_name", ""),
                e.get("trustee_sid", ""),
                ", ".join(e.get("rights", [])),
                "Y" if e.get("inherited") else "",
            )
        console.print(table)

    _interactive_pager(results, _render, top=top, skip=skip)


# ---------------------------------------------------------------------------
# acl
# ---------------------------------------------------------------------------
def print_acl(aces: list[dict], target: str, as_json: bool = False,
              top: int | None = None, skip: int = 0) -> None:
    if as_json:
        _dump_json({"target": target, "count": len(aces), "aces": aces})
        return

    if not aces:
        console.print(f"[dim]No access-control entries for {target}[/]")
        return

    total = len(aces)
    is_entra = any(a.get("ace_type") == "Entra" for a in aces)
    label = "Entra control over" if is_entra else "DACL for"

    def _render(page: list[dict], start: int) -> None:
        table = Table(
            title=f"{label} {target} ({total} entries)",
            show_lines=False, pad_edge=False,
        )
        table.add_column("Type", min_width=8)
        table.add_column("Trustee", style="bold", min_width=20)
        table.add_column("SID", min_width=15)
        table.add_column("Rights", min_width=15)
        table.add_column("Inh", justify="center", min_width=3)
        for ace in page:
            table.add_row(
                ace.get("ace_type", ""),
                ace.get("trustee_name", ""),
                ace.get("trustee_sid", ""),
                ", ".join(ace.get("rights", [])),
                "Y" if ace.get("inherited") else "",
            )
        console.print(table)

    _interactive_pager(aces, _render, top=top, skip=skip)


# ---------------------------------------------------------------------------
# search
# ---------------------------------------------------------------------------
def print_search_results(results: list[dict], attr: str, pattern: str, as_json: bool = False,
                          top: int | None = None, skip: int = 0) -> None:
    if as_json:
        rows = [
            {
                "name": obj.get("name", ""),
                "sid": obj.get("object_sid", ""),
                "class": obj.get("object_class", ""),
                "matched_value": _get_attr_value(obj, attr),
            }
            for obj in results
        ]
        _dump_json({"attr": attr, "pattern": pattern, "count": len(rows), "results": rows})
        return

    if not results:
        console.print(f"[dim]No objects match {attr}={pattern}[/]")
        return

    total = len(results)

    def _render(page: list[dict], start: int) -> None:
        table = Table(
            title=f"Search: {attr} matches '{pattern}' ({total})",
            show_lines=False, pad_edge=False,
        )
        table.add_column("Name", style="bold", min_width=20)
        table.add_column("Class", min_width=10)
        table.add_column("SID", min_width=15)
        table.add_column("Value", min_width=30)
        for obj in page:
            val = _get_attr_value(obj, attr)
            table.add_row(
                obj.get("name", ""),
                obj.get("object_class", ""),
                obj.get("object_sid", ""),
                str(val)[:80],
            )
        console.print(table)

    _interactive_pager(results, _render, top=top, skip=skip)


def _get_attr_value(obj: dict, attr: str) -> object:
    val = obj.get(attr)
    if val is None:
        val = obj.get("properties", {}).get(attr)
    return val


# ---------------------------------------------------------------------------
# ou-tree
# ---------------------------------------------------------------------------
def print_ou_tree(ous: list[dict], as_json: bool = False) -> None:
    if as_json:
        rows = [
            {
                "name": o.get("name", ""),
                "dn": o.get("dn", ""),
                "sid": o.get("object_sid", ""),
                "counts": o.get("_counts", {}),
            }
            for o in ous
        ]
        _dump_json({"count": len(rows), "ous": rows})
        return

    if not ous:
        console.print("[dim]No OUs found[/]")
        return

    # Build a tree based on DN hierarchy
    tree = Tree("[bold cyan]Domain[/]")
    dn_nodes: dict[str, Tree] = {}

    for ou in ous:
        dn = ou.get("dn", "")
        name = ou.get("name", dn)
        desc = ou.get("properties", {}).get("description", "")
        counts = ou.get("_counts", {})

        # Build count summary
        count_parts: list[str] = []
        for key, label in (("user", "U"), ("group", "G"), ("computer", "C")):
            n = counts.get(key, 0)
            if n:
                count_parts.append(f"{n}{label}")
        count_str = ", ".join(count_parts) if count_parts else ""

        label = f"[bold]{name}[/]"
        if count_str:
            label += f"  [cyan][{count_str}][/]"
        if desc:
            label += f"  [dim]({desc})[/]"
        label += f"\n[dim]{dn}[/]"

        # Find parent OU
        parts = dn.split(",", 1)
        parent_dn = parts[1] if len(parts) > 1 else ""

        parent_node = dn_nodes.get(parent_dn.lower())
        if parent_node:
            node = parent_node.add(label)
        else:
            node = tree.add(label)

        dn_nodes[dn.lower()] = node

    console.print(tree)
    console.print()


# ---------------------------------------------------------------------------
# stale-passwords
# ---------------------------------------------------------------------------
def print_stale_passwords(
    results: list[tuple[dict, object, int | None]],
    days: int,
    as_json: bool = False,
    disabled_excluded: int = 0,
    top: int | None = None,
    skip: int = 0,
) -> None:
    if as_json:
        rows = [
            {
                "name": obj.get("name", ""),
                "sid": obj.get("object_sid", ""),
                "class": obj.get("object_class", ""),
                "pwd_last_set": str(dt) if dt else None,
                "age_days": age,
            }
            for obj, dt, age in results
        ]
        _dump_json({"threshold_days": days, "count": len(rows),
                     "disabled_excluded": disabled_excluded, "results": rows})
        return

    if not results:
        msg = f"[dim]No accounts with passwords older than {days} days[/]"
        if disabled_excluded:
            msg += (f"\n[dim]({disabled_excluded:,} disabled account(s) excluded "
                    f"— use --include-disabled to include them)[/]")
        console.print(msg)
        return

    total = len(results)

    def _render(page: list, start: int) -> None:
        table = Table(
            title=f"Stale Passwords (>{days} days) — {total} accounts",
            show_lines=False, pad_edge=False,
        )
        table.add_column("Name", style="bold", min_width=20)
        table.add_column("Class", min_width=10)
        table.add_column("pwdLastSet", min_width=22)
        table.add_column("Age (days)", justify="right", min_width=10)
        for obj, dt, age in page:
            age_str = str(age) if age is not None else "never set"
            style = "bold red" if (age is not None and age > 730) else ""
            table.add_row(
                obj.get("name", ""),
                obj.get("object_class", ""),
                str(dt)[:19] if dt else "never",
                age_str,
                style=style,
            )
        console.print(table)

    _interactive_pager(results, _render, top=top, skip=skip)
    if disabled_excluded:
        console.print(f"[dim]({disabled_excluded:,} disabled account(s) excluded "
                      f"— use --include-disabled to include them)[/]")


# ---------------------------------------------------------------------------
# oldest-passwords
# ---------------------------------------------------------------------------
def print_oldest_passwords(
    rows: list[dict], top: int, as_json: bool = False, disabled_excluded: int = 0,
) -> None:
    if as_json:
        out = [
            {k: v for k, v in r.items() if k not in ("object", "_sort_key")}
            for r in rows
        ]
        _dump_json({"top": top, "count": len(out),
                     "disabled_excluded": disabled_excluded, "results": out})
        return

    if not rows:
        msg = "[dim]No accounts found[/]"
        if disabled_excluded:
            msg += (f"\n[dim]({disabled_excluded:,} disabled account(s) excluded "
                    f"— use --include-disabled to include them)[/]")
        console.print(msg)
        return

    table = Table(
        title=f"Oldest Passwords — Top {top} ({len(rows)} shown)",
        show_lines=False, pad_edge=False,
    )
    table.add_column("#", justify="right", min_width=3)
    table.add_column("Name", style="bold", min_width=20)
    table.add_column("Class", min_width=10)
    table.add_column("pwdLastSet", min_width=22)
    table.add_column("Age (days)", justify="right", min_width=10)
    table.add_column("Flags", min_width=18)

    for i, row in enumerate(rows, 1):
        age = row.get("age_days")
        flags: list[str] = []
        if row.get("passwd_notreqd"):
            flags.append("[bold red]NO_PWD_REQD[/]")
        if row.get("never_set"):
            flags.append("[bold red]NEVER_SET[/]")
        if not row.get("enabled"):
            flags.append("[dim]disabled[/]")

        if row.get("never_set") or row.get("passwd_notreqd"):
            style = "bold red"
            age_str = "N/A"
        elif age is not None and age > 730:
            style = "bold red"
            age_str = str(age)
        elif age is not None and age > 365:
            style = "bold yellow"
            age_str = str(age)
        else:
            style = ""
            age_str = str(age) if age is not None else "?"

        pwd_display = row.get("pwd_last_set", "never")
        if row.get("never_set"):
            pwd_display = "never"

        table.add_row(
            str(i),
            row.get("name", ""),
            row.get("object_class", ""),
            pwd_display,
            age_str,
            " ".join(flags) if flags else "",
            style=style,
        )
    console.print(table)
    if disabled_excluded:
        console.print(f"[dim]({disabled_excluded:,} disabled account(s) excluded "
                      f"— use --include-disabled to include them)[/]")
    console.print()


# ---------------------------------------------------------------------------
# newest / oldest (by whenCreated)
# ---------------------------------------------------------------------------
def print_by_created(
    rows: list[dict],
    object_class: str,
    top: int,
    newest_first: bool,
    as_json: bool = False,
    disabled_excluded: int = 0,
) -> None:
    if as_json:
        out = [
            {k: v for k, v in r.items() if k not in ("object", "when_created_dt")}
            for r in rows
        ]
        order = "newest" if newest_first else "oldest"
        _dump_json({"order": order, "class": object_class, "top": top, "count": len(out),
                     "disabled_excluded": disabled_excluded, "results": out})
        return

    if not rows:
        msg = f"[dim]No {object_class} objects found[/]"
        if disabled_excluded:
            msg += (f"\n[dim]({disabled_excluded:,} disabled account(s) excluded "
                    f"— use --include-disabled to include them)[/]")
        console.print(msg)
        return

    order_label = "Newest" if newest_first else "Oldest"
    table = Table(
        title=f"{order_label} {object_class}s — Top {top} ({len(rows)} shown)",
        show_lines=False, pad_edge=False,
    )
    table.add_column("#", justify="right", min_width=3)
    table.add_column("Name", style="bold", min_width=20)
    table.add_column("whenCreated", min_width=22)
    table.add_column("Age (days)", justify="right", min_width=10)
    table.add_column("DN", min_width=30)

    for i, row in enumerate(rows, 1):
        wc = row.get("when_created", "N/A")
        age = row.get("days_ago")
        age_str = str(age) if age is not None else "?"
        table.add_row(
            str(i),
            row.get("name", ""),
            wc,
            age_str,
            row.get("dn", ""),
        )
    console.print(table)
    if disabled_excluded:
        console.print(f"[dim]({disabled_excluded:,} disabled account(s) excluded "
                      f"— use --include-disabled to include them)[/]")
    console.print()


# ---------------------------------------------------------------------------
# spns
# ---------------------------------------------------------------------------
def print_spns(results: list[tuple[dict, list[str]]], as_json: bool = False,
               top: int | None = None, skip: int = 0,
               idx=None, domain_col: bool = False) -> None:
    if as_json:
        rows = [
            {"name": obj.get("name", ""), "sid": obj.get("object_sid", ""), "spns": spns}
            for obj, spns in results
        ]
        _dump_json({"count": len(rows), "results": rows})
        return

    if not results:
        console.print("[dim]No SPNs found[/]")
        return

    total = len(results)

    def _render(page: list, start: int) -> None:
        table = Table(
            title=f"Service Principal Names ({total} objects)",
            show_lines=False, pad_edge=False,
        )
        table.add_column("Account", style="bold", min_width=20)
        table.add_column("Class", min_width=10)
        if domain_col:
            table.add_column("Domain", min_width=10)
        table.add_column("SPNs", min_width=50)
        for obj, spns in page:
            row = [obj.get("name", ""), obj.get("object_class", "")]
            if domain_col:
                row.append(_row_domain_label(obj, idx))
            row.append("\n".join(spns))
            table.add_row(*row)
        console.print(table)

    _interactive_pager(results, _render, top=top, skip=skip)


# ---------------------------------------------------------------------------
# cas (Certificate Authorities)
# ---------------------------------------------------------------------------
def print_cas(results: list[dict], as_json: bool = False) -> None:
    if as_json:
        _dump_json({"count": len(results), "cas": results})
        return

    if not results:
        console.print("[dim]No Certificate Authorities found[/]")
        return

    table = Table(
        title=f"Certificate Authorities ({len(results)})",
        show_lines=False, pad_edge=False,
    )
    table.add_column("#", justify="right", min_width=3)
    table.add_column("CA Name", style="bold", min_width=20)
    table.add_column("DNS Hostname", min_width=25)
    table.add_column("Templates", justify="right", min_width=9)
    table.add_column("RPC Encryption", min_width=14)

    for i, ca in enumerate(results, 1):
        enc = "[green]Enforced[/]" if ca["enforce_encryption"] else "[red]Not Enforced[/]"
        table.add_row(
            str(i),
            ca["name"],
            ca["dns_hostname"],
            str(ca["template_count"]),
            enc,
        )
    console.print(table)
    console.print()


# ---------------------------------------------------------------------------
# templates (Certificate Templates)
# ---------------------------------------------------------------------------
def print_templates(results: list[dict], as_json: bool = False) -> None:
    if as_json:
        _dump_json({"count": len(results), "templates": results})
        return

    if not results:
        console.print("[dim]No Certificate Templates found[/]")
        return

    # Sort: vulnerable first, then by name
    results = sorted(results, key=lambda t: (not t["vulnerable"], t["name"]))

    vuln_count = sum(1 for t in results if t["vulnerable"])
    safe_count = len(results) - vuln_count
    table = Table(
        title=f"Certificate Templates ({len(results)}: [red]{vuln_count} vulnerable[/], [green]{safe_count} OK[/])",
        show_lines=False, pad_edge=False,
    )
    table.add_column("#", justify="right", min_width=3)
    table.add_column("Template Name", style="bold", min_width=25)
    table.add_column("Ver", justify="center", min_width=3)
    table.add_column("EKU", min_width=25)
    table.add_column("SAN", justify="center", min_width=3)
    table.add_column("Approval", justify="center", min_width=8)
    table.add_column("Status", min_width=8)
    table.add_column("ESC IDs", min_width=12)

    for i, t in enumerate(results, 1):
        vuln = t["vulnerable"]
        status = "[red]VULN[/]" if vuln else "[green]OK[/]"
        esc = ", ".join(t["esc_ids"]) if t["esc_ids"] else ""
        if vuln:
            esc = f"[red]{esc}[/]"
        san = "[red]Yes[/]" if t["supplies_san"] else "No"
        approval = "Required" if t["manager_approval"] else "[dim]None[/]"
        eku_str = ", ".join(t["ekus"]) if t["ekus"] else ""

        # No row background — a populated 'ESC IDs' column already makes a
        # vulnerable template evident; the colored ESC list draws the eye.
        table.add_row(
            str(i),
            t["name"],
            t["schema_version"] or "?",
            eku_str,
            san,
            approval,
            status,
            esc,
        )
    console.print(table)
    console.print()


# ---------------------------------------------------------------------------
# trusts
# ---------------------------------------------------------------------------
def print_trusts(trusts: list[dict], idx: CollectionIndex, as_json: bool = False) -> None:
    if as_json:
        rows = []
        for t in trusts:
            props = t.get("properties", {})
            rows.append({
                "name": t.get("name", ""),
                "sid": t.get("object_sid", ""),
                "direction": props.get("trustDirection"),
                "type": props.get("trustType"),
                "attributes": props.get("trustAttributes"),
                "flat_name": props.get("flatName", ""),
            })
        _dump_json({"count": len(rows), "trusts": rows})
        return

    if not trusts:
        console.print("[dim]No trust relationships found[/]")
        return

    from .query import _trust_direction_str, _trust_type_str

    table = Table(
        title=f"Domain Trusts ({len(trusts)})",
        show_lines=False, pad_edge=False,
    )
    table.add_column("Name", style="bold", min_width=20)
    table.add_column("Direction", min_width=15)
    table.add_column("Type", min_width=15)
    table.add_column("Flat Name", min_width=15)

    for t in trusts:
        props = t.get("properties", {})
        table.add_row(
            t.get("name", ""),
            _trust_direction_str(props.get("trustDirection")),
            _trust_type_str(props.get("trustType")),
            props.get("flatName", ""),
        )
    console.print(table)
    console.print()


# ---------------------------------------------------------------------------
# stats
# ---------------------------------------------------------------------------
def print_stats(stats: dict, as_json: bool = False) -> None:
    if as_json:
        _dump_json(stats)
        return

    lines = [
        f"[bold]Domain:[/]              {stats['domain']}",
        f"[bold]DC:[/]                  {stats['dc']}",
        f"[bold]Collected:[/]           {stats['collected_at']}",
        f"[bold]Method:[/]              {stats['collection_method']}",
        f"[bold]Total Objects:[/]       {stats['total_objects']}",
        f"[bold]SID Map Entries:[/]     {stats['sid_map_entries']}",
        f"[bold]Disabled Accounts:[/]   {stats['disabled_accounts']}",
        "",
        "[bold]Objects by class:[/]",
    ]
    for cls, count in sorted(stats.get("by_class", {}).items()):
        lines.append(f"  {cls:20s} {count}")

    if stats.get("sessions"):
        lines.append(f"\n[bold]Sessions:[/]            {stats['sessions']}")
    if stats.get("local_group_members"):
        lines.append(f"[bold]Local Group Members:[/] {stats['local_group_members']}")

    console.print(Panel("\n".join(lines), title="Collection Statistics", border_style="green"))


# ---------------------------------------------------------------------------
# delegation-map (Feature 1)
# ---------------------------------------------------------------------------
def print_delegation_map(results: list[dict], as_json: bool = False,
                          top: int | None = None, skip: int = 0,
                          idx=None, domain_col: bool = False) -> None:
    if as_json:
        _dump_json({"count": len(results), "delegations": results})
        return

    if not results:
        console.print("[dim]No delegation relationships found[/]")
        return

    total = len(results)
    type_styles = {
        "Unconstrained": "bold red",
        "Constrained": "bold yellow",
        "RBCD": "cyan",
    }

    def _render(page: list[dict], start: int) -> None:
        table = Table(
            title=f"Delegation Map ({total} entries)",
            show_lines=False, pad_edge=False,
        )
        table.add_column("Principal", style="bold", min_width=20)
        table.add_column("Class", min_width=10)
        if domain_col:
            table.add_column("Domain", min_width=10)
        table.add_column("Type", min_width=15)
        table.add_column("Proto Trans", justify="center", min_width=5)
        table.add_column("Targets", min_width=40)
        table.add_column("Status", min_width=8)
        for d in page:
            dtype = d.get("delegation_type", "")
            style = type_styles.get(dtype, "")
            enabled = "enabled" if d.get("enabled") else "[red]disabled[/]"
            targets = d.get("targets", [])
            target_str = "\n".join(targets[:5])
            if len(targets) > 5:
                target_str += f"\n... +{len(targets) - 5} more"
            row = [d.get("principal", ""), d.get("principal_class", "")]
            if domain_col:
                row.append(_row_domain_label(d, idx))
            row += [dtype, "Y" if d.get("protocol_transition") else "",
                    target_str, enabled]
            table.add_row(*row, style=style)
        console.print(table)

    _interactive_pager(results, _render, top=top, skip=skip)


# ---------------------------------------------------------------------------
# attack-surface (Feature 2)
# ---------------------------------------------------------------------------
def print_attack_surface(surface: dict, as_json: bool = False) -> None:
    if as_json:
        _dump_json(surface)
        return

    name = surface.get("name", "")
    cls = surface.get("object_class", "")
    enabled = "[green]Enabled[/]" if surface.get("enabled") else "[red]Disabled[/]"

    lines = [
        f"[bold]Principal:[/]     {name}  ({cls})",
        f"[bold]SID:[/]           {surface.get('sid', '')}",
        f"[bold]Status:[/]        {enabled}",
        "",
    ]

    # Groups
    groups = surface.get("groups", [])
    lines.append(f"[bold]Group Memberships ({len(groups)}):[/]")
    for g in groups[:20]:
        lines.append(f"  {g}")
    if len(groups) > 20:
        lines.append(f"  ... +{len(groups) - 20} more")

    # ACL rights
    acl_rights = surface.get("acl_rights", [])
    lines.append(f"\n[bold]ACL Rights on Other Objects ({len(acl_rights)}):[/]")
    if acl_rights:
        for r in acl_rights[:15]:
            rights_str = ", ".join(r.get("rights", []))
            lines.append(f"  {r['target']} ({r['target_class']}): {rights_str}  via {r['via']}")
        if len(acl_rights) > 15:
            lines.append(f"  ... +{len(acl_rights) - 15} more")
    else:
        lines.append("  [dim]none[/]")

    # Delegation
    dt = surface.get("delegation_targets", [])
    if dt:
        lines.append(f"\n[bold]Constrained Delegation Targets ({len(dt)}):[/]")
        for t in dt:
            lines.append(f"  {t}")

    # Sessions
    sessions = surface.get("sessions", [])
    if sessions:
        lines.append(f"\n[bold]Active Sessions ({len(sessions)}):[/]")
        for s in sessions[:10]:
            lines.append(f"  {s['computer']}")

    # Local admin
    local_admin = surface.get("local_admin_on", [])
    if local_admin:
        lines.append(f"\n[bold]Local Admin On ({len(local_admin)}):[/]")
        for comp in local_admin[:10]:
            lines.append(f"  {comp}")

    # Flags
    flags = []
    if surface.get("kerberoastable"):
        flags.append("[bold red]KERBEROASTABLE[/]")
    if surface.get("asrep_roastable"):
        flags.append("[bold red]AS-REP ROASTABLE[/]")
    if surface.get("admin_count"):
        flags.append("[yellow]adminCount=1[/]")
    if flags:
        lines.append(f"\n[bold]Flags:[/] {' | '.join(flags)}")

    # SPNs
    spns = surface.get("spns", [])
    if spns:
        lines.append(f"\n[bold]SPNs ({len(spns)}):[/]")
        for s in spns[:10]:
            lines.append(f"  {s}")

    console.print(Panel("\n".join(lines), title=f"Attack Surface: {name}", border_style="red"))


# ---------------------------------------------------------------------------
# kerberoastable (Feature 5)
# ---------------------------------------------------------------------------
def print_kerberoastable(results: list[dict], as_json: bool = False,
                          top: int | None = None, skip: int = 0,
                          idx=None, domain_col: bool = False) -> None:
    if as_json:
        _dump_json({"count": len(results), "accounts": results})
        return

    if not results:
        console.print("[dim]No kerberoastable accounts found[/]")
        return

    total = len(results)

    def _render(page: list[dict], start: int) -> None:
        table = Table(
            title=f"Kerberoastable Accounts ({total})",
            show_lines=False, pad_edge=False,
        )
        table.add_column("#", justify="right", min_width=3)
        table.add_column("Account", style="bold", min_width=20)
        if domain_col:
            table.add_column("Domain", min_width=10)
        table.add_column("Status", min_width=8)
        table.add_column("SPNs", justify="right", min_width=4)
        table.add_column("Pwd Age", justify="right", min_width=8)
        table.add_column("Flags", min_width=20)
        table.add_column("Top SPN", min_width=30)
        for i, r in enumerate(page, start + 1):
            flags = []
            if r.get("des_only"):
                flags.append("[bold red]DES[/]")
            if r.get("admin_count"):
                flags.append("[yellow]adminCount[/]")
            if not r.get("enabled"):
                flags.append("[dim]disabled[/]")
            enabled = "enabled" if r.get("enabled") else "[red]disabled[/]"
            age = r.get("pwd_age_days")
            age_str = str(age) if age is not None else "?"
            spns = r.get("spns", [])
            style = ""
            if r.get("admin_count"):
                style = "bold yellow"
            elif r.get("enabled") and age is not None and age > 365:
                style = "yellow"
            row = [str(i), r.get("name", "")]
            if domain_col:
                row.append(_row_domain_label(r, idx))
            row += [enabled, str(r.get("spn_count", 0)), age_str,
                    " ".join(flags) if flags else "", spns[0] if spns else ""]
            table.add_row(*row, style=style)
        console.print(table)

    _interactive_pager(results, _render, top=top, skip=skip)


# ---------------------------------------------------------------------------
# CSV export helper (Feature 8)
# ---------------------------------------------------------------------------
def export_query_csv(rows: list[dict], columns: list[str], output_path: str) -> str:
    """Write query results to a CSV file. Returns the path written."""
    import csv
    from pathlib import Path

    p = Path(output_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
    return str(p)


# ---------------------------------------------------------------------------
# graph (Feature 12) — ASCII/DOT attack path visualization
# ---------------------------------------------------------------------------
def print_graph(
    idx: "CollectionIndex",
    principal_id: str,
    max_depth: int = 5,
    output_format: str = "ascii",
    as_json: bool = False,
    include_edges: set[str] | None = None,
    exclude_edges: set[str] | None = None,
    weighted: bool = False,
    max_cost: float = 30.0,
) -> None:
    """Render a small attack path graph from a principal.

    Args:
        include_edges: If set, only show edges with these types.
        exclude_edges: If set, hide edges with these types.
        weighted: Use Dijkstra (weighted) instead of BFS for path discovery.
        max_cost: Maximum cumulative path cost (only for weighted mode).
    """
    graph = _build_graph_data(idx, principal_id, max_depth,
                              include_edges=include_edges,
                              exclude_edges=exclude_edges,
                              weighted=weighted, max_cost=max_cost)

    if as_json:
        _dump_json(graph)
        return

    if not graph["edges"]:
        console.print(f"[dim]No outbound edges found for {principal_id}[/]")
        return

    if output_format == "dot":
        _print_dot(graph)
    else:
        _print_ascii_graph(graph)


def _edge_allowed(label: str,
                   include_edges: set[str] | None,
                   exclude_edges: set[str] | None) -> bool:
    """Check if an edge label passes the include/exclude filters.

    Comparison is case-insensitive: user can type ``memberof`` or ``MemberOf``.
    """
    label_lower = label.lower()
    base = label_lower.split(":")[0]
    if include_edges is not None:
        inc_lower = {e.lower() for e in include_edges}
        if label_lower not in inc_lower and base not in inc_lower:
            return False
    if exclude_edges is not None:
        exc_lower = {e.lower() for e in exclude_edges}
        if label_lower in exc_lower or base in exc_lower:
            return False
    return True


def _build_graph_data(
    idx: "CollectionIndex",
    principal_id: str,
    max_depth: int,
    include_edges: set[str] | None = None,
    exclude_edges: set[str] | None = None,
    weighted: bool = False,
    max_cost: float = 30.0,
) -> dict:
    """BFS/Dijkstra to build a small graph of outbound relationships."""
    obj = idx.get(principal_id)
    if not obj:
        return {"nodes": [], "edges": [], "root": principal_id}

    root_sid = obj.get("object_sid", "")
    root_name = obj.get("name", principal_id)

    nodes: dict[str, dict] = {root_sid: {"name": root_name, "class": obj.get("object_class", "")}}
    edges: list[dict] = []

    # If weighted mode, build the full attack graph and use Dijkstra
    if weighted:
        from .analyzer import (
            _build_attack_graph,
            _is_high_value,
            dijkstra_shortest_paths,
            get_edge_weight,
        )
        objects = idx.objects
        sid_map = idx.raw_sid_map
        graph_data, sid_names, _ = _build_attack_graph(
            objects, sid_map=sid_map,
            sessions=idx.sessions,
            local_group_members=idx.local_group_members,
        )
        # Find all high-value targets
        hv_sids = {o.get("object_sid", "") for o in objects if _is_high_value(o.get("object_sid", ""))}
        hv_sids.discard("")  # remove empty SIDs
        if not hv_sids:
            import logging
            logging.getLogger(__name__).warning(
                "No high-value targets identified — weighted path results will be empty"
            )
            return {"nodes": [{"sid": sid, **data} for sid, data in nodes.items()], "edges": edges, "root": root_name}

        paths = dijkstra_shortest_paths(
            graph_data, {root_sid}, hv_sids,
            max_cost=max_cost,
            include_edges=include_edges,
            exclude_edges=exclude_edges,
        )
        for p in paths[:50]:  # limit output
            path_sids = p["path_sids"]
            path_edges = p["path_edges"]
            for i, sid in enumerate(path_sids):
                if sid not in nodes:
                    name = sid_names.get(sid, _resolve_name(sid, idx.sid_map, idx.domain))
                    nodes[sid] = {"name": name, "class": ""}
                if i > 0:
                    src_name = nodes[path_sids[i - 1]]["name"]
                    tgt_name = nodes[sid]["name"]
                    edge_label = path_edges[i - 1] if i - 1 < len(path_edges) else "?"
                    weight = get_edge_weight(edge_label)
                    edges.append({
                        "from": src_name, "to": tgt_name,
                        "label": f"{edge_label} (w={weight})",
                    })

        return {
            "root": root_name,
            "nodes": [{"sid": sid, **data} for sid, data in nodes.items()],
            "edges": edges,
            "weighted": True,
            "paths_found": len(paths),
        }

    # Standard BFS mode with optional edge filtering
    # Get group memberships
    groups = idx.memberof(principal_id, recursive=True)
    all_sids = {root_sid} | {g.get("object_sid", "") for g in groups}

    # Add group edges
    if _edge_allowed("MemberOf", include_edges, exclude_edges):
        direct_groups = idx.memberof(principal_id, recursive=False)
        for g in direct_groups:
            gsid = g.get("object_sid", "")
            gname = g.get("name", "")
            if gsid and gsid not in nodes:
                nodes[gsid] = {"name": gname, "class": "group"}
            if gsid:
                edges.append({"from": root_name, "to": gname, "label": "MemberOf"})

    # Look for ACL-based edges (limited scan)
    count = 0
    for target_obj in idx.objects:
        if count >= 50:
            break
        target_sid = target_obj.get("object_sid", "")
        if target_sid in all_sids:
            continue
        for ace in target_obj.get("dacl", []):
            if "ALLOWED" not in ace.get("ace_type", ""):
                continue
            trustee = ace.get("trustee_sid", "")
            if trustee in all_sids:
                labels = _acl_edge_labels(
                    ace.get("access_mask", 0), ace.get("object_type"),
                )
                # Apply edge filter
                filtered_labels = [
                    l for l in labels
                    if _edge_allowed(l, include_edges, exclude_edges)
                ]
                if filtered_labels:
                    target_name = target_obj.get("name", target_sid)
                    if target_sid not in nodes:
                        nodes[target_sid] = {"name": target_name, "class": target_obj.get("object_class", "")}
                    edges.append({
                        "from": _resolve_name(trustee, idx.sid_map, idx.domain),
                        "to": target_name,
                        "label": ", ".join(filtered_labels),
                    })
                    count += 1
                    break

    return {
        "root": root_name,
        "nodes": [{"sid": sid, **data} for sid, data in nodes.items()],
        "edges": edges,
    }


def _print_ascii_graph(graph: dict) -> None:
    """Render graph as an ASCII tree."""
    root = graph["root"]
    tree = Tree(f"[bold cyan]{root}[/]")

    # Group edges by source
    by_source: dict[str, list[dict]] = {}
    for edge in graph["edges"]:
        by_source.setdefault(edge["from"], []).append(edge)

    # BFS rendering
    rendered: set[str] = {root}
    queue = [(root, tree)]
    while queue:
        src, parent_node = queue.pop(0)
        for edge in by_source.get(src, []):
            target = edge["to"]
            label = edge["label"]
            if target in rendered:
                parent_node.add(f"[dim]{target}[/]  [dim italic]({label}, circular)[/]")
                continue
            rendered.add(target)
            style = "bold red" if any(d in label for d in ("GenericAll", "WriteDACL")) else "yellow"
            child = parent_node.add(f"[{style}]{target}[/]  [dim italic]--{label}-->[/]")
            queue.append((target, child))

    console.print(tree)
    console.print()


def _print_dot(graph: dict) -> None:
    """Render graph in DOT (Graphviz) format."""
    lines = ['digraph attack_path {', '  rankdir=LR;', '  node [shape=box];']
    for node in graph["nodes"]:
        name = node["name"].replace('"', '\\"')
        cls = node.get("class", "")
        lines.append(f'  "{name}" [label="{name}\\n({cls})"];')
    for edge in graph["edges"]:
        src = edge["from"].replace('"', '\\"')
        dst = edge["to"].replace('"', '\\"')
        label = edge["label"].replace('"', '\\"')
        lines.append(f'  "{src}" -> "{dst}" [label="{label}"];')
    lines.append("}")
    sys.stdout.write("\n".join(lines) + "\n")


# ---------------------------------------------------------------------------
# Sessions and local-admins formatters
# ---------------------------------------------------------------------------

def print_sessions(
    results: list[dict], *, as_json: bool = False,
    top: int | None = None, skip: int = 0,
) -> None:
    """Print session query results as a Rich table or JSON."""
    if as_json:
        _dump_json(results)
        return
    if not results:
        console.print("  No sessions found.")
        return

    total = len(results)

    # Check if any session has the new metadata fields
    has_metadata = any(s.get("collected_at") or s.get("source_method") for s in results)

    def _render(page: list[dict], start: int) -> None:
        t = Table(title=f"Sessions ({total})", show_lines=False, pad_edge=False)
        t.add_column("User", style="cyan", min_width=20)
        t.add_column("Source Host", min_width=16)
        t.add_column("Target Host", min_width=16)
        if has_metadata:
            t.add_column("Method", style="dim", min_width=16)
            t.add_column("Collected At", style="dim", min_width=20)
        for s in page:
            row = [
                s.get("username", ""),
                s.get("source_host", ""),
                s.get("target_host", ""),
            ]
            if has_metadata:
                row.append(s.get("source_method", ""))
                raw_ts = s.get("collected_at", "")
                # Format ISO timestamp to a more readable form
                if raw_ts:
                    try:
                        from datetime import datetime
                        dt = datetime.fromisoformat(raw_ts)
                        row.append(dt.strftime("%Y-%m-%d %H:%M:%S UTC"))
                    except (ValueError, TypeError):
                        row.append(raw_ts)
                else:
                    row.append("")
            t.add_row(*row)
        console.print(t)

    _interactive_pager(results, _render, top=top, skip=skip)


def print_local_admins(
    results: list[dict], *, as_json: bool = False,
    top: int | None = None, skip: int = 0,
) -> None:
    """Print local group membership query results as a Rich table or JSON."""
    if as_json:
        _dump_json(results)
        return
    if not results:
        console.print("  No local group memberships found.")
        return

    total = len(results)

    def _render(page: list[dict], start: int) -> None:
        t = Table(title=f"Local Group Memberships ({total})",
                  show_lines=False, pad_edge=False)
        t.add_column("Member", style="cyan", min_width=20)
        t.add_column("Group", min_width=18)
        t.add_column("Edge Type", style="dim", min_width=14)
        t.add_column("Target Host", min_width=16)
        for m in page:
            t.add_row(
                m.get("member_name", m.get("member_sid", "")),
                m.get("group_name", ""),
                m.get("edge_type", ""),
                m.get("target_host", ""),
            )
        console.print(t)

    _interactive_pager(results, _render, top=top, skip=skip)
