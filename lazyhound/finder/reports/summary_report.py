"""Environment summary report from collection data.

Generates a comprehensive environment overview including domain metadata,
object counts, privileged group memberships, security posture indicators,
and trust relationships.  Works from collection JSON (no live LDAP needed).
"""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

from ..collect.analyzer import _get_uac
from ..collect.query import CollectionIndex


def generate_summary(idx: CollectionIndex) -> dict:
    """Build a summary data dict from a CollectionIndex."""
    stats = idx.stats()
    domain = idx.domain
    meta = idx.meta

    # --- Object counts ---
    by_class = stats["by_class"]

    # --- Enabled / disabled breakdown ---
    users = idx.objects_by_class("user")
    computers = idx.objects_by_class("computer")
    groups = idx.objects_by_class("group")
    ous = idx.objects_by_class("ou")
    gpos = idx.objects_by_class("gpo")
    trusts = idx.trusts()
    gmsas = idx.objects_by_class("gmsa")
    cert_templates = idx.objects_by_class("certtemplate")

    enabled_users = sum(1 for u in users if not (_get_uac(u) & 0x0002))
    disabled_users = len(users) - enabled_users
    enabled_computers = sum(1 for c in computers if not (_get_uac(c) & 0x0002))
    disabled_computers = len(computers) - enabled_computers

    # --- Privileged group membership counts ---
    priv_groups = {}
    priv_group_rids = {512: "Domain Admins", 518: "Schema Admins",
                       519: "Enterprise Admins", 526: "Key Admins",
                       527: "Enterprise Key Admins"}
    for obj in groups:
        sid = obj.get("object_sid", "")
        if not sid:
            continue
        parts = sid.rsplit("-", 1)
        if len(parts) == 2:
            try:
                rid = int(parts[1])
            except ValueError:
                continue
            if rid in priv_group_rids:
                members = obj.get("properties", {}).get("member", [])
                if isinstance(members, str):
                    members = [members]
                priv_groups[priv_group_rids[rid]] = {
                    "sid": sid,
                    "member_count": len(members),
                }

    # BUILTIN\Administrators
    for obj in groups:
        sid = obj.get("object_sid", "")
        if sid == "S-1-5-32-544":
            members = obj.get("properties", {}).get("member", [])
            if isinstance(members, str):
                members = [members]
            priv_groups["BUILTIN\\Administrators"] = {
                "sid": sid,
                "member_count": len(members),
            }

    # --- Security indicators ---
    kerberoastable = 0
    asrep_roastable = 0
    passwd_notreqd = 0
    dont_expire = 0
    admin_count_set = 0
    unconstrained_deleg = 0
    constrained_deleg = 0
    rbcd_configured = 0

    for obj in users + gmsas:
        uac = _get_uac(obj)
        props = obj.get("properties", {})

        spns = props.get("servicePrincipalName", [])
        if isinstance(spns, str):
            spns = [spns]
        if spns and obj.get("object_class") == "user":
            kerberoastable += 1
        if uac & 0x400000:  # DONT_REQ_PREAUTH
            asrep_roastable += 1
        if uac & 0x0020:  # PASSWD_NOTREQD
            passwd_notreqd += 1
        if uac & 0x10000:  # DONT_EXPIRE_PASSWORD
            dont_expire += 1
        if props.get("adminCount") in (1, "1", True):
            admin_count_set += 1

    for obj in users + computers:
        uac = _get_uac(obj)
        props = obj.get("properties", {})

        # Unconstrained (skip DCs)
        if uac & 0x80000 and not (uac & 0x2000):
            unconstrained_deleg += 1

        # Constrained
        targets = props.get("msDS-AllowedToDelegateTo", [])
        if isinstance(targets, str):
            targets = [targets]
        if targets:
            constrained_deleg += 1

        # RBCD
        rbcd = props.get("msDS-AllowedToActOnBehalfOfOtherIdentity")
        if rbcd is not None and rbcd != "":
            rbcd_configured += 1

    # --- Domain info ---
    domain_obj = None
    for obj in idx.objects_by_class("domain"):
        domain_obj = obj
        break

    domain_sid = ""
    functional_level = ""
    machine_account_quota = ""
    if domain_obj:
        domain_sid = domain_obj.get("object_sid", "")
        props = domain_obj.get("properties", {})
        functional_level = str(props.get("msDS-Behavior-Version", ""))
        maq = props.get("ms-DS-MachineAccountQuota")
        if maq is not None:
            machine_account_quota = str(maq)

    # Domain controllers
    dcs = []
    for obj in computers:
        uac = _get_uac(obj)
        if uac & 0x2000:  # SERVER_TRUST_ACCOUNT
            dcs.append(obj.get("name", ""))

    # --- Trust relationships ---
    trust_info = []
    _TRUST_DIRS = {0: "Disabled", 1: "Inbound", 2: "Outbound", 3: "Bidirectional"}
    _TRUST_TYPES = {1: "Downlevel (NT4)", 2: "Uplevel (AD)", 3: "MIT (Kerberos)"}
    for t in trusts:
        props = t.get("properties", {})
        try:
            trust_dir = int(props.get("trustDirection") or 0)
        except (ValueError, TypeError):
            trust_dir = 0
        try:
            trust_tp = int(props.get("trustType") or 0)
        except (ValueError, TypeError):
            trust_tp = 0
        direction = _TRUST_DIRS.get(trust_dir, "Unknown")
        ttype = _TRUST_TYPES.get(trust_tp, "Unknown")
        tattrs = props.get("trustAttributes", 0)
        try:
            tattrs = int(tattrs)
        except (ValueError, TypeError):
            tattrs = 0
        sid_filtering = "Enabled" if (tattrs & 0x04) else "Disabled"
        is_forest = bool(tattrs & 0x08)
        trust_info.append({
            "name": t.get("name", ""),
            "direction": direction,
            "type": ttype,
            "sid_filtering": sid_filtering,
            "forest_trust": is_forest,
            "flat_name": props.get("flatName", ""),
        })

    # --- OS distribution ---
    os_dist: dict[str, int] = defaultdict(int)
    for c in computers:
        os_name = c.get("properties", {}).get("operatingSystem", "Unknown")
        if os_name:
            os_dist[str(os_name)] += 1

    return {
        "domain": domain,
        "domain_sid": domain_sid,
        "dc": meta.get("dc", "unknown"),
        "collected_at": meta.get("collected_at", "unknown"),
        "collection_method": meta.get("collection_method", "unknown"),
        "functional_level": functional_level,
        "machine_account_quota": machine_account_quota,
        "domain_controllers": dcs,
        "object_counts": {
            "total": stats["total_objects"],
            "users": len(users),
            "users_enabled": enabled_users,
            "users_disabled": disabled_users,
            "computers": len(computers),
            "computers_enabled": enabled_computers,
            "computers_disabled": disabled_computers,
            "groups": len(groups),
            "ous": len(ous),
            "gpos": len(gpos),
            "gmsas": len(gmsas),
            "cert_templates": len(cert_templates),
            "trusts": len(trusts),
            "by_class": by_class,
        },
        "privileged_groups": priv_groups,
        "security_indicators": {
            "kerberoastable_users": kerberoastable,
            "asrep_roastable_users": asrep_roastable,
            "passwd_notreqd": passwd_notreqd,
            "dont_expire_password": dont_expire,
            "admin_count_set": admin_count_set,
            "unconstrained_delegation": unconstrained_deleg,
            "constrained_delegation": constrained_deleg,
            "rbcd_configured": rbcd_configured,
        },
        "trusts": trust_info,
        "os_distribution": dict(sorted(os_dist.items(), key=lambda x: -x[1])),
        "sessions_collected": stats["sessions"],
        "local_group_members_collected": stats["local_group_members"],
    }


def render_markdown(summary: dict) -> str:
    """Render summary dict as a Markdown report."""
    lines: list[str] = []
    oc = summary["object_counts"]
    si = summary["security_indicators"]

    lines.append(f"# LazyHound Environment Summary — {summary['domain']}\n")

    # Meta
    lines.append("## Collection Metadata\n")
    lines.append("| Field | Value |")
    lines.append("|-------|-------|")
    lines.append(f"| **Domain** | `{summary['domain']}` |")
    lines.append(f"| **Domain SID** | `{summary['domain_sid']}` |")
    lines.append(f"| **Domain Controller** | `{summary['dc']}` |")
    lines.append(f"| **Collected At** | {summary['collected_at']} |")
    lines.append(f"| **Collection Method** | {summary['collection_method']} |")
    if summary["functional_level"]:
        lines.append(f"| **Functional Level** | {summary['functional_level']} |")
    if summary["machine_account_quota"]:
        lines.append(f"| **MachineAccountQuota** | {summary['machine_account_quota']} |")
    if summary["domain_controllers"]:
        lines.append(f"| **Domain Controllers** | {', '.join(summary['domain_controllers'])} |")
    lines.append("")

    # Object counts
    lines.append("## Object Counts\n")
    lines.append("| Object Type | Total | Enabled | Disabled |")
    lines.append("|-------------|------:|--------:|---------:|")
    lines.append(f"| Users | {oc['users']} | {oc['users_enabled']} | {oc['users_disabled']} |")
    lines.append(f"| Computers | {oc['computers']} | {oc['computers_enabled']} | {oc['computers_disabled']} |")
    lines.append(f"| Groups | {oc['groups']} | — | — |")
    lines.append(f"| OUs | {oc['ous']} | — | — |")
    lines.append(f"| GPOs | {oc['gpos']} | — | — |")
    if oc["gmsas"]:
        lines.append(f"| gMSAs | {oc['gmsas']} | — | — |")
    if oc["cert_templates"]:
        lines.append(f"| Certificate Templates | {oc['cert_templates']} | — | — |")
    if oc["trusts"]:
        lines.append(f"| Trust Relationships | {oc['trusts']} | — | — |")
    lines.append(f"| **Total** | **{oc['total']}** | | |")
    lines.append("")

    # Privileged groups
    if summary["privileged_groups"]:
        lines.append("## Privileged Groups\n")
        lines.append("| Group | Members | SID |")
        lines.append("|-------|--------:|-----|")
        for name, info in sorted(summary["privileged_groups"].items()):
            lines.append(f"| {name} | {info['member_count']} | `{info['sid']}` |")
        lines.append("")

    # Security indicators
    lines.append("## Security Indicators\n")
    lines.append("| Indicator | Count |")
    lines.append("|-----------|------:|")
    lines.append(f"| Kerberoastable users | {si['kerberoastable_users']} |")
    lines.append(f"| AS-REP roastable users | {si['asrep_roastable_users']} |")
    lines.append(f"| PASSWD_NOTREQD set | {si['passwd_notreqd']} |")
    lines.append(f"| DONT_EXPIRE_PASSWORD set | {si['dont_expire_password']} |")
    lines.append(f"| adminCount=1 | {si['admin_count_set']} |")
    lines.append(f"| Unconstrained delegation | {si['unconstrained_delegation']} |")
    lines.append(f"| Constrained delegation | {si['constrained_delegation']} |")
    lines.append(f"| RBCD configured | {si['rbcd_configured']} |")
    lines.append("")

    # Trusts
    if summary["trusts"]:
        lines.append("## Trust Relationships\n")
        lines.append("| Trusted Domain | Direction | Type | SID Filtering | Forest Trust |")
        lines.append("|----------------|-----------|------|---------------|-------------|")
        for t in summary["trusts"]:
            forest = "Yes" if t["forest_trust"] else "No"
            lines.append(f"| {t['name']} | {t['direction']} | {t['type']} | {t['sid_filtering']} | {forest} |")
        lines.append("")

    # OS distribution
    if summary["os_distribution"]:
        lines.append("## Operating System Distribution\n")
        lines.append("| Operating System | Count |")
        lines.append("|------------------|------:|")
        for os_name, count in summary["os_distribution"].items():
            lines.append(f"| {os_name} | {count} |")
        lines.append("")

    # Network data
    if summary["sessions_collected"] or summary["local_group_members_collected"]:
        lines.append("## Network Collection\n")
        lines.append("| Data | Count |")
        lines.append("|------|------:|")
        lines.append(f"| Sessions | {summary['sessions_collected']} |")
        lines.append(f"| Local group memberships | {summary['local_group_members_collected']} |")
        lines.append("")

    lines.append("---\n*Report generated by LazyHound*\n")
    return "\n".join(lines)


def render_json(summary: dict) -> str:
    """Render summary as JSON string."""
    return json.dumps(summary, indent=2, default=str)


def write_summary(idx: CollectionIndex, output: str | Path, fmt: str = "markdown") -> Path:
    """Generate and write a summary report to a file."""
    summary = generate_summary(idx)
    p = Path(output)
    p.parent.mkdir(parents=True, exist_ok=True)

    if fmt == "json":
        p.write_text(render_json(summary), encoding="utf-8")
    else:
        p.write_text(render_markdown(summary), encoding="utf-8")
    return p
