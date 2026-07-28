"""Attack-path report (``report run --type attackpaths``).

A purpose-built report for both sides of the house:
- **Offense (pentest):** the concrete attack paths to Tier Zero and, per finding
  category, how to abuse it (tools/commands).
- **Defense (SOC/blue team):** how to remediate and how to detect each step.

MITRE ATT&CK is front and center — every finding category maps to a technique
(ID + tactic, linked to attack.mitre.org), and the report leads with an ATT&CK
technique matrix. Self-contained/offline; reuses the shared HTML theming.
"""
from __future__ import annotations

import html
from datetime import datetime, timezone

from lazyhound.finder.collect.analyzer import Category
from lazyhound.finder.reports.html_unified_report import (
    STYLES, _THEME_VARS, _BASE_CSS, _SEV_COLOR, _SEV_ORDER, _e,
)


class _TTP:
    __slots__ = ("tid", "name", "tactic", "offense", "remediate", "detect")

    def __init__(self, tid, name, tactic, offense, remediate, detect):
        self.tid, self.name, self.tactic = tid, name, tactic
        self.offense, self.remediate, self.detect = offense, remediate, detect

    @property
    def url(self) -> str:
        return f"https://attack.mitre.org/techniques/{self.tid.replace('.', '/')}/"


# Finding category -> MITRE ATT&CK technique + offense/defense playbook.
_TTPS: dict[Category, _TTP] = {
    Category.ACL_ABUSE: _TTP(
        "T1098", "Account Manipulation", "Persistence / Privilege Escalation",
        "Abuse the DACL right on the target: GenericAll/GenericWrite → set a Shadow "
        "Credential (Whisker/pyWhisker) or reset the password; WriteDacl/WriteOwner → "
        "grant yourself full control first (dacledit.py, bloodyAD, PowerView Add-DomainObjectAcl).",
        "Remove the excessive ACE; enforce least privilege on the object DACL; apply admin tiering.",
        "Event 5136 on the object's nTSecurityDescriptor; unexpected ACE additions to Tier-0 objects."),
    Category.KERBEROAST: _TTP(
        "T1558.003", "Kerberoasting", "Credential Access",
        "Request a service ticket for the SPN and crack it offline (Rubeus kerberoast, "
        "GetUserSPNs.py, hashcat -m 13100).",
        "Move the account to a (g)MSA or a 25+ char random password; require AES; strip unused SPNs.",
        "Event 4769 requesting RC4 (0x17) tickets for user SPNs; anomalous TGS-request volume."),
    Category.ASREP_ROAST: _TTP(
        "T1558.004", "AS-REP Roasting", "Credential Access",
        "Request an AS-REP for the pre-auth-disabled account and crack it (Rubeus asreproast, "
        "GetNPUsers.py, hashcat -m 18200).",
        "Enable Kerberos pre-authentication on the account; set a strong password.",
        "Event 4768 with pre-authentication not required."),
    Category.UNCONSTRAINED_DELEG: _TTP(
        "T1558", "Steal or Forge Kerberos Tickets", "Credential Access",
        "Coerce a privileged host/DC to authenticate (PetitPotam/PrinterBug), capture its TGT on "
        "the delegation host (Rubeus monitor), then Pass-the-Ticket or DCSync.",
        "Remove unconstrained delegation; mark Tier-0 accounts 'sensitive and cannot be delegated' "
        "and add them to Protected Users.",
        "TrustedForDelegation UAC changes; DC auth to non-DC hosts; coercion signatures (MS-RPRN/EFSRPC)."),
    Category.CONSTRAINED_DELEG: _TTP(
        "T1134.001", "Token Impersonation/Theft", "Privilege Escalation",
        "Use S4U2Self+S4U2Proxy to impersonate any user to the allowed service (Rubeus s4u, "
        "impacket getST); with protocol transition, impersonate to any SPN on the host.",
        "Restrict msDS-AllowedToDelegateTo to the minimum; avoid protocol transition; protect Tier-0.",
        "S4U2Self/Proxy ticket requests (4769) from delegation accounts."),
    Category.RBCD: _TTP(
        "T1134.001", "Token Impersonation/Theft (RBCD)", "Privilege Escalation",
        "Write msDS-AllowedToActOnBehalfOfOtherIdentity on the target (needs a controlled computer "
        "+ MAQ), then S4U to impersonate an admin (rbcd.py, Rubeus s4u).",
        "Set MachineAccountQuota=0; remove attacker-writable msDS-AllowedToActOnBehalfOfOtherIdentity.",
        "Event 5136 on msDS-AllowedToActOnBehalfOfOtherIdentity; new computer accounts + S4U activity."),
    Category.GROUP_MEMBERSHIP: _TTP(
        "T1098", "Account Manipulation", "Privilege Escalation",
        "Add a controlled principal to the privileged group on the path (net group /add, bloodyAD, "
        "PowerView Add-DomainGroupMember).",
        "Reduce nested privileged group membership; restrict who can modify the group; apply tiering.",
        "Events 4728/4732/4756 (member added to a security-enabled group)."),
    Category.DANGEROUS_CONFIG: _TTP(
        "T1078", "Valid Accounts", "Privilege Escalation / Defense Evasion",
        "Abuse the weak setting: PASSWORD_NOT_REQUIRED (blank-password logon), MachineAccountQuota>0 "
        "(join a machine → RBCD/noPac/Certifried), reversible/DES (recover cleartext or weak keys).",
        "Fix the flag: require passwords, set MAQ=0, disable reversible/DES encryption, rotate.",
        "UAC flag changes (5136); logons by accounts with weak configuration."),
    Category.OWNERSHIP: _TTP(
        "T1098", "Account Manipulation (Ownership)", "Privilege Escalation",
        "As owner, grant yourself WriteDacl then full control (owneredit.py, dacledit.py), then reset "
        "or shadow-credential the target.",
        "Reassign ownership of high-value objects to Tier-0 admins; audit owner changes.",
        "Event 5136 owner changes (nTSecurityDescriptor owner) on sensitive objects."),
    Category.GPO_ABUSE: _TTP(
        "T1484.001", "Group Policy Modification", "Privilege Escalation / Defense Evasion",
        "Edit a linked GPO to push an immediate scheduled task / local admin / logon script to the "
        "target OU (SharpGPOAbuse, pyGPOAbuse).",
        "Restrict GPO edit rights (WriteProperty/GPLink) to Tier-0; review linked scope; change control.",
        "SYSVOL GPO file changes; 5136 on gPCFileSysPath/gPLink; unexpected GPO-delivered tasks."),
    Category.OU_CONTROL: _TTP(
        "T1484.001", "Domain Policy Modification", "Privilege Escalation",
        "Link a malicious GPO to the OU, or write the AdminSDHolder ACL to persist rights on all "
        "protected principals via SDProp.",
        "Restrict OU DACL and AdminSDHolder write; monitor SDProp; enforce tiering.",
        "Event 5136 on AdminSDHolder / OU objects; new gPLink on OUs."),
    Category.DCSYNC: _TTP(
        "T1003.006", "DCSync", "Credential Access",
        "Replicate directory secrets to dump any hash incl. krbtgt (secretsdump.py -just-dc, "
        "mimikatz lsadump::dcsync) → Golden Ticket.",
        "Remove Get-Changes / Get-Changes-All from non-DC principals; alert on replication-right grants.",
        "Event 4662 with the DS-Replication-Get-Changes-All GUID from a non-DC (DRSUAPI)."),
    Category.LAPS_READ: _TTP(
        "T1555", "Credentials from Password Stores (LAPS)", "Credential Access",
        "Read ms-Mcs-AdmPwd / ms-LAPS-Password to get the local admin password (pyLAPS, LAPSDumper, "
        "ldapsearch), then log on locally.",
        "Restrict LAPS read to Tier-0/PAW admins; enable LAPS encryption; rotate on read.",
        "LDAP reads / 4662 on the LAPS attribute by unexpected principals."),
    Category.GMSA_READ: _TTP(
        "T1555", "Credentials from Password Stores (gMSA)", "Credential Access",
        "Read msDS-ManagedPassword and derive the NT hash (gMSADumper.py, DSInternals), then use "
        "the service account.",
        "Restrict PrincipalsAllowedToRetrieveManagedPassword to the intended hosts only.",
        "LDAP reads of msDS-ManagedPassword by unexpected principals."),
    Category.ADCS_ABUSE: _TTP(
        "T1649", "Steal or Forge Authentication Certificates", "Credential Access",
        "Enroll an abusable template for a privileged identity (Certipy req; ESC1 alt-SAN, ESC8 NTLM "
        "relay to web enrollment, Certifried machine dNSHostName), then PKINIT for a TGT.",
        "Fix the template/CA: remove ENROLLEE_SUPPLIES_SUBJECT+client-auth, require manager approval, "
        "enforce the security extension, disable web enrollment / enable EPA.",
        "Enrollment events 4886/4887 for unexpected subjects; PKINIT logons; Certipy signatures."),
    Category.TRUST_ABUSE: _TTP(
        "T1134.005", "SID-History Injection", "Privilege Escalation",
        "Forge an inter-realm/golden ticket with an extra privileged SID in SIDHistory across a trust "
        "without SID filtering (Rubeus, ticketer.py -extra-sid).",
        "Enable SID filtering / quarantine on trusts; remove stale SIDHistory; treat trusts as tiering "
        "boundaries.",
        "TGTs carrying foreign/privileged SIDs in SIDHistory; cross-trust 4769 with unexpected SIDs."),
    Category.SESSION_ABUSE: _TTP(
        "T1003.001", "LSASS Memory", "Credential Access",
        "Compromise the host with the privileged session and dump credentials from LSASS (mimikatz "
        "sekurlsa::logonpasswords, comsvcs MiniDump) → Pass-the-Hash/Ticket.",
        "Enable Credential Guard + LSA protection; use PAWs; avoid privileged logons to lower tiers.",
        "LSASS access (Sysmon 10) by non-system processes; privileged 4624 on workstations."),
    Category.LOCAL_ACCESS: _TTP(
        "T1021", "Remote Services", "Lateral Movement",
        "Use the local-admin/RDP/DCOM/WinRM right to execute on the host (psexec.py, wmiexec.py, "
        "evil-winrm, RDP), then harvest creds/sessions.",
        "Reduce local-admin sprawl (LAPS + tiering); restrict RDP/WinRM; monitor lateral movement.",
        "4624 type 3/10 admin logons; service creation (7045); WinRM/DCOM usage."),
    Category.DMSA_ABUSE: _TTP(
        "T1098", "Account Manipulation (BadSuccessor / dMSA)", "Privilege Escalation",
        "Set msDS-ManagedAccountPrecededByLink on a writable dMSA to a privileged predecessor and "
        "request the dMSA's keys — inheriting its privileges (BadSuccessor).",
        "Restrict who can create/write dMSA objects per OU; audit the succession link.",
        "5137/5136 on msDS-DelegatedManagedServiceAccount objects; succession-link changes."),
    Category.HYBRID_SYNC: _TTP(
        "T1078.004", "Valid Accounts: Cloud Accounts", "Privilege Escalation / Lateral Movement",
        "Compromise the on-prem synced account, then use its Entra privileges in the cloud (or the "
        "reverse) — a hybrid identity pivot.",
        "Don't grant privileged Entra roles to synced accounts; use cloud-only admins; enforce PIM + MFA.",
        "Cloud sign-ins by synced privileged accounts; correlated on-prem + Entra role use."),
    Category.AZURE_PRIVILEGE: _TTP(
        "T1098.003", "Additional Cloud Roles", "Privilege Escalation",
        "Abuse the Entra privilege: add credentials to a privileged SP/app you own, satisfy a "
        "dynamic-group rule, exploit a Conditional Access gap, or use a managed identity's token "
        "(roadtx, AADInternals, az cli).",
        "Least-privilege Entra roles + PIM; lock app/SP ownership & credentials; tighten Conditional "
        "Access; scope dynamic groups.",
        "Entra audit logs: role assignments, app-credential additions, CA policy changes, MI token use."),
}

# Path/meta categories are shown as paths, not technique cards.
_PATH_CATS = {Category.SHORTEST_PATH, Category.BLAST_RADIUS, Category.CROSS_CORRELATION}

_EXTRA_CSS = """
.ttp-badge{display:inline-block;font-family:var(--font);font-weight:700;font-size:.8rem;
background:var(--accent);color:#fff;border-radius:6px;padding:2px 8px;text-decoration:none}
.tactic{color:var(--muted);font-size:.85rem}
.play{border:1px solid var(--border);border-radius:var(--radius);padding:10px 14px;margin:8px 0}
.play.off{border-left:4px solid #e5484d;background:rgba(229,72,77,.06)}
.play.def{border-left:4px solid #3b82f6;background:rgba(59,130,246,.06)}
.play .lbl{font-weight:700;font-size:.75rem;text-transform:uppercase;letter-spacing:.04em}
.play.off .lbl{color:#e5484d}.play.def .lbl{color:#3b82f6}
.pathcard{background:var(--panel);border:1px solid var(--border);border-left:4px solid var(--accent);
border-radius:var(--radius);box-shadow:var(--shadow);padding:12px 16px;margin:10px 0}
.pathcard .chain{font-family:var(--font);word-break:break-word}
.hop{color:var(--accent);font-weight:700}
.edge{color:var(--muted);font-size:.78rem;font-weight:600;margin:0 2px}
.hops-chip{display:inline-block;background:rgba(127,127,127,.14);color:var(--muted);
border-radius:999px;padding:0 8px;font-size:.72rem;font-weight:700;margin:0 4px}
.tech{margin:18px 0;padding-bottom:6px;border-bottom:1px solid var(--border)}
.fitem{padding:6px 0;border-bottom:1px dashed var(--border);font-size:.92rem}
.fitem:last-child{border-bottom:none}
/* ---- visual summary ---- */
.viz{background:var(--panel);border:1px solid var(--border);border-radius:var(--radius);
box-shadow:var(--shadow);padding:16px;margin:14px 0}
.viz h3{margin:0 0 12px;font-size:.95rem}
.chain{display:flex;flex-wrap:wrap;align-items:stretch;gap:0}
.stage{flex:1 1 0;min-width:120px;text-align:center;border:1px solid var(--border);
border-radius:var(--radius);padding:10px 8px;background:rgba(127,127,127,.05)}
.stage.on{border-color:var(--accent);background:rgba(79,70,229,.08)}
.stage .tac{font-weight:700;font-size:.82rem}
.stage .cnt{font-size:1.5rem;font-weight:800;color:var(--accent)}
.stage.off .cnt{color:var(--muted);font-weight:600}
.stage .sub{color:var(--muted);font-size:.7rem;text-transform:uppercase;letter-spacing:.03em}
.chain .arr{display:flex;align-items:center;color:var(--muted);font-size:1.4rem;padding:0 6px}
.goal{flex:0 0 auto;min-width:120px;text-align:center;border-radius:var(--radius);
padding:10px 12px;background:var(--sev-critical);color:#fff}
.goal .tac{font-weight:800}.goal .sub{opacity:.85;font-size:.7rem;text-transform:uppercase}
.sevbar{display:flex;height:30px;border-radius:8px;overflow:hidden;border:1px solid var(--border)}
.sevbar span{display:flex;align-items:center;justify-content:center;color:#fff;font-size:.75rem;
font-weight:700;min-width:0}
.sevleg{display:flex;flex-wrap:wrap;gap:12px;margin-top:10px;font-size:.8rem;color:var(--muted)}
.sevleg .k{display:inline-block;width:10px;height:10px;border-radius:2px;margin-right:5px;vertical-align:middle}
.bars{display:flex;flex-direction:column;gap:8px}
.bar{display:flex;align-items:center;gap:10px}
.bar .lab{flex:0 0 150px;font-size:.85rem;text-align:right;color:var(--text)}
.bar .track{flex:1;background:rgba(127,127,127,.10);border-radius:6px;overflow:hidden}
.bar .fill{height:16px;background:var(--accent);border-radius:6px}
.bar .val{flex:0 0 34px;font-weight:700;font-size:.85rem}
@media print{.viz{break-inside:avoid}}
/* ---- ATT&CK heatmap ---- */
.heatmap-wrap{overflow-x:auto;border:1px solid var(--border);border-radius:var(--radius);
background:var(--panel);padding:10px;margin:12px 0}
.heatmap{display:flex;gap:6px;min-width:max-content}
.hm-col{flex:0 0 132px;display:flex;flex-direction:column;gap:3px}
.hm-tac{font-size:.72rem;font-weight:700;text-align:center;padding:4px;color:var(--muted);
border-bottom:1px solid var(--border);text-transform:uppercase;letter-spacing:.02em;min-height:34px}
.hm-cell{font-size:.68rem;padding:4px 6px;border-radius:4px;background:rgba(127,127,127,.06);
color:var(--muted);border:1px solid transparent;line-height:1.2}
.hm-cell .n{float:right;font-weight:800}
/* default colouring: by finding COUNT, green -> red */
.hm-cell.cnt-1{background:#2f9e44;color:#08140b}
.hm-cell.cnt-2{background:#82c91e;color:#0f1a06}
.hm-cell.cnt-3{background:#f2c744;color:#241c00}
.hm-cell.cnt-4{background:#f5871f;color:#fff}
.hm-cell.cnt-5{background:#e5484d;color:#fff;font-weight:700}
.hm-legend{display:flex;gap:12px;flex-wrap:wrap;margin:8px 0;font-size:.75rem;color:var(--muted)}
.hm-legend .k{display:inline-block;width:12px;height:12px;border-radius:3px;margin-right:5px;vertical-align:middle}
"""

# Matrix columns — the severities the analyzer emits (no "low").
_MATRIX_SEV = ["critical", "high", "medium", "info"]


def _labeled_chain_html(names, edges) -> str:
    """'A [GenericAll]→ B [MemberOf]→ C' — the chain with the edge label (the
    'how') on each hop. Falls back to plain arrows when no edge labels."""
    names = list(names or [])
    edges = list(edges or [])
    if not names:
        return ""
    parts = [_e(names[0])]
    for i, nm in enumerate(names[1:]):
        lbl = edges[i] if i < len(edges) else ""
        edge = f"<span class='edge'>[{_e(lbl)}]</span>" if lbl else ""
        parts.append(f" {edge}<span class='hop'>→</span> {_e(nm)}")
    return "".join(parts)


def _labeled_chain_md(names, edges) -> str:
    names = list(names or [])
    edges = list(edges or [])
    if not names:
        return ""
    out = [names[0]]
    for i, nm in enumerate(names[1:]):
        lbl = edges[i] if i < len(edges) else ""
        out.append((f" -[{lbl}]-> " if lbl else " → ") + nm)
    return "".join(out)


def _technique_counts(tech: dict) -> dict:
    """Findings per PARENT ATT&CK technique id (sub-technique ids rolled up):
    a category tagged T1558.003 increments T1558."""
    counts: dict = {}
    for cat, fs in tech.items():
        tid = _TTPS[cat].tid.split(".")[0]      # parent technique
        counts[tid] = counts.get(tid, 0) + len(fs)
    return counts


def _heat_bucket(n: int) -> str:
    """Count -> colour bucket (green -> red)."""
    if n <= 0:
        return ""
    if n <= 2:
        return "cnt-1"     # green
    if n <= 5:
        return "cnt-2"     # lime
    if n <= 10:
        return "cnt-3"     # yellow
    if n <= 20:
        return "cnt-4"     # orange
    return "cnt-5"         # red


def _technique_worst_sev(tech: dict) -> dict:
    """Worst (highest) severity per PARENT ATT&CK technique id."""
    out: dict = {}
    for cat, fs in tech.items():
        tid = _TTPS[cat].tid.split(".")[0]
        for f in fs:
            s = _sev(f)
            if tid not in out or _rank(s) < _rank(out[tid]):
                out[tid] = s
    return out


def _heatmap_html(tech: dict, heading: bool = True) -> str:
    """The ATT&CK matrix grid. Each hit cell carries BOTH a count bucket
    (cnt-1..5) and a severity class (sev-*) so the report's 'count vs severity'
    toggle can recolour it in pure CSS. Legends live in the report."""
    from lazyhound.finder.reports.attack_matrix import load_attack_matrix
    matrix = load_attack_matrix()
    counts = _technique_counts(tech)
    worst = _technique_worst_sev(tech)
    o = (["<h2>MITRE ATT&amp;CK Heatmap</h2>"] if heading else []) + [
         "<div class='heatmap-wrap'><div class='heatmap'>"]
    for tac in matrix.get("tactics", []):
        cells = []
        col_hits = 0
        for t in tac["techniques"]:
            n = counts.get(t["id"], 0)
            if n:
                col_hits += 1
                cnt = _heat_bucket(n)
                sev = "sev-" + worst.get(t["id"], "info")
                cells.append(f"<div class='hm-cell hm-hit {cnt} {sev}' title='{_e(t['id'])}'>"
                             f"<span class='n'>{n}</span>{_e(t['name'])}</div>")
            else:
                cells.append(f"<div class='hm-cell hm-empty' title='{_e(t['id'])}'>"
                             f"{_e(t['name'])}</div>")
        col_cls = "hm-col" + ("" if col_hits else " hm-col-empty")
        o.append(f"<div class='{col_cls}'><div class='hm-tac'>{_e(tac['name'])}</div>"
                 f"{''.join(cells)}</div>")
    o.append("</div></div>")
    return "".join(o)


def _severity_matrix(tech: dict) -> dict:
    """{Category: {severity: count}} — per-category findings tallied by severity."""
    out: dict = {}
    for cat, fs in tech.items():
        row = {s: 0 for s in _MATRIX_SEV}
        for f in fs:
            s = _sev(f)
            if s in row:
                row[s] += 1
        out[cat] = row
    return out


def _sev(f) -> str:
    return getattr(f.severity, "value", str(f.severity))


def _rank(sev: str) -> int:
    return _SEV_ORDER.index(sev) if sev in _SEV_ORDER else len(_SEV_ORDER)


def _collect(result):
    findings = result.actionable if result else []
    paths = [f for f in findings if f.category == Category.SHORTEST_PATH]
    tech: dict[Category, list] = {}
    for f in findings:
        if f.category in _PATH_CATS or f.category not in _TTPS:
            continue
        tech.setdefault(f.category, []).append(f)
    return findings, paths, tech


def _sev_counts(findings) -> dict[str, int]:
    out = {s: 0 for s in _SEV_ORDER}
    for f in findings:
        out[_sev(f)] = out.get(_sev(f), 0) + 1
    return out


def _severity_dist_html(findings) -> str:
    """The Severity distribution stacked bar + legend (kept beneath the heatmap)."""
    sc = _sev_counts(findings)
    total = sum(sc.values()) or 1
    o = ["<div class='viz'><h3>Severity distribution</h3><div class='sevbar'>"]
    for s in _SEV_ORDER:
        if sc[s]:
            pct = round(sc[s] * 100 / total, 1)
            o.append(f"<span style='background:{_SEV_COLOR[s]};flex:{sc[s]} 0 0'>"
                     f"{sc[s] if pct >= 8 else ''}</span>")
    o.append("</div><div class='sevleg'>")
    for s in _SEV_ORDER:
        o.append(f"<span><span class='k' style='background:{_SEV_COLOR[s]}'></span>"
                 f"{s.capitalize()} {sc[s]}</span>")
    o.append("</div></div>")
    return "".join(o)


def build_attackpaths_html(result, domain: str = "", style: int = 1,
                           generated: str | None = None) -> str:
    if style not in _THEME_VARS:
        style = 1
    findings, paths, tech = _collect(result)
    ts = generated or datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    title = domain or getattr(result, "domain", "") or "unknown realm"
    # order techniques by worst severity then count
    def _tkey(cat):
        fs = tech[cat]
        return (min(_rank(_sev(f)) for f in fs), -len(fs))
    ordered = sorted(tech, key=_tkey)

    css = (f":root{{{_THEME_VARS[style]}}}\n"
           f":root{{--sev-critical:{_SEV_COLOR['critical']};--sev-high:{_SEV_COLOR['high']};"
           f"--sev-medium:{_SEV_COLOR['medium']};--sev-low:{_SEV_COLOR['low']};--sev-info:{_SEV_COLOR['info']};}}\n"
           + _BASE_CSS + _EXTRA_CSS)

    o = ["<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'>",
         "<meta name='viewport' content='width=device-width,initial-scale=1'>",
         f"<title>LazyHound Attack Path Report — {_e(title)}</title>",
         f"<style>{css}</style></head><body class='style-{style}'><div class='wrap'>"]
    # header
    o.append(f"<header class='rpt'><h1>Attack Path Report</h1>"
             f"<div class='sub'>{_e(title)} · generated {_e(ts)} · "
             f"offense &amp; defense with MITRE ATT&amp;CK · style {style} ({_e(STYLES[style])})</div></header>")
    # Severity distribution (the ATT&CK heatmap is its own landscape report,
    # `report run --type heatmap`).
    o.append(_severity_dist_html(findings))

    # Findings Matrix — finding type × TTP × severity counts
    o.append("<h2>Findings Matrix</h2>")
    if ordered:
        matrix = _severity_matrix(tech)
        o.append("<table><thead><tr><th>Finding Type</th><th>TTP</th>"
                 + "".join(f"<th class='n'>{s.capitalize()}</th>" for s in _MATRIX_SEV)
                 + "<th class='n'>Total</th></tr></thead><tbody>")
        col_tot = {s: 0 for s in _MATRIX_SEV}
        grand = 0
        for cat in ordered:
            t = _TTPS[cat]
            row = matrix[cat]
            tot = len(tech[cat])
            grand += tot
            cells = []
            for s in _MATRIX_SEV:
                col_tot[s] += row[s]
                if row[s]:
                    cells.append(f"<td class='n'><span class='pill' style='background:"
                                 f"{_SEV_COLOR.get(s, '#8b93a7')}'>{row[s]}</span></td>")
                else:
                    cells.append("<td class='n muted'>·</td>")
            o.append(f"<tr><td>{_e(cat.value)}</td>"
                     f"<td><a class='ttp-badge' href='{t.url}'>{_e(t.tid)}</a></td>"
                     f"{''.join(cells)}<td class='n'>{tot}</td></tr>")
        o.append("<tr class='total'><td>Total</td><td></td>"
                 + "".join(f"<td class='n'>{col_tot[s]}</td>" for s in _MATRIX_SEV)
                 + f"<td class='n'>{grand}</td></tr>")
        o.append("</tbody></table>")
    else:
        o.append("<p class='muted'>No technique-mapped findings.</p>")

    # Attack paths — collapsed by default
    o.append("<h2>Attack Paths to Tier Zero</h2>")
    o.append("<details class='finding' style='--sev:var(--accent)'>"
             f"<summary><span class='title'>Attack Paths to Tier Zero</span>"
             f"<span class='badge' style='background:var(--accent)'>{len(paths)}</span></summary>"
             "<div class='body'>")
    if paths:
        for p in sorted(paths, key=lambda x: x.details.get("depth", 99))[:100]:
            names = p.details.get("path_names", []) or [p.principal_name, p.target_name]
            edges = p.details.get("path_edges", [])
            chain = _labeled_chain_html(names, edges)
            o.append(f"<div class='pathcard'><div class='chain'>{chain}</div>"
                     f"<div class='muted' style='font-size:.8rem'>{_e(p.details.get('depth',''))} hop(s) "
                     f"→ {_e(p.target_name)}</div></div>")
        if len(paths) > 100:
            o.append(f"<p class='muted'>…and {len(paths)-100} more paths.</p>")
    else:
        o.append("<p class='muted'>No shortest paths to Tier Zero found "
                 "(the technique findings below are still actionable).</p>")
    o.append("</div></details>")

    # Findings by Type — one collapsed <details> per finding category
    o.append("<h2>Findings by Type</h2>")
    if not ordered:
        o.append("<p class='muted'>No findings.</p>")
    for cat in ordered:
        t = _TTPS[cat]
        fs = sorted(tech[cat], key=lambda f: _rank(_sev(f)))
        worst = min((_sev(f) for f in fs), key=_rank)
        sevc = _SEV_COLOR.get(worst, "#8b93a7")
        o.append(f"<details class='finding' style='--sev:{sevc}'>"
                 f"<summary><span class='title'>{_e(cat.value)}</span>"
                 f"<span class='muted' style='font-size:.85rem'>{len(fs)} finding(s)</span>"
                 f"<span class='badge' style='background:{sevc}'>{_e(worst)}</span></summary>"
                 f"<div class='body'>"
                 f"<div class='cat'><a class='ttp-badge' href='{t.url}'>{_e(t.tid)}</a> "
                 f"{_e(t.name)} · {_e(t.tactic)}</div>"
                 f"<div class='play off'><span class='lbl'>🔴 Offensive</span><div>{_e(t.offense)}</div></div>"
                 f"<div class='play def'><span class='lbl'>🔵 Defensive — Remediate</span><div>{_e(t.remediate)}</div></div>"
                 f"<div class='play def'><span class='lbl'>🔵 Defensive — Detect</span><div>{_e(t.detect)}</div></div>")
        for f in fs:
            desc = f" — {_e(f.description)}" if f.description else ""
            dep = (f.details or {}).get("depth")
            hop = f"<span class='hops-chip'>{_e(dep)} hops</span>" if dep else ""
            o.append(f"<div class='fitem'><span class='badge' style='background:"
                     f"{_SEV_COLOR.get(_sev(f),'#8b93a7')}'>{_e(_sev(f))}</span> "
                     f"<strong>{_e(f.principal_name)}</strong> → {_e(f.target_name)}{hop}{desc}</div>")
        o.append("</div></details>")

    o.append("<footer class='rpt'>Generated by LazyHound · attack-path report · "
             f"{len(paths)} paths · {len(ordered)} ATT&amp;CK techniques</footer>")
    o.append("</div></body></html>")
    return "\n".join(o)


def build_attackpaths_markdown(result, domain: str = "") -> str:
    findings, paths, tech = _collect(result)
    title = domain or getattr(result, "domain", "") or "unknown"

    def _tkey(cat):
        fs = tech[cat]
        return (min(_rank(_sev(f)) for f in fs), -len(fs))
    ordered = sorted(tech, key=_tkey)

    lines = [f"# Attack Path Report — {title}", "",
             "_Offense & defense, mapped to MITRE ATT&CK._", "",
             "## Summary", "",
             f"- Attack paths to Tier Zero: **{len(paths)}**",
             f"- ATT&CK techniques observed: **{len(ordered)}**",
             f"- Technique findings: **{sum(len(v) for v in tech.values())}**", ""]

    # Severity histogram (the ATT&CK heatmap is its own report type).
    lines += ["## At a glance", ""]
    sc = _sev_counts(findings)
    for s in _SEV_ORDER:
        if sc[s]:
            lines.append(f"- {s.capitalize():9} {'█' * sc[s]} {sc[s]}")
    lines.append("")

    matrix = _severity_matrix(tech)
    lines += ["## Findings Matrix", "",
              "| Finding Type | TTP | " + " | ".join(s.capitalize() for s in _MATRIX_SEV) + " | Total |",
              "|---|---|" + "---|" * (len(_MATRIX_SEV) + 1)]
    if ordered:
        for cat in ordered:
            t = _TTPS[cat]
            row = matrix[cat]
            lines.append(f"| {cat.value} | [{t.tid}]({t.url}) | "
                         + " | ".join(str(row[s]) for s in _MATRIX_SEV)
                         + f" | {len(tech[cat])} |")
    else:
        lines.append("| _none_ | | " + " | ".join("0" for _ in _MATRIX_SEV) + " | 0 |")

    lines += ["", "## Attack Paths to Tier Zero", ""]
    if paths:
        for p in sorted(paths, key=lambda x: x.details.get("depth", 99))[:100]:
            names = p.details.get("path_names", []) or [p.principal_name, p.target_name]
            chain = _labeled_chain_md(names, p.details.get("path_edges", []))
            lines.append(f"- {chain}  _({p.details.get('depth','')} hop(s))_")
    else:
        lines.append("_No shortest paths found._")

    lines += ["", "## Findings by Type", ""]
    for cat in ordered:
        t = _TTPS[cat]
        lines.append(f"### {cat.value}")
        lines.append(f"_[{t.tid}]({t.url}) · {t.name} · {t.tactic}_")
        lines.append("")
        lines.append(f"- **🔴 Offensive:** {t.offense}")
        lines.append(f"- **🔵 Remediate:** {t.remediate}")
        lines.append(f"- **🔵 Detect:** {t.detect}")
        lines.append("")
        for f in sorted(tech[cat], key=lambda f: _rank(_sev(f))):
            desc = f" — {f.description}" if f.description else ""
            lines.append(f"  - [{_sev(f).upper()}] {f.principal_name} → {f.target_name}{desc}")
        lines.append("")
    return "\n".join(lines)
