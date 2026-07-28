# LazyHound

```
    __                      __  __                      __
   / /   ____ _____  __  __/ / / /___  __  ______  ____/ /
  / /   / __ `/_  / / / / / /_/ / __ \/ / / / __ \/ __  / 
 / /___/ /_/ / / /_/ /_/ / __  / /_/ / /_/ / / / / /_/ /  
/_____/\__,_/ /___/\__, /_/ /_/\____/\__,_/_/ /_/\__,_/   
                  /____/
```

<sub>What launching it looks like:</sub>

```console
└─$ lazyhound
    __                      __  __                      __
   / /   ____ _____  __  __/ / / /___  __  ______  ____/ /
  / /   / __ `/_  / / / / / /_/ / __ \/ / / / __ \/ __  / 
 / /___/ /_/ / / /_/ /_/ / __  / /_/ / /_/ / / / / /_/ /  
/_____/\__,_/ /___/\__, /_/ /_/\____/\__,_/_/ /_/\__,_/   
                  /____/
  AD & Entra Attack-Path Analysis
  v0.5.5.1 | MAP: collect → search → analyze   ·   ASSESS: scan → report

Restored 27 options from previous session.
Type 'help' or '?' for commands · a bare verb (collect · analyze · scan · report · search) shows its subcommands · add 'run' to launch (analyze run) or a subcommand (analyze paths, search info)

lazyhound> help
╭───────────────────────────────────────── Main Menu ─────────────────────────────────────────╮
│ Map                                                                                         │
│   collect       Collect AD (LDAP) & Entra (Graph), or import/export BloodHound & AzureHound │
│   search        Explore collected AD & Entra data (info, members, acl, who-can, ...)        │
│   analyze       Attack path analysis (graph-based)                                          │
│                                                                                             │
│ Assess                                                                                      │
│   scan          Live security assessment (76 checks)                                        │
│   report        Report generation                                                           │
│                                                                                             │
│ General                                                                                     │
│   options [key=value ...]  View/set connection & settings                                   │
│   domain [<fqdn|netbios|sid>]  Show/switch the active domain (multi-domain collections)     │
│   help          Show this help                                                              │
│   version       Show version info                                                           │
│   exit          Exit shell                                                                  │
╰─────────────────────────────────────────────────────────────────────────────────────────────╯
```

**Active Directory & Entra ID attack-path analysis, security assessment, and reporting — one offline tool, no server or database backend to stand up.**

LazyHound pulls Active Directory and Entra ID (Azure AD) data, maps
BloodHound-style attack paths across on-prem **and** cloud, runs a 76-check live
security assessment, lets you interactively explore everything from a single
REPL, and fuses it all into a report. It speaks BloodHound CE / SharpHound /
AzureHound formats both ways, so it drops into an existing workflow instead of
replacing it.

- **Offline-first** — once data is collected (or imported), every map, search,
  path, and report runs with no network access.
- **On-prem + cloud + hybrid** — AD forests, Entra tenants, and the sync edges
  between them are all first-class realms in one dataset.
- **No infrastructure** — no Neo4j, no web server, no Docker. `pip install`,
  point it at a project folder, go.
- **Interoperable** — import/export BloodHound `.zip` and AzureHound `.json`;
  export attack-path graphics as SVG / PNG / Mermaid / DOT.

---

## Contents

- [How it works](#how-it-works)
- [Scan vs. Analyze — what each covers](#scan-vs-analyze--what-each-covers)
- [Feature highlights](#feature-highlights)
- [What it finds](#what-it-finds)
- [Install](#install)
- [Dependencies](#dependencies)
- [Quick start](#quick-start)
- [Authentication](#authentication)
- [The interactive shell](#the-interactive-shell)
- [Command reference](#command-reference)
- [Realm scoping (forests & tenants)](#realm-scoping-forests--tenants)
- [Data interoperability](#data-interoperability)
- [Offline & OPSEC](#offline--opsec)
- [Credits](#credits)
- [License](#license)

---

## How it works

Two workflows, five verbs:

```
MAP     collect → search → analyze     pull AD/Entra data, explore it, map attack paths
ASSESS  scan → report                  grade the environment, deliver a report
```

- **MAP** is the relationship side — raw objects → interactive exploration →
  BloodHound-style attack **paths** to Tier Zero, entirely offline once
  collected.
- **ASSESS** is the live side — a graded, 76-check security **scan** fused with
  the path analysis into a single **report**.

Everything for an engagement lives in one project folder (config, databases,
logs, reports, exports), so nothing scatters across the host.

## Scan vs. Analyze — what each covers

`analyze` and `scan` are two different approaches to examining AD attack
pathways. They overlap on the classic AD primitives, but neither depends on the
other — run both:

- **`analyze run`** works against the **offline database built from a
  collection**. Once the data is collected (or imported), you can run and re-run
  analysis as many times as you like — try different owned principals, scopes,
  and categories — **without any further connection to the server**. It emits
  what is an **edge in the attack graph**: a privilege or relationship that
  moves an attacker toward Tier Zero.
- **`scan run`** performs **live checks against a running server** and **does
  not require a collection — it stands on its own**. It grades the environment
  into **findings**, including configuration/hygiene posture and on-the-wire
  protocol state (LDAP/SMB/DNS) that no attack-graph edge would ever capture.

|                | `analyze` (graph)                        | `scan` (assessment)                          |
|----------------|------------------------------------------|----------------------------------------------|
| Input          | collected / imported data — **offline**  | **live** LDAP/SMB/DNS (+ optional collection) |
| Emits          | escalation **edges → Tier Zero**         | graded **findings** (posture + hygiene)      |
| Best for       | "how do I get to DA/Global Admin?"       | "how healthy is this domain?"                |

### Only `scan` finds

Things with no attack-graph edge, so `analyze` never surfaces them:

- **Live protocol / network posture** — SMB signing (`net_001`), LDAP signing &
  channel binding (`proto_001`/`005`), NTLMv1 (`proto_006`), legacy OS
  (`proto_004`), print spooler on DCs (`proto_007`), authentication-coercion
  exposure (`proto_008`), LAPS deployment coverage (`proto_003`).
  *(analyze uses coercion/spooler as path mechanics, but never reports the
  exposure itself.)*
- **Domain / forest configuration** — password policy & fine-grained policies
  (`pwd_001`/`002`), FRS-vs-DFSR, functional level, AD Recycle Bin, tombstone
  lifetime (`infra_001`–`004`), ADIDNS wildcard & zone permissions
  (`infra_005`/`006`).
- **Kerberos hygiene** — KRBTGT password age (`kerb_004`), RC4/legacy encryption
  (`kerb_006`), duplicate SPNs (`kerb_007`).
- **Account hygiene** — passwords in description (`hygiene_001`), stale
  privileged / computer accounts (`hygiene_004`/`010`), guest enabled
  (`hygiene_008`), default-admin hygiene (`hygiene_009`), smartcard-but-reusable-hash
  (`hygiene_012`), and **existing** shadow-credential injections (`hygiene_006`
  — analyze only flags who *can write* `msDS-KeyCredentialLink`).
- **Privileged-access posture** — Protected Users coverage (`priv_003`),
  PrivExchange (`priv_005`), Pre-Windows 2000 Compatible Access (`priv_006`),
  privileged-group sprawl (`priv_007`), DNSAdmins (`priv_008`).
- **GPO (SYSVOL / hygiene)** — GPP cpassword / MS14-025 (`gpo_003`), unlinked
  GPOs (`gpo_004`), login/startup scripts (`gpo_005`).
- **ADCS** — ESC14, ESC15 (`adcs_010`/`011`) plus long-validity and CRL
  advisories (`adcs_012`/`013`). *(analyze's ADCS covers ESC1–4, 9, 10, 13 from
  a DCOnly collection, and adds the CA-host ESCs — ESC6, ESC7, ESC8, ESC11 —
  once the collection is enriched with [`collect adcs`](#collect); only
  ESC14/ESC15 and the advisories stay scan-only.)*
- **Trust hygiene** — orphaned foreign security principals (`trust_002`).
- **Patch-level CVE advisories** — ZeroLogon (`patch_001`) and Bronze Bit
  (`patch_002`), plus PrintNightmare context on the spooler check. These are
  INFO advisories: patch state isn't visible over LDAP, so they flag the
  precondition and tell you what to verify rather than asserting vulnerability.

### Only `analyze` finds

Graph reasoning that `scan` does not do: **shortest / arbitrary attack paths**
to Tier Zero, **blast radius** from owned principals, **cross-correlated
compound risks**, and **Azure/Entra + hybrid-sync** escalation paths (Global-Admin
roles, app/SP ownership, synced on-prem users holding privileged Entra roles).

### Both find

The core AD primitives, from opposite angles (an edge vs. a graded finding):
ADCS ESC1–4/6–11/13 (analyze's CA-host ESC6/7/8/11 via `collect adcs`),
DCSync, all three delegation types, kerberoast, AS-REP,
LAPS/gMSA read ACLs, GPO edit-permission abuse, SID history, DA membership,
AdminSDHolder ACLs, MachineAccountQuota, `PASSWD_NOTREQD`, orphaned `adminCount`,
reversible encryption, DES-only, `DONT_EXPIRE_PASSWORD`, and trust SID filtering.

## Feature highlights

### Collect
- **Native LDAP collector** for on-prem AD, with three **stealth pacing
  profiles** (`--stealth low|medium|high`) that spread queries out to lower the
  request rate a DC sees — all three collect the same full dataset
  ([details](#stealth-pacing-collect-run)).
- **Native Entra ID collection over Microsoft Graph** — supplied-credential
  (ROPC), **device-code** sign-in (MFA-friendly), or a service principal. The
  user flows need **no app registration**.
- **SMB session / local-admin enumeration** (`crawl`) for `AdminTo`, `CanRDP`,
  `ExecuteDCOM`, `CanPSRemote`, and active-session edges. **Incremental &
  resumable** — a persisted tracker skips already-collected hosts across runs
  (`--recheck` forces a re-crawl), and the summary separates *this run* from the
  *cumulative* totals ([details](#incremental-crawling)).
- **CA-host ADCS enrichment** (`collect adcs`) — actively probes each CA
  (HTTP web enrollment for **ESC8**; the CA registry for **ESC6** EDITF, **ESC11**
  RPC encryption, **ESC7** CA role-security) and merges the result into the
  collection, so `analyze`/`report` surface those CA-host ESCs **offline** —
  the SharpHound-CARegistry analog. `collect run` stays strictly DCOnly; this is
  the opt-in, host-touching step (or chain it inline with **`collect run
  --adcs`**). Degrades gracefully when Remote Registry is off (keeps the ESC8
  result). Marks the collection `DCOnly+ADCS`.
- **One-shot enrichment** — **`collect run --adcs --network`** runs the DCOnly
  collection, then automatically chains the ADCS enrichment and/or the full SMB
  network crawl, leaving a `DCOnly+ADCS+Network` collection in one command.
- **Import & export** BloodHound CE (`.zip`) and AzureHound (`.json`); mix
  collected and imported data freely.
- **Forest and hybrid** collections — multiple AD domains plus an Entra tenant
  in one dataset.
- **`--nodisabled`** on `run` / `import` / `azure` drops disabled accounts
  (AD `ACCOUNTDISABLE`, Entra `accountEnabled=false`), and **`--slim`** trims
  object properties to just the fields analysis/scan/search read — both keep
  attack-path results identical while shrinking large collections.

#### Stealth pacing (`collect run`)

`collect run` is a **DCOnly** LDAP collection — it talks only to the Domain
Controller, never to member hosts. The `--stealth` flag picks one of three
pacing profiles. **All three collect exactly the same full dataset** — full
security descriptors (OWNER + GROUP + DACL) and the full attribute set — so
every level yields a complete, analysable collection. They differ only in how
fast pages are pulled and in two optional *active* side-lookups that reach
beyond the bound LDAP session:

| Knob | `low` (default) | `medium` | `high` |
|---|---|---|---|
| LDAP delay / jitter | none | 0.3s ±20% | 1.0s ±30% |
| LDAP page size | 1000 | 500 | 300 |
| ADCS HTTP probe (ESC8) | on | off | off |
| GC / Kerberos SRV lookups | on | off | off |
| Data collected | full | full | full |

- **LDAP pacing** inserts a randomised delay between each page fetch and shrinks
  the page size, spreading the *same* queries over more wall-clock time. This
  lowers the per-second request rate a DC (or its monitoring) sees; it does not
  change *what* is collected.
- **ADCS HTTP probe** is the ESC8 web-enrollment check — an active HTTP request
  to the CA. **GC / Kerberos SRV lookups** are extra DNS SRV queries beyond core
  collection. Both are quality-of-life extras that touch things outside the LDAP
  session, so `low` keeps them for coverage while `medium` and `high` drop them.

Pick `low` when noise isn't a concern (fastest), `medium` for a lighter LDAP
footprint, and `high` when you want the lowest sustained request rate — none of
them sacrifices data. The active banner shows the profile in effect, e.g.
`Stealth: MEDIUM — LDAP 0.3s, page 500, no SRV lookups, no ADCS probe`.

> **Note:** these profiles govern `collect run` only. Host-touching SMB
> session / local-admin enumeration is the separate **`collect crawl`** command,
> which has its own throttles (`--batch-size`, `--smb-workers`, `--smb-timeout`)
> and ignores `--stealth`.

#### Incremental crawling

`collect crawl` is **incremental and resumable**. A tracker persisted with the
collection records which hosts have already been enumerated, so re-running the
command **skips already-collected hosts** (you'll see `Skipping N
already-collected`) and only touches what's new. Pass **`--recheck`** to force a
re-crawl of hosts that were already done. Large jobs can also run detached with
**`--background`** and be steered with `collect crawl status | pause | resume |
stop`.

Because of that, the completion summary reports **two different scopes**, each
labelled so they don't read as contradictory:

| Line | Scope |
|---|---|
| `Crawl complete (this run): …` | Only the hosts crawled *just now* (plus how many were skipped this run). |
| `Cumulative (all runs): …` | The persisted tracker across *every* crawl of the loaded collection. |

So a follow-up run that skips the only reachable host can legitimately show
`0/N reachable` **this run** while the cumulative line still counts that host as
reachable — the totals describe different things, not a discrepancy. Use
`collect clear --all` to wipe crawl-derived data and the tracker if you want a
clean re-crawl.

### Analyze — graph-based, BloodHound-style
**33 built-in checks** build an attack graph and surface paths to Tier Zero:

- **ACL abuse** — `GenericAll`, `WriteDACL`, `WriteOwner`, extended rights,
  `WriteProperty`, and object **ownership** on high-value targets.
- **ADCS** — certificate-template abuse **ESC1–ESC13**, GoldenCert, WritePKI,
  plus **Certifried (CVE-2022-26923)**. The CA-host ESCs (**ESC6/ESC7/ESC8/ESC11**)
  surface after enriching the collection with
  [`collect adcs`](#collect); the template/directory ESCs come straight
  from a DCOnly `collect run`.
- **DCSync** replication rights (`GetChanges` + `GetChangesAll`), with
  group-held rights expanded to the member principals that inherit them.
- **Delegation** — unconstrained (TGT capture), constrained (S4U2Proxy /
  protocol transition), and **RBCD**.
- **Kerberos** — kerberoastable and AS-REP-roastable accounts.
- **dMSA / BadSuccessor** (Server 2025) and **noPac / Certifried** exposure via
  MachineAccountQuota.
- **GPO / OU control**, AdminSDHolder, LAPS / gMSA password-read access, nested
  DA-equivalent group membership, dangerous configs (`PASSWD_NOTREQD`, orphaned
  `adminCount`, MachineAccountQuota), and trust / SID-history abuse.
- **Azure / Entra** — Global-Admin-equivalent roles, app/SP ownership abuse,
  **managed-identity** abuse (a resource running as a privileged identity),
  **dynamic-group** privilege abuse (rule-based membership to a privileged role),
  **Conditional Access** posture gaps (unenforced policies, privileged
  exclusions, legacy auth, no tenant-wide MFA), **federated-domain / Golden
  SAML** exposure, Entra **Seamless SSO** (`AZUREADSSOACC$`) risk, **inbound
  cross-tenant sync** backdoors, **AU-scoped privileged roles**, and
  **hybrid-sync** paths (a synced on-prem user holding a privileged Entra role).
- **Shortest paths**, ad-hoc reachability queries, blast-radius from owned
  principals, and cross-correlated compound risks.
- **Graphic exports** — SVG / PNG / Mermaid / DOT, styled to read like
  BloodHound.

### Scan — live security assessment
**76 checks** across 11 categories: Kerberos, Delegation, Password Policy,
Account Hygiene, Privileged Access, ADCS, GPO, Protocol Security, DNS,
Infrastructure, and Trust. Graded into findings, collection-aware when a
collection is loaded, diffable across runs, and exportable.

**Customizable scoring/grading.** The 0–100 risk score and A/B/C/D/F grade are
tunable per project. Pick a preset (`strict` / `balanced` / `lenient`) and
override any of the A/B/C/D grade thresholds, the curve/coefficient, the health
blend, per-severity points, or per-category weights in the `scoring:` section of
`lazyhound.yml`. `scan scoring` shows the model in effect; `scan run --profile
<name>` overrides the profile for a single run.

### Search — interactive exploration
Realm-aware queries that resolve both AD and Entra objects (roles, group
membership, ownership): `info`, `members`, `memberof`, `acl`, `who-can`,
`search`, `kerberoastable`, `delegation-map`, `computers`, `trusts`,
`templates`, `spns`, `graph`, and detailed `stats`.

### Report
`run` builds a report from the loaded data. `--type` picks the source (each uses
exactly one, in memory):

- **`analyze`** (default) — the attack-path report from the `analyze run`
  findings. A red/blue report that opens with a **visual dashboard** (a **MITRE
  ATT&CK attack chain** flowing through the observed tactics to Tier Zero, a
  severity distribution, and a techniques-by-tactic chart — all inline/offline,
  PDF-safe), then the ATT&CK technique matrix, the paths to Tier Zero, and
  per-technique **offensive** (how to abuse, with tools) and **defensive**
  (remediate + detect) playbooks.
- **`scan`** — the security-scan findings (the scan's own report).

`--format html|pdf|markdown` and `--style 1-5` (style 1 is a modern, clean
theme) control rendering; **PDF** renders via WeasyPrint (`[reports]` extra).
Reports default to `./reports/` and data/graphic exports to `./exports/`
(both created under the project
folder); pass `-o` for a custom path.

**Editable report templates.** On first run, LazyHound drops a Markdown
template for every report type into the project's `templates/` folder
(`scan.md`, `analyze.md`, `heatmap.md`, …). Each is plain Markdown you can edit
to **rebrand and reshape** the report — no code:

- A **settings block** (YAML front-matter) sets the title and colors
  (`accent_color`, `critical_color`, `background`, …) and points `logo:` at an
  image in `templates/assets/` (embedded into HTML/PDF as a data URI).
- The **body** is yours: add cover text, scope, a confidentiality banner,
  client notes, or any prose/sections, using `{{placeholder}}` tokens
  (`{{domain}}`, `{{date}}`, `{{finding_count}}`, `{{critical_count}}`,
  `{{rating}}`, …). `{{content}}` marks where the generated report is injected.

Colors and the logo apply to **HTML/PDF**; Markdown output keeps the prose and
logo reference. Anything left out falls back to the built-in default, so an
unedited (or deleted) template reproduces the original report exactly.

## What it finds

The complete finding inventory: **33 graph checks** (`analyze`) and **75 live
checks** (`scan`).

### Analyze — attack-graph findings (33)

**ACL & ownership**
- ACL-based privilege escalation — `GenericAll`, `WriteDACL`, `WriteOwner`, extended rights, `WriteProperty`
- Object ownership abuse on high-value targets
- Targeted kerberoasting via `WriteSPN`

**ADCS (certificates)**
- Certificate-template abuse — ESC1–ESC13, GoldenCert, WritePKI
- CA-host ESCs — ESC8 (HTTP web enrollment), ESC6 (EDITF), ESC11 (RPC
  encryption), ESC7 (CA role-security) — after `collect adcs` enrichment
- Certifried (CVE-2022-26923) — `dNSHostName` SAN abuse via MachineAccountQuota

**Kerberos & delegation**
- Kerberoastable accounts (SPN on non-computer accounts)
- AS-REP roastable accounts (pre-auth not required)
- Unconstrained delegation (TGT capture)
- Constrained delegation (S4U2Proxy / protocol transition)
- Resource-based constrained delegation (S4U2Self/S4U2Proxy)

**Replication & credential read**
- DCSync / replication rights (`GetChanges` + `GetChangesAll`), expanded to member principals
- LAPS password-read access (`ms-Mcs-AdmPwd`, `ms-LAPS-Password`)
- gMSA managed-password read (`msDS-ManagedPassword`)

**Group, GPO, OU & config**
- Nested group-membership paths to DA-equivalent groups
- GPO abuse (modification rights, linking, inheritance)
- OU control and AdminSDHolder abuse
- Dangerous configurations (`PASSWD_NOTREQD`, orphaned `adminCount`, MAQ, reversible/DES, `DONT_EXPIRE`)
- dMSA takeover / BadSuccessor (Server 2025 delegated-MSA succession)

**Trust, sessions & access**
- Trust / forest-trust abuse (SID history, SID filtering)
- Session abuse — high-value users with active sessions
- Local group access — `AdminTo`, `CanRDP`, `ExecuteDCOM`, `CanPSRemote`

**Graph reasoning**
- Shortest attack paths to high-value targets
- Blast radius from owned/compromised principals (`--owned`)
- Cross-correlated compound risks

**Azure / Entra**
- Global-Admin-equivalent role holders
- App/SP ownership abuse (credential-addition takeover)
- Managed-identity abuse (resource running as a privileged identity)
- Dynamic-group privilege abuse (rule-based membership to a privileged role)
- Conditional Access posture gaps (unenforced policies, exclusions, legacy auth, no tenant-wide MFA)
- Federated-domain / Golden SAML exposure
- Seamless SSO (`AZUREADSSOACC$`) Silver-ticket-to-cloud exposure
- Inbound cross-tenant synchronization backdoors
- Administrative-unit-scoped privileged roles
- Hybrid-sync paths (synced on-prem user holding a privileged Entra role)

### Scan — live security findings (75, across 11 categories)

**ADCS (14)** — ESC1 (`adcs_001`), ESC3 (`adcs_002`), ESC8 web enrollment (`adcs_003`), ESC4/5/7 ACL audit (`adcs_004`), ESC2 any-purpose/SubCA (`adcs_005`), ESC6 `EDITF_ATTRIBUTESUBJECTALTNAME2` (`adcs_006`), ESC9 no-security-extension (`adcs_007`), ESC11 unencrypted RPC (`adcs_008`), ESC13 issuance-policy (`adcs_009`), ESC14 weak mappings (`adcs_010`), ESC15 schema-v1 (`adcs_011`), long cert validity (`adcs_012`), CA CRL advisory (`adcs_013`), **CertiGhost CVE-2026-54121 advisory** (`adcs_014`)

**Kerberos (9)** — kerberoastable (`kerb_001`), AS-REP roastable (`kerb_002`), DES-only (`kerb_003`), KRBTGT password age (`kerb_004`), non-expiring privileged passwords (`kerb_005`), RC4/legacy encryption (`kerb_006`), duplicate SPNs (`kerb_007`), constrained delegation to sensitive services (`kerb_008`), delegation on privileged accounts (`kerb_009`)

**Delegation (4)** — unconstrained (`deleg_001`), constrained w/ protocol transition (`deleg_002`), RBCD (`deleg_003`), Bronze Bit advisory CVE-2020-17049 (`patch_002`)

**Account Hygiene (12)** — passwords in description (`hygiene_001`), reversible encryption (`hygiene_002`), password-not-required (`hygiene_003`), stale privileged accounts (`hygiene_004`), AdminSDHolder orphans (`hygiene_005`), shadow credentials (`hygiene_006`), SID history injection (`hygiene_007`), guest enabled (`hygiene_008`), default-admin hygiene (`hygiene_009`), stale computers (`hygiene_010`), service accounts in DA (`hygiene_011`), smartcard-but-reusable-hash (`hygiene_012`)

**Privileged Access (11)** — Domain Admin membership (`priv_001`), DCSync permissions (`priv_002`), Protected Users (`priv_003`), AdminSDHolder ACL audit (`priv_004`), PrivExchange (`priv_005`), Pre-Windows 2000 access (`priv_006`), privileged-group sprawl (`priv_007`), DNSAdmins abuse (`priv_008`), computers in privileged groups (`priv_009`), gMSA password readers (`priv_010`), LAPS password ACL audit (`priv_011`)

**Protocol Security (10)** — SMB security probes (`net_001`), LDAP signing (`proto_001`), Machine Account Quota (`proto_002`), LAPS deployment (`proto_003`), legacy OS (`proto_004`), LDAP channel binding (`proto_005`), NTLMv1 advisory (`proto_006`), Print Spooler on DCs / PrintNightmare (`proto_007`), authentication-coercion exposure (`proto_008`), ZeroLogon advisory CVE-2020-1472 (`patch_001`)

**GPO (5)** — GPO security review (`gpo_001`), broad edit permissions (`gpo_002`), GPP cpassword / MS14-025 (`gpo_003`), unlinked GPOs (`gpo_004`), login/startup scripts (`gpo_005`)

**Infrastructure (4)** — FRS vs DFSR (`infra_001`), domain functional level (`infra_002`), AD Recycle Bin (`infra_003`), tombstone lifetime (`infra_004`)

**Trust (3)** — SID filtering (`trust_001`), orphaned foreign security principals (`trust_002`), inbound trust w/ TGT delegation (`trust_003`)

**DNS (2)** — ADIDNS wildcard records (`infra_005`), ADIDNS zone permissions (`infra_006`)

**Password Policy (2)** — domain password policy (`pwd_001`), fine-grained password policies (`pwd_002`)

## Install

### From PyPI (recommended)

```bash
pip install lazyhound            # add --break-system-packages on externally-managed Python
```

This pulls the latest release from [PyPI](https://pypi.org/project/lazyhound/)
and puts the **`lazyhound`** command on your `PATH`. Then scaffold a project and
launch the shell:

```bash
lazyhound init /opt/engagements/acme    # scaffold a project folder
cd /opt/engagements/acme
lazyhound                               # launch the interactive shell
```

Prefer an isolated install (no system-Python conflicts, no
`--break-system-packages`)? Use [pipx](https://pipx.pypa.io/):

```bash
pipx install lazyhound
```

To include the optional PDF/DOCX report formats, install the `reports` extra
(or `all`):

```bash
pip install 'lazyhound[reports]'        # adds PDF (WeasyPrint) and DOCX (python-docx)
```

### From source (development / latest `main`)

Clone the repo and install editable to hack on LazyHound or run an unreleased
`main`:

```bash
git clone https://github.com/renmizo/lazyhound
cd lazyhound
pip install -e .                 # add --break-system-packages on externally-managed Python
pip install -e '.[reports]'      # optional: PDF + DOCX report formats
```

Requires **Python 3.10+**. Core dependencies (Rich, Click, ldap3, impacket,
dnspython, pycryptodome, Pillow, requests) install automatically either way.

## Dependencies

Runtime: **Python 3.10+**. The core libraries below install automatically with
`pip install -e .`; report formats and the Graphviz image export are optional.

### Core (required)

| Library | Min | Purpose |
|---------|-----|---------|
| [click](https://pypi.org/project/click/) | 8.1 | CLI framework — commands, options, the `lazyhound` entry point |
| [rich](https://pypi.org/project/rich/) | 13.0 | Terminal UI — tables, panels, colour, the animated banner |
| [PyYAML](https://pypi.org/project/PyYAML/) | 6.0 | Load/save the project `lazyhound.yml` config |
| [ldap3](https://pypi.org/project/ldap3/) | 2.9 | LDAP connector — AD collection and the live scan |
| [impacket](https://pypi.org/project/impacket/) | 0.11 | SMB / Kerberos / LDAP protocol ops (collectors, `crawl`) |
| [dnspython](https://pypi.org/project/dnspython/) | 2.4 | DNS resolution and ADIDNS checks |
| [pycryptodome](https://pypi.org/project/pycryptodome/) | 3.19 | Crypto primitives (e.g. GPP `cpassword` decryption) |
| [Pillow](https://pypi.org/project/Pillow/) | 10.0 | Image compositing for attack-graph exports (icons, PNG) |
| [requests](https://pypi.org/project/requests/) | 2.28 | Microsoft Graph HTTP client — live Entra collection |

### Optional — reports (`pip install -e '.[reports]'`)

| Library | Min | Purpose |
|---------|-----|---------|
| [python-docx](https://pypi.org/project/python-docx/) | 1.0 | DOCX report export |
| [WeasyPrint](https://pypi.org/project/weasyprint/) | 60.0 | PDF report export |
| [Markdown](https://pypi.org/project/Markdown/) | 3.5 | Markdown → HTML for HTML reports |

### Optional — Kerberos LDAP (`pip install gssapi`)

| Library | Min | Purpose |
|---------|-----|---------|
| [gssapi](https://pypi.org/project/gssapi/) | 1.8 | Kerberos (ccache) auth for the **LDAP** paths (`collect run`, `scan run`). Needs system krb5 libraries. |

Not required for password / pass-the-hash, nor for Kerberos on `collect crawl`
(SMB, which uses impacket). Missing it yields a clear install hint, not a crash.

### Optional — external (non-Python)

- **Graphviz** (`dot` binary) — renders attack-graph **PNG / SVG** image
  exports. If it isn't on `PATH`, LazyHound writes the `.dot` source instead
  and tells you how to render it later, so nothing hard-fails.

Everything else (SQLite history DBs, `readline`, `termios`, `subprocess`,
`concurrent.futures`) is from the Python standard library.

## Quick start

```bash
lazyhound init /opt/engagements/acme   # scaffold a project folder
cd /opt/engagements/acme
lazyhound                              # launch the interactive shell
```

`init` writes `lazyhound.yml` plus `logs/`, `reports/`, `exports/`,
`templates/`, and the history databases, all inside the project folder.

Then, in the shell:

```
options dc=10.0.0.10 domain=corp.local username=administrator   # target + identity

# Pick ONE credential (they are mutually exclusive — the last one set wins):
options password=P@ssw0rd                                   # password
options nthash=aad3b435b51404eeaad3b435b51404ee:<nt-hash>   # pass-the-hash (bare 32-hex or LM:NT)
options ccache=/tmp/administrator.ccache                    # Kerberos (see below)

collect run                               # LDAP collection from a DC
collect run --stealth high                # same data, slow/low-rate LDAP queries (see Stealth pacing)
collect azure --run --tenant <t> --username <upn>   # live Entra collection (device-code by default)
collect import ./bloodhound.zip           # or import BloodHound / AzureHound data

analyze run                               # build the attack graph
analyze shortest --from bob               # shortest paths to Tier Zero
analyze run --notier0                     # hide Tier-Zero-actor / low-signal findings (shown by default)
analyze paths --category dcsync,adcs      # filtered findings summary
analyze export --category laps_read --format png    # BloodHound-styled graphic

search info administrator                 # inspect an object
search who-can WriteDacl "domain admins"  # who holds a right on a target
search custom name=svc*                   # open attribute search

scan run                                  # live security assessment (76 checks)
report run                                # analyze report — red/blue attack paths (MITRE ATT&CK)
report run --type scan --format pdf       # the scan findings as a PDF
```

## Authentication

`collect run`, `collect crawl`, and `scan run` all support the same three,
**mutually exclusive** credential types — set one via `options` and it clears
the others:

| Method | Set with | Notes |
|---|---|---|
| **Password** | `options password=<pw>` | NTLM (or SIMPLE) bind. |
| **Pass-the-hash** | `options nthash=<hash>` | Bare 32-hex NT hash or a full `LM:NT` pair. Forces an NTLM bind. |
| **Kerberos** | `options ccache=<file>` | Uses a credential cache (TGT). Forces GSSAPI. |

**Kerberos details:** obtain a TGT first (e.g. `kinit`, or impacket's
`getTGT.py`) and point `ccache` at the resulting cache file. LazyHound connects
to the DC by **FQDN** (for the SPN) and auto-generates a `krb5.conf` mapping the
realm to your DC, so no manual `/etc/krb5.conf` is required (a self-provided
`KRB5_CONFIG` is respected). The **LDAP** paths (`collect run` / `scan run`)
need the optional [`gssapi`](https://pypi.org/project/gssapi/) package plus
system krb5 libraries; **`collect crawl`** (SMB) uses impacket and needs no
extra package.

## The interactive shell

The shell is a single flat menu with five workflow verbs (`collect`, `analyze`,
`scan`, `report`, `search`). **Typing a bare verb shows its subcommands**;
launching is explicit — you run the primary action with `run` (`analyze run`,
`collect run`) and use a subcommand for supporting actions (`analyze paths`,
`collect load`, `search info`). Global commands work anywhere:

- **`?`** or **`help`** — show the main menu; **`help <verb>`** lists a verb's
  subcommands (`help analyze`).
- **`<verb> [sub] --help`** — detailed help for a verb.
- **`domain`** — show or switch the active realm (see below).
- Verbs and subcommands resolve by shortest unique prefix (e.g. `ana sh` →
  `analyze shortest`).
- Note: launching is always explicit — `analyze` alone lists subcommands,
  `analyze run` launches. Open attribute search is `search custom <filter>`.

The banner reverse-dissolves into view on launch and on `version`.

## Command reference

**Main menu**

| Command | What it does |
|---------|--------------|
| `collect` | Collect AD (LDAP) & Entra (Graph), or import/export BloodHound & AzureHound |
| `scan` | Live security assessment (76 checks) |
| `search` | Explore collected AD & Entra data |
| `analyze` | Graph-based attack-path analysis |
| `report` | Report generation |
| `options` | View/set connection & settings |
| `domain` | Show/switch the active realm |

**collect**

| Command | What it does |
|---------|--------------|
| `run` | LDAP collection from a DC (`--stealth low\|medium\|high` — see [Stealth pacing](#stealth-pacing-collect-run)) |
| `crawl` | Session + local-group enumeration via SMB |
| `adcs` | CA-host ADCS enrichment (ESC6/7/8/11) of the loaded collection |
| `azure` | Live Entra collection via Graph, or import AzureHound JSON |
| `import` / `export` | BloodHound `.zip` / AzureHound `.json` / raw |
| `load` / `unload` / `list` / `delete` | Manage stored collections |
| `stats` | Quick collection summary |
| `clear` | Strip session / local-admin data |

**analyze**

| Command | What it does |
|---------|--------------|
| `run` | Build the attack graph and run all checks (`--notier0`, `--owned`, `--category`, `--checks`, `--exclude`, `--domain`, plus the scale controls `--prune` / `--aggregate` / `--noexpand` / `--expand-cap` below) |
| `shortest` | Shortest attack paths to DA / high-value targets (`--from`) |
| `trace` | Shortest path(s) to any target object |
| `paths` | Findings summary; `--show` for full tables, `--category a,b` to filter |
| `find` | Ad-hoc graph query by attribute / reachability |
| `graph` | Render a diagram in the terminal (ASCII) |
| `export` | Export analysis / diagrams — `--category`/`--severity` draws those findings, `--from` scopes a path to its nearest Tier-Zero target |
| `checks` | List available analysis checks |

*Large environments* (100k+ objects, millions of ACL edges) — two opt-in scale
controls on `analyze run`, off by default so normal runs are unchanged:
- **`--prune`** keeps only findings whose principal can actually reach Tier Zero
  (drops the dead-end subgraph).
- **`--aggregate <slug,...>`** collapses per-object findings in the named
  finding-categories into one-per-`(principal, right, target-class)` with a
  count + sample — e.g. `analyze run --prune --aggregate acl_abuse,dcsync` turns
  millions of `X has GenericAll on <object>` findings into `X has GenericAll on
  4,213 user objects`. For `acl_abuse` this rolls up **inline during the scan**
  (accumulating counts, not millions of finding objects), so peak memory stays
  bounded on huge collections. Slugs match `paths --category`. A category you
  aggregate is **not** member-expanded (see `--noexpand`) — the roll-up is the
  point, so re-exploding it would defeat the flag.
- **`--noexpand`** skips the group-member expansion phase entirely. Normally a
  group holding a dangerous right is exploded into one finding per transitive
  member; on very large forests that phase dominates runtime and can produce
  millions of findings. `--noexpand` omits those effective-member findings —
  **attack paths are unaffected** (they come from the graph BFS, not
  expansion), and you can still see effective holders via `search members`.
- **`--expand-cap N`** bounds the group-member expansion instead of skipping it.
  Expansion projects how many per-member findings it would emit and, above `N`
  (default **250,000**), rolls those up into one finding per
  `(member, right, target-class)` with a count — keeping peak memory bounded
  instead of OOMing on very large forests. `--expand-cap 0` forces full
  per-member output (use only when you have the RAM). Also settable via the
  `LAZYHOUND_EXPAND_CAP` environment variable (the flag wins). When rollup
  engages, the run prints a one-line notice; below the cap, output is unchanged.

**search**

`info` · `members` · `memberof` · `acl` · `who-can` · `search` ·
`kerberoastable` · `delegation-map` · `computers` · `trusts` · `templates` ·
`spns` · `graph` · `stats`

**scan**

`run` · `checks` · `list` · `show` · `delete` · `diff` · `export` · `options`

**report**

| Command | What it does |
|---------|--------------|
| `run` | Build a report from the loaded analyze **or** scan data — `--type analyze\|scan` (default analyze), `--format html\|pdf\|markdown`, `--style 1-5`, `-o` |

Every menu can also jump to any of `collect` / `search` / `analyze` / `scan` /
`report` (and `domain`), so the five verbs are always one word away.

## Realm scoping (forests & tenants)

Multi-domain forests and Entra tenants are first-class **realms**. `domain`
shows every realm in the current dataset (always by FQDN — `child.corp.local`,
`mydomain.local`) and switches the active one. Every search/analyze command
accepts `--domain all | <fqdn>`, so you can pivot a single query across a whole
forest or narrow it to one domain or tenant.

## Data interoperability

LazyHound reads and writes the formats teams already use:

| Direction | Format |
|-----------|--------|
| Import | BloodHound CE `.zip`, AzureHound `.json`, raw collections |
| Export (data) | BloodHound `.zip`, AzureHound `.json`, raw |
| Export (graphics) | SVG, PNG, Mermaid, DOT (BloodHound-styled) |
| Export (reports) | Markdown, JSON, HTML, CSV; PDF & DOCX with `[reports]` |

## Offline & OPSEC

- After collection or import, **analysis, search, path-finding, and reporting
  are fully offline** — no outbound calls, nothing leaves the host.
- Live network activity is confined to the explicit collectors: LDAP (`collect
  run`), SMB (`collect crawl`), Microsoft Graph (`collect azure --run`), and the
  live `scan`. Nothing else touches the network.
- **`collect run` is strictly DCOnly** — it talks only to the DC over LDAP.
  Host-touching is opt-in: `collect crawl` (SMB to member hosts) and
  `collect adcs` (HTTP + remote registry to the **CA host** only). The
  collection's method label records exactly what was touched
  (`DCOnly` / `DCOnly+ADCS` / `DCOnly+Network` / `DCOnly+ADCS+Network`).
- The LDAP collector paces its queries; the scanner honors include/exclude and
  category filters so you can keep runs targeted and quiet.
- All engagement data stays inside the project folder you `init`.

## Credits

Attack-path analysis is BloodHound-inspired and interoperates with SpecterOps'
BloodHound CE, SharpHound, and AzureHound data formats.

Inspired by:

- [BloodHound](https://github.com/SpecterOps/BloodHound) & [AzureHound](https://github.com/SpecterOps/AzureHound) (SpecterOps) — the attack-graph model and the on-prem/cloud data formats LazyHound reads and writes.
- [ADPulse](https://github.com/dievus/ADPulse) (dievus) — Active Directory security assessment.
- [BloodBash](https://github.com/DotNetRussell/BloodBash) (DotNetRussell).

## License

MIT — see [LICENSE](LICENSE).
