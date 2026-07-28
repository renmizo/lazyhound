"""Network collector — enumerates sessions and local groups across discovered computers.

Orchestrates parallel SMB/DCERPC enumeration of domain-joined computers to
collect data that LDAP alone cannot provide:

  - **Sessions**: Who is logged in where (HasSession edges)
  - **Local groups**: Who has local admin / RDP / DCOM / WinRM access
    (AdminTo, CanRDP, ExecuteDCOM, CanPSRemote edges)

This data enables BloodHound-style lateral movement path discovery.

The :class:`NetworkCollectionJob` orchestrator provides batched enumeration
with operator controls (pause, resume, stop, status) and target filtering
by computer category (DCs, servers, workstations) or OU.
"""

from __future__ import annotations

import enum
import json
import logging
import re
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..connectors.smb import (
    HostEnumResult,
    RID_TO_EDGE,
    enumerate_host,
    require_impacket,
)
from ..stealth import StealthConfig

logger = logging.getLogger(__name__)

# Default number of concurrent host scans
DEFAULT_WORKERS = 10
DEFAULT_TIMEOUT = 5
DEFAULT_BATCH_SIZE = 50

# UAC flag for domain controller (SERVER_TRUST_ACCOUNT)
_UAC_SERVER_TRUST = 0x2000


# ---------------------------------------------------------------------------
# Computer classification
# ---------------------------------------------------------------------------

class ComputerCategory(enum.Enum):
    """Classification of computer objects."""
    DOMAIN_CONTROLLER = "domain_controllers"
    SERVER = "servers"
    WORKSTATION = "workstations"


@dataclass
class ClassifiedComputer:
    """A computer object enriched with classification metadata."""
    name: str
    dns_hostname: str
    dn: str
    sid: str
    category: ComputerCategory
    operating_system: str
    ou: str  # immediate parent OU DN


def _extract_parent_ou(dn: str) -> str:
    """Extract the parent OU/container DN from an object's DN.

    For ``CN=SRV01,OU=Servers,OU=Corp,DC=test,DC=local`` returns
    ``OU=Servers,OU=Corp,DC=test,DC=local``.
    """
    parts = dn.split(",", 1)
    return parts[1] if len(parts) > 1 else dn


def _classify_computer(obj: dict) -> ClassifiedComputer:
    """Classify a single computer collection object."""
    props = obj.get("properties", {})
    uac = props.get("userAccountControl", 0)
    if isinstance(uac, str):
        try:
            uac = int(uac)
        except ValueError:
            uac = 0

    os_str = props.get("operatingSystem", "") or ""

    if uac & _UAC_SERVER_TRUST:
        category = ComputerCategory.DOMAIN_CONTROLLER
    elif re.search(r"(?i)server", os_str):
        category = ComputerCategory.SERVER
    else:
        category = ComputerCategory.WORKSTATION

    return ClassifiedComputer(
        name=obj.get("name", ""),
        dns_hostname=props.get("dNSHostName", "") or "",
        dn=obj.get("dn", ""),
        sid=obj.get("object_sid", "") or "",
        category=category,
        operating_system=os_str,
        ou=_extract_parent_ou(obj.get("dn", "")),
    )


def classify_computers(objects: list[dict]) -> list[ClassifiedComputer]:
    """Classify all computer objects from a collection.

    Returns a list of :class:`ClassifiedComputer` instances.
    """
    computers = [obj for obj in objects if obj.get("object_class") == "computer"]
    return [_classify_computer(c) for c in computers]


# ---------------------------------------------------------------------------
# OU hierarchy with computer counts
# ---------------------------------------------------------------------------

@dataclass
class OUNode:
    """A node in the OU tree, tracking computer counts."""
    dn: str
    name: str
    children: list[OUNode] = field(default_factory=list)
    computer_count: int = 0
    # Counts including all descendants
    total_computer_count: int = 0
    computers: list[ClassifiedComputer] = field(default_factory=list)


def build_ou_tree(
    classified: list[ClassifiedComputer],
    ou_objects: list[dict] | None = None,
) -> tuple[list[OUNode], dict[str, OUNode]]:
    """Build an OU hierarchy with computer counts.

    Args:
        classified: Classified computer objects.
        ou_objects: OU objects from the collection (optional, used to
            include empty OUs in the tree).

    Returns:
        Tuple of (root nodes, flat dn-to-node map).
    """
    nodes: dict[str, OUNode] = {}

    # Seed from OU objects if available
    if ou_objects:
        for ou in ou_objects:
            dn = ou.get("dn", "")
            name = ou.get("name", "") or _ou_name_from_dn(dn)
            if dn:
                nodes[dn.lower()] = OUNode(dn=dn, name=name)

    # Ensure every computer's parent OU exists
    for comp in classified:
        ou_dn = comp.ou
        key = ou_dn.lower()
        if key not in nodes:
            nodes[key] = OUNode(dn=ou_dn, name=_ou_name_from_dn(ou_dn))
        nodes[key].computer_count += 1
        nodes[key].computers.append(comp)

    # Wire parent-child relationships
    for key, node in list(nodes.items()):
        parent_dn = _extract_parent_ou(node.dn)
        parent_key = parent_dn.lower()
        if parent_key != key and parent_key in nodes:
            nodes[parent_key].children.append(node)

    # Compute total counts (bottom-up)
    visited: set[str] = set()

    def _total(node: OUNode) -> int:
        nkey = node.dn.lower()
        if nkey in visited:
            return node.total_computer_count
        visited.add(nkey)
        node.total_computer_count = node.computer_count + sum(
            _total(c) for c in node.children
        )
        return node.total_computer_count

    # Find root nodes (those whose parent is not in the tree)
    roots: list[OUNode] = []
    for key, node in nodes.items():
        parent_dn = _extract_parent_ou(node.dn)
        if parent_dn.lower() not in nodes or parent_dn.lower() == key:
            roots.append(node)

    for root in roots:
        _total(root)

    return roots, {n.dn.lower(): n for n in nodes.values()}


def _ou_name_from_dn(dn: str) -> str:
    """Extract a human-readable name from an OU/container DN."""
    first = dn.split(",", 1)[0]
    if "=" in first:
        return first.split("=", 1)[1]
    return first


def format_ou_tree(roots: list[OUNode], indent: int = 0) -> list[str]:
    """Format the OU tree as indented text lines.

    Returns a list of strings, one per line.
    """
    lines: list[str] = []
    for node in sorted(roots, key=lambda n: n.name.lower()):
        prefix = "  " * indent
        direct = node.computer_count
        total = node.total_computer_count
        if total != direct:
            lines.append(f"{prefix}{node.name}  ({direct} direct, {total} total)")
        elif direct > 0:
            lines.append(f"{prefix}{node.name}  ({direct})")
        else:
            lines.append(f"{prefix}{node.name}")
        lines.extend(format_ou_tree(node.children, indent + 1))
    return lines


# ---------------------------------------------------------------------------
# Target summary for operator
# ---------------------------------------------------------------------------

@dataclass
class TargetSummary:
    """Summary of classified computers for operator review."""
    all_computers: list[ClassifiedComputer]
    domain_controllers: list[ClassifiedComputer]
    servers: list[ClassifiedComputer]
    workstations: list[ClassifiedComputer]
    ou_roots: list[OUNode]
    ou_map: dict[str, OUNode]

    @property
    def total(self) -> int:
        return len(self.all_computers)


def summarize_targets(
    objects: list[dict],
) -> TargetSummary:
    """Build a complete target summary from collection objects.

    Classifies computers and builds the OU hierarchy.
    """
    classified = classify_computers(objects)
    ou_objects = [obj for obj in objects if obj.get("object_class") == "ou"]
    ou_roots, ou_map = build_ou_tree(classified, ou_objects)

    dcs = [c for c in classified if c.category == ComputerCategory.DOMAIN_CONTROLLER]
    servers = [c for c in classified if c.category == ComputerCategory.SERVER]
    workstations = [c for c in classified if c.category == ComputerCategory.WORKSTATION]

    return TargetSummary(
        all_computers=classified,
        domain_controllers=dcs,
        servers=servers,
        workstations=workstations,
        ou_roots=ou_roots,
        ou_map=ou_map,
    )


# ---------------------------------------------------------------------------
# NetworkCollectionJob — batched orchestrator with pause/resume/stop
# ---------------------------------------------------------------------------

class JobState(enum.Enum):
    """State machine for a network collection job."""
    PENDING = "pending"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    CANCELLED = "cancelled"


@dataclass
class BatchProgress:
    """Progress snapshot for a single batch."""
    batch_number: int
    total_batches: int
    hosts_in_batch: int
    completed_in_batch: int
    hosts_scanned_total: int
    hosts_total: int
    reachable: int
    sessions: int
    local_group_members: int


class NetworkCollectionJob:
    """Orchestrates batched network enumeration with operator controls.

    Usage::

        job = NetworkCollectionJob(
            targets=classified_computers,
            username="admin", password="...", domain="corp.local",
        )
        job.start()          # begins async enumeration
        job.pause()           # pauses after current batch
        job.resume()          # resumes
        job.stop()            # cancels, keeps partial results
        status = job.status() # returns current state + progress
        result = job.result   # NetworkCollectionResult when done
    """

    def __init__(
        self,
        targets: list[ClassifiedComputer],
        username: str,
        password: str,
        domain: str,
        nthash: str = "",
        ccache: str = "",
        collect_sessions: bool = True,
        collect_local_groups: bool = True,
        max_workers: int = DEFAULT_WORKERS,
        timeout: int = DEFAULT_TIMEOUT,
        batch_size: int = DEFAULT_BATCH_SIZE,
        tracker: EnumerationTracker | None = None,
        stealth: StealthConfig | None = None,
    ) -> None:
        self._stealth = stealth or StealthConfig()
        # Apply stealth overrides for concurrency
        if self._stealth.smb_workers is not None:
            max_workers = self._stealth.smb_workers
        if self._stealth.smb_batch_size is not None:
            batch_size = self._stealth.smb_batch_size
        self._targets = targets
        self._username = username
        self._password = password
        self._domain = domain
        self._nthash = nthash
        self._ccache = ccache
        self._collect_sessions = collect_sessions
        self._collect_local_groups = collect_local_groups
        self._max_workers = max_workers
        self._timeout = timeout
        self._batch_size = batch_size
        self._tracker = tracker

        self._state = JobState.PENDING
        self._state_lock = threading.Lock()
        self._pause_event = threading.Event()
        self._pause_event.set()  # not paused initially
        self._cancel_flag = threading.Event()

        self._result = NetworkCollectionResult()
        self._result.hosts_total = len(targets)
        self._current_batch = 0
        self._total_batches = max(1, (len(targets) + batch_size - 1) // batch_size)
        self._hosts_scanned = 0
        self._thread: threading.Thread | None = None
        self._batch_callback: Any = None  # callable(BatchProgress)

    @property
    def state(self) -> JobState:
        with self._state_lock:
            return self._state

    @property
    def result(self) -> NetworkCollectionResult:
        return self._result

    def set_batch_callback(self, callback: Any) -> None:
        """Set a callback invoked after each batch completes."""
        self._batch_callback = callback

    def start(self) -> None:
        """Start the enumeration in a background thread."""
        require_impacket()
        with self._state_lock:
            if self._state != JobState.PENDING:
                raise RuntimeError(f"Cannot start job in state {self._state.value}")
            self._state = JobState.RUNNING
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def start_blocking(self) -> NetworkCollectionResult:
        """Run the enumeration synchronously (blocks until complete)."""
        require_impacket()
        with self._state_lock:
            if self._state != JobState.PENDING:
                raise RuntimeError(f"Cannot start job in state {self._state.value}")
            self._state = JobState.RUNNING
        self._run()
        return self._result

    def pause(self) -> None:
        """Pause after the current batch finishes."""
        with self._state_lock:
            if self._state != JobState.RUNNING:
                return
            self._state = JobState.PAUSED
        self._pause_event.clear()

    def resume(self) -> None:
        """Resume a paused job."""
        with self._state_lock:
            if self._state != JobState.PAUSED:
                return
            self._state = JobState.RUNNING
        self._pause_event.set()

    def stop(self) -> None:
        """Cancel the job. Partial results are preserved."""
        self._cancel_flag.set()
        self._pause_event.set()  # unblock if paused
        with self._state_lock:
            if self._state in (JobState.RUNNING, JobState.PAUSED):
                self._state = JobState.CANCELLED

    def wait(self, timeout: float | None = None) -> None:
        """Block until the job finishes or *timeout* seconds elapse."""
        if self._thread:
            self._thread.join(timeout)

    def status(self) -> dict[str, Any]:
        """Return a snapshot of job progress."""
        return {
            "state": self.state.value,
            "batch": self._current_batch,
            "total_batches": self._total_batches,
            "hosts_scanned": self._hosts_scanned,
            "hosts_total": self._result.hosts_total,
            "hosts_reachable": self._result.hosts_reachable,
            "hosts_unreachable": self._result.hosts_unreachable,
            "sessions": self._result.total_sessions,
            "local_group_members": self._result.total_local_group_members,
            "batch_size": self._batch_size,
            "workers": self._max_workers,
        }

    def _run(self) -> None:
        """Internal: run all batches."""
        try:
            for batch_idx in range(self._total_batches):
                # Check cancellation
                if self._cancel_flag.is_set():
                    break

                # Check pause (blocks until resumed or cancelled)
                self._pause_event.wait()
                if self._cancel_flag.is_set():
                    break

                self._current_batch = batch_idx + 1
                start = batch_idx * self._batch_size
                end = min(start + self._batch_size, len(self._targets))
                batch_targets = self._targets[start:end]

                self._run_batch(batch_targets)
                self._hosts_scanned = end

                if self._batch_callback:
                    self._batch_callback(BatchProgress(
                        batch_number=self._current_batch,
                        total_batches=self._total_batches,
                        hosts_in_batch=len(batch_targets),
                        completed_in_batch=len(batch_targets),
                        hosts_scanned_total=self._hosts_scanned,
                        hosts_total=self._result.hosts_total,
                        reachable=self._result.hosts_reachable,
                        sessions=self._result.total_sessions,
                        local_group_members=self._result.total_local_group_members,
                    ))

            with self._state_lock:
                if self._state == JobState.RUNNING:
                    self._state = JobState.COMPLETED
        except Exception:
            logger.exception("Network collection job failed")
            with self._state_lock:
                self._state = JobState.CANCELLED

    def _run_batch(self, targets: list[ClassifiedComputer]) -> None:
        """Enumerate a single batch of hosts."""
        stealth = self._stealth

        def _scan(comp: ClassifiedComputer) -> HostEnumResult:
            # Stealth: pace between SMB connections
            stealth.smb_pace()
            host = comp.dns_hostname or comp.name.rstrip("$")
            return enumerate_host(
                host=host,
                username=self._username,
                password=self._password,
                domain=self._domain,
                nthash=self._nthash,
                ccache=self._ccache,
                collect_sessions=self._collect_sessions,
                collect_local_groups=self._collect_local_groups,
                timeout=self._timeout,
            )

        with ThreadPoolExecutor(max_workers=self._max_workers) as pool:
            futures = {pool.submit(_scan, comp): comp for comp in targets}
            for future in as_completed(futures):
                if self._cancel_flag.is_set():
                    pool.shutdown(wait=False, cancel_futures=True)
                    break
                try:
                    hr = future.result()
                    self._result.host_results.append(hr)
                    if hr.reachable:
                        self._result.hosts_reachable += 1
                    else:
                        self._result.hosts_unreachable += 1
                    self._result.total_sessions += len(hr.sessions)
                    self._result.total_local_group_members += len(hr.local_group_members)
                    # Track what was collected
                    if self._tracker:
                        self._tracker.record(
                            hr.hostname,
                            reachable=hr.reachable,
                            sessions=hr.reachable and self._collect_sessions,
                            local_groups=hr.reachable and self._collect_local_groups,
                        )
                except Exception as exc:
                    comp = futures[future]
                    logger.warning("Host scan failed for %s: %s", comp.name, exc)
                    self._result.hosts_unreachable += 1
                    if self._tracker:
                        host = comp.dns_hostname or comp.name.rstrip("$")
                        self._tracker.record(host, reachable=False,
                                             sessions=False, local_groups=False)


# ---------------------------------------------------------------------------
# Enumeration tracker — records per-host collection state
# ---------------------------------------------------------------------------

@dataclass
class HostEnumRecord:
    """Tracks what was collected from a single host and when."""
    hostname: str
    collected_at: str  # ISO-8601 timestamp
    reachable: bool
    sessions_collected: bool
    local_groups_collected: bool

    def is_complete(self, need_sessions: bool, need_local_groups: bool) -> bool:
        """Return True if this host has all requested data types collected."""
        if not self.reachable:
            return False
        if need_sessions and not self.sessions_collected:
            return False
        if need_local_groups and not self.local_groups_collected:
            return False
        return True

    def to_dict(self) -> dict[str, Any]:
        return {
            "hostname": self.hostname,
            "collected_at": self.collected_at,
            "reachable": self.reachable,
            "sessions_collected": self.sessions_collected,
            "local_groups_collected": self.local_groups_collected,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> HostEnumRecord:
        return cls(
            hostname=d["hostname"],
            collected_at=d.get("collected_at", ""),
            reachable=d.get("reachable", False),
            sessions_collected=d.get("sessions_collected", False),
            local_groups_collected=d.get("local_groups_collected", False),
        )


class EnumerationTracker:
    """Tracks which hosts have been enumerated and what data was collected.

    Persists to the collection JSON under ``meta.enumeration_tracker`` so
    that subsequent runs can skip already-collected hosts.

    Usage::

        tracker = EnumerationTracker.from_collection(collection_data)
        pending = tracker.filter_pending(targets, sessions=True, local_groups=True)
        # ... enumerate pending hosts ...
        tracker.record("srv01.test.local", reachable=True, sessions=True, local_groups=True)
        tracker.save_to_collection(collection_data)
    """

    def __init__(self, records: dict[str, HostEnumRecord] | None = None) -> None:
        self._records: dict[str, HostEnumRecord] = records or {}

    @property
    def records(self) -> dict[str, HostEnumRecord]:
        return self._records

    def record(
        self,
        hostname: str,
        reachable: bool,
        sessions: bool,
        local_groups: bool,
    ) -> None:
        """Record enumeration result for a host.

        If the host was previously recorded, updates the record (merges
        collected data types — once a type is True it stays True).
        """
        key = hostname.lower()
        now = datetime.now(timezone.utc).isoformat()
        existing = self._records.get(key)
        if existing:
            self._records[key] = HostEnumRecord(
                hostname=hostname,
                collected_at=now,
                reachable=reachable or existing.reachable,
                sessions_collected=sessions or existing.sessions_collected,
                local_groups_collected=local_groups or existing.local_groups_collected,
            )
        else:
            self._records[key] = HostEnumRecord(
                hostname=hostname,
                collected_at=now,
                reachable=reachable,
                sessions_collected=sessions,
                local_groups_collected=local_groups,
            )

    def filter_pending(
        self,
        targets: list[ClassifiedComputer],
        need_sessions: bool = True,
        need_local_groups: bool = True,
    ) -> tuple[list[ClassifiedComputer], list[ClassifiedComputer]]:
        """Split targets into (pending, already_collected).

        A host is considered collected if its record shows all requested
        data types were successfully gathered while the host was reachable.
        """
        pending: list[ClassifiedComputer] = []
        collected: list[ClassifiedComputer] = []
        for comp in targets:
            host = (comp.dns_hostname or comp.name.rstrip("$")).lower()
            rec = self._records.get(host)
            if rec and rec.is_complete(need_sessions, need_local_groups):
                collected.append(comp)
            else:
                pending.append(comp)
        return pending, collected

    def summary(self) -> dict[str, int]:
        """Return summary counts."""
        total = len(self._records)
        reachable = sum(1 for r in self._records.values() if r.reachable)
        sessions = sum(1 for r in self._records.values() if r.sessions_collected)
        local_groups = sum(1 for r in self._records.values() if r.local_groups_collected)
        unreachable = sum(1 for r in self._records.values() if not r.reachable)
        return {
            "total_tracked": total,
            "reachable": reachable,
            "unreachable": unreachable,
            "sessions_collected": sessions,
            "local_groups_collected": local_groups,
        }

    def to_dict(self) -> dict[str, Any]:
        return {k: v.to_dict() for k, v in self._records.items()}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> EnumerationTracker:
        records = {}
        for key, val in data.items():
            records[key] = HostEnumRecord.from_dict(val)
        return cls(records)

    @classmethod
    def from_collection(cls, collection_data: dict) -> EnumerationTracker:
        """Load tracker state from a collection JSON dict."""
        tracker_data = collection_data.get("meta", {}).get("enumeration_tracker", {})
        if tracker_data:
            return cls.from_dict(tracker_data)
        return cls()

    def save_to_collection(self, collection_data: dict) -> None:
        """Persist tracker state into a collection JSON dict."""
        meta = collection_data.setdefault("meta", {})
        meta["enumeration_tracker"] = self.to_dict()


@dataclass
class NetworkCollectionResult:
    """Aggregated results from scanning all hosts."""
    hosts_total: int = 0
    hosts_reachable: int = 0
    hosts_unreachable: int = 0
    total_sessions: int = 0
    total_local_group_members: int = 0
    host_results: list[HostEnumResult] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        sessions = []
        local_groups = []
        for hr in self.host_results:
            for s in hr.sessions:
                rec: dict[str, str] = {
                    "username": s.username,
                    "source_host": s.source_host,
                    "target_host": s.target_host,
                }
                if s.source_method:
                    rec["source_method"] = s.source_method
                if s.collected_at:
                    rec["collected_at"] = s.collected_at
                sessions.append(rec)
            for m in hr.local_group_members:
                local_groups.append({
                    "member_sid": m.member_sid,
                    "member_name": m.member_name,
                    "group_rid": m.group_rid,
                    "group_name": m.group_name,
                    "target_host": m.target_host,
                    "edge_type": RID_TO_EDGE.get(m.group_rid, "Unknown"),
                })
        return {
            "hosts_total": self.hosts_total,
            "hosts_reachable": self.hosts_reachable,
            "hosts_unreachable": self.hosts_unreachable,
            "total_sessions": self.total_sessions,
            "total_local_group_members": self.total_local_group_members,
            "sessions": sessions,
            "local_group_members": local_groups,
        }


def _resolve_host(computer: dict) -> str | None:
    """Extract the best hostname to contact from a computer LDAP entry."""
    # Prefer dNSHostName, fall back to sAMAccountName (strip trailing $)
    host = computer.get("dNSHostName")
    if host:
        return host if isinstance(host, str) else host[0]
    name = computer.get("sAMAccountName", "")
    if isinstance(name, list):
        name = name[0] if name else ""
    return name.rstrip("$") if name else None


def collect_network(
    computers: list[dict],
    username: str,
    password: str,
    domain: str,
    nthash: str = "",
    ccache: str = "",
    collect_sessions: bool = True,
    collect_local_groups: bool = True,
    max_workers: int = DEFAULT_WORKERS,
    timeout: int = DEFAULT_TIMEOUT,
    progress_callback: Any = None,
    stealth: StealthConfig | None = None,
) -> NetworkCollectionResult:
    """Run session and local group enumeration across a list of computers.

    Args:
        computers: List of computer dicts from LDAP (must have dNSHostName
                   or sAMAccountName).
        username: Domain username for authentication.
        password: Password for authentication.
        domain: FQDN of the AD domain.
        nthash: NT hash for pass-the-hash (optional).
        collect_sessions: Enumerate active sessions.
        collect_local_groups: Enumerate local group memberships.
        max_workers: Number of concurrent host scanners.
        timeout: Per-host connection timeout in seconds.
        progress_callback: Optional callable(completed, total, hostname) for
                           progress reporting.

    Returns:
        NetworkCollectionResult with all session and local group data.
    """
    require_impacket()
    _stealth = stealth or StealthConfig()

    # Apply stealth overrides for concurrency
    if _stealth.smb_workers is not None:
        max_workers = _stealth.smb_workers

    result = NetworkCollectionResult()

    # Build target list
    targets: list[str] = []
    for comp in computers:
        host = _resolve_host(comp)
        if host:
            targets.append(host)

    result.hosts_total = len(targets)
    if not targets:
        return result

    def _scan_host(host: str) -> HostEnumResult:
        _stealth.smb_pace()
        return enumerate_host(
            host=host,
            username=username,
            password=password,
            domain=domain,
            nthash=nthash,
            ccache=ccache,
            collect_sessions=collect_sessions,
            collect_local_groups=collect_local_groups,
            timeout=timeout,
        )

    # Use rich progress bar when available and no custom callback
    use_rich = progress_callback is None
    if use_rich:
        try:
            from rich.progress import (
                Progress, SpinnerColumn, BarColumn, TextColumn,
                MofNCompleteColumn, TimeElapsedColumn, TimeRemainingColumn,
            )
        except ImportError:
            use_rich = False

    completed = 0

    if use_rich:
        from rich.progress import (
            Progress, SpinnerColumn, BarColumn, TextColumn,
            MofNCompleteColumn, TimeElapsedColumn, TimeRemainingColumn,
        )
        with Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]Scanning hosts"),
            BarColumn(),
            MofNCompleteColumn(),
            TextColumn("[dim]|"),
            TextColumn("reachable={task.fields[reachable]}"),
            TextColumn("sessions={task.fields[sessions]}"),
            TextColumn("members={task.fields[members]}"),
            TextColumn("[dim]|"),
            TimeElapsedColumn(),
            TimeRemainingColumn(),
        ) as progress:
            task = progress.add_task(
                "scan", total=len(targets),
                reachable=0, sessions=0, members=0,
            )

            with ThreadPoolExecutor(max_workers=max_workers) as pool:
                futures = {pool.submit(_scan_host, host): host for host in targets}
                for future in as_completed(futures):
                    host = futures[future]
                    completed += 1
                    try:
                        hr = future.result()
                        result.host_results.append(hr)
                        if hr.reachable:
                            result.hosts_reachable += 1
                        else:
                            result.hosts_unreachable += 1
                        result.total_sessions += len(hr.sessions)
                        result.total_local_group_members += len(hr.local_group_members)
                    except Exception as exc:
                        logger.warning("Host scan failed for %s: %s", host, exc)
                        result.hosts_unreachable += 1

                    progress.update(
                        task, advance=1,
                        reachable=result.hosts_reachable,
                        sessions=result.total_sessions,
                        members=result.total_local_group_members,
                    )
    else:
        print(f"[*] Network collection: scanning {len(targets)} host(s) "
              f"with {max_workers} workers", file=sys.stderr)

        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = {pool.submit(_scan_host, host): host for host in targets}
            for future in as_completed(futures):
                host = futures[future]
                completed += 1
                try:
                    hr = future.result()
                    result.host_results.append(hr)
                    if hr.reachable:
                        result.hosts_reachable += 1
                    else:
                        result.hosts_unreachable += 1
                    result.total_sessions += len(hr.sessions)
                    result.total_local_group_members += len(hr.local_group_members)

                    if progress_callback:
                        progress_callback(completed, result.hosts_total, host)
                    elif completed % 50 == 0 or completed == result.hosts_total:
                        print(
                            f"    [{completed}/{result.hosts_total}] "
                            f"reachable={result.hosts_reachable} "
                            f"sessions={result.total_sessions} "
                            f"local_members={result.total_local_group_members}",
                            file=sys.stderr,
                        )
                except Exception as exc:
                    logger.warning("Host scan failed for %s: %s", host, exc)
                    result.hosts_unreachable += 1

    print(
        f"[+] Network collection complete: "
        f"{result.hosts_reachable}/{result.hosts_total} reachable, "
        f"{result.total_sessions} sessions, "
        f"{result.total_local_group_members} local group members",
        file=sys.stderr,
    )

    return result


def resolve_member_names(
    network_result: NetworkCollectionResult,
    sid_map: dict[str, str],
) -> None:
    """Resolve member SIDs to names using the SID map from LDAP collection.

    Modifies LocalGroupMember.member_name and SessionInfo.username in place.
    Sessions from registry-based enumeration store raw SIDs as the username;
    this resolves them to ``DOMAIN\\user`` format when possible.
    """
    for hr in network_result.host_results:
        for member in hr.local_group_members:
            if not member.member_name and member.member_sid in sid_map:
                member.member_name = sid_map[member.member_sid]
        for session in hr.sessions:
            if session.username.startswith("S-1-5-21-") and session.username in sid_map:
                session.username = sid_map[session.username]


def save_network_collection(
    network_result: NetworkCollectionResult,
    domain: str,
    output_dir: str = ".",
) -> Path:
    """Write network collection results to a JSON file."""
    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = out_path / f"{domain}_{timestamp}_network.json"

    output = {
        "meta": {
            "domain": domain,
            "collected_at": datetime.now(timezone.utc).isoformat(),
            "collection_method": "Network",
        },
        **network_result.to_dict(),
    }

    with open(filename, "w") as f:
        json.dump(output, f, indent=2, default=str)

    print(f"[+] Wrote network collection to {filename}", file=sys.stderr)
    return filename


def merge_network_into_collection(
    collection_data: dict,
    network_result: NetworkCollectionResult,
) -> dict:
    """Merge network collection data into an existing collection JSON dict.

    Appends new sessions and local_group_members to any existing entries,
    deduplicating by content, and updates the meta to reflect the combined
    collection method.
    """
    net_dict = network_result.to_dict()

    # Append new sessions, deduplicating by (username, source_host, target_host)
    existing_sessions = collection_data.get("sessions") or []
    seen_sessions: set[tuple] = {
        (s.get("username", "").lower(), s.get("source_host", "").lower(),
         s.get("target_host", "").lower())
        for s in existing_sessions
    }
    for s in net_dict["sessions"]:
        key = (s.get("username", "").lower(), s.get("source_host", "").lower(),
               s.get("target_host", "").lower())
        if key not in seen_sessions:
            existing_sessions.append(s)
            seen_sessions.add(key)
    collection_data["sessions"] = existing_sessions

    # Append new local_group_members, deduplicating by
    # (member_sid, group_rid, target_host)
    existing_members = collection_data.get("local_group_members") or []
    seen_members: set[tuple] = {
        (m.get("member_sid", "").upper(), m.get("group_rid", ""),
         m.get("target_host", "").lower())
        for m in existing_members
    }
    for m in net_dict["local_group_members"]:
        key = (m.get("member_sid", "").upper(), m.get("group_rid", ""),
               m.get("target_host", "").lower())
        if key not in seen_members:
            existing_members.append(m)
            seen_members.add(key)
    collection_data["local_group_members"] = existing_members

    # Update meta
    meta = collection_data.get("meta", {})
    prev_stats = meta.get("network_stats", {})
    meta["network_stats"] = {
        "hosts_total": prev_stats.get("hosts_total", 0)
                       + net_dict["hosts_total"],
        "hosts_reachable": prev_stats.get("hosts_reachable", 0)
                           + net_dict["hosts_reachable"],
        "hosts_unreachable": prev_stats.get("hosts_unreachable", 0)
                             + net_dict["hosts_unreachable"],
        "total_sessions": len(collection_data["sessions"]),
        "total_local_group_members": len(collection_data["local_group_members"]),
    }
    from .collection_meta import compose_collection_method
    meta.setdefault("base_method", "DCOnly")
    meta["collection_method"] = compose_collection_method(meta)
    collection_data["meta"] = meta

    return collection_data
