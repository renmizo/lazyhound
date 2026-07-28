"""Core data models for LazyHound."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class Severity(Enum):
    """Mirror lazyhound finder severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ValidationStatus(Enum):
    """Outcome of a single validation action."""
    CONFIRMED = "confirmed"       # Vulnerability confirmed exploitable (invasive)
    COMPLETED = "completed"       # Action ran successfully (recon/enumeration)
    PARTIAL = "partial"           # Partially confirmed
    NOT_VULNERABLE = "not_vulnerable"  # Could not confirm
    INCONCLUSIVE = "inconclusive"  # Ran but produced no proof of success
    ERROR = "error"               # Execution error
    SKIPPED = "skipped"           # Operator skipped / denied
    PENDING = "pending"           # Not yet executed


class ActionClassification(Enum):
    """Whether an action is read-only or makes changes."""
    READ_ONLY = "read_only"       # Enumeration, querying, hash extraction
    INVASIVE = "invasive"         # Modifies AD objects, creates accounts, etc.


class FindingCategory(Enum):
    """Categories matching lazyhound finder."""
    ACCOUNT_HYGIENE = "account_hygiene"
    KERBEROS = "kerberos"
    DELEGATION = "delegation"
    ADCS = "adcs"
    PRIVILEGED_ACCESS = "privileged_access"
    GPO = "gpo"
    PASSWORD_POLICY = "password_policy"
    PROTOCOL_SECURITY = "protocol_security"
    INFRASTRUCTURE = "infrastructure"
    TRUST = "trust"
    ATTACK_PATH = "attack_path"


# ---------------------------------------------------------------------------
# Validation action & result
# ---------------------------------------------------------------------------

@dataclass
class ValidationAction:
    """A single command / tool invocation to validate a finding."""
    action_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    name: str = ""
    description: str = ""
    tool: str = ""                         # e.g. "impacket-GetUserSPNs", "rpcclient"
    command_template: str = ""             # Command with {placeholders}
    classification: ActionClassification = ActionClassification.READ_ONLY
    requires_approval: bool = False        # True for INVASIVE actions
    requires_root: bool = False            # True to auto-prefix sudo when not root
    order: int = 0                         # Execution order within a validation
    timeout: int = 120                     # Seconds

    # -- Chain support (inter-step dependencies) --
    # If set, a regex applied to stdout; first capture group stored in
    # context[output_key] for subsequent steps to use via {output_key}.
    output_key: str = ""                   # e.g. "cracked_password"
    output_pattern: str = ""               # regex with capture group

    # Gate: if set, this action's output is checked.  When the gate
    # condition is NOT met, the operator is prompted with gate_fail_prompt.
    # They can supply a value (stored in gate_key) or cancel remaining steps.
    gate_key: str = ""                     # context key to set from operator input
    gate_check: str = ""                   # "exit_code_zero", "stdout_not_empty", "stdout_contains:TEXT"
    gate_fail_prompt: str = ""             # message shown to operator on failure

    # Discovery gate: after execution, parse discovered objects from stdout
    # and prompt operator to accept, edit, or paste their own list.
    # The resulting list is stored in context[discovery_key] as comma-separated.
    discovery_key: str = ""                # context key (e.g. "discovered_targets")
    discovery_pattern: str = ""            # regex to extract objects (all matches)
    discovery_prompt: str = ""             # description of what was discovered

    # Command resolver: optional callable(context) -> str that returns the
    # final command. When set, used instead of command_template.format().
    # Produces cleaner commands for screenshots (avoids bash -c wrappers).
    command_resolver: Any = None

    # Outcome classification (copied from library Action; see outcomes.py)
    success_patterns: list[str] = field(default_factory=list)
    failure_sets: list[str] = field(default_factory=list)
    extra_failures: list[tuple[str, str]] = field(default_factory=list)
    preflight: bool = False
    unmatched_category: str = ""


@dataclass
class ActionResult:
    """Result of executing a single ValidationAction."""
    action_id: str = ""
    action_name: str = ""
    command_executed: str = ""             # Actual command (template resolved)
    exit_code: int = -1
    stdout: str = ""
    stderr: str = ""
    duration_ms: int = 0
    screenshot_path: str | None = None    # Path to terminal screenshot PNG
    log_path: str | None = None           # Path to raw output log
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    status: ValidationStatus = ValidationStatus.PENDING
    operator_approved: bool | None = None  # None=not needed, True/False=decision
    error_message: str = ""
    outcome_reason: str = ""               # machine-readable category (see outcomes.OutcomeCategory)

    def to_dict(self) -> dict:
        return {
            "action_id": self.action_id,
            "action_name": self.action_name,
            "command_executed": self.command_executed,
            "exit_code": self.exit_code,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "duration_ms": self.duration_ms,
            "screenshot_path": self.screenshot_path,
            "log_path": self.log_path,
            "timestamp": self.timestamp,
            "status": self.status.value,
            "operator_approved": self.operator_approved,
            "error_message": self.error_message,
            "outcome_reason": self.outcome_reason,
        }


@dataclass
class FindingValidation:
    """Maps a lazyhound finder finding to its validation actions."""
    check_id: str = ""                     # e.g. "hygiene_003", "kerb_001"
    finding_title: str = ""
    category: FindingCategory = FindingCategory.ACCOUNT_HYGIENE
    severity: Severity = Severity.MEDIUM
    affected_objects: list[str] = field(default_factory=list)
    actions: list[ValidationAction] = field(default_factory=list)
    description: str = ""
    mitre_technique: str = ""


@dataclass
class ValidationResult:
    """Complete result for validating one finding."""
    validation_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    check_id: str = ""
    finding_title: str = ""
    category: FindingCategory = FindingCategory.ACCOUNT_HYGIENE
    severity: Severity = Severity.MEDIUM
    affected_objects: list[str] = field(default_factory=list)
    action_results: list[ActionResult] = field(default_factory=list)
    overall_status: ValidationStatus = ValidationStatus.PENDING
    started_at: str = ""
    completed_at: str = ""
    notes: str = ""
    mitre_technique: str = ""

    def determine_status(self) -> ValidationStatus:
        """Derive overall status from action results."""
        statuses = [r.status for r in self.action_results]
        if not statuses:
            return ValidationStatus.PENDING
        if all(s == ValidationStatus.CONFIRMED for s in statuses):
            return ValidationStatus.CONFIRMED
        if any(s == ValidationStatus.CONFIRMED for s in statuses):
            return ValidationStatus.PARTIAL
        if any(s == ValidationStatus.ERROR for s in statuses):
            return ValidationStatus.ERROR
        if any(s == ValidationStatus.INCONCLUSIVE for s in statuses):
            return ValidationStatus.INCONCLUSIVE
        if all(s == ValidationStatus.SKIPPED for s in statuses):
            return ValidationStatus.SKIPPED
        if any(s == ValidationStatus.NOT_VULNERABLE for s in statuses):
            return ValidationStatus.NOT_VULNERABLE
        if all(s in (ValidationStatus.COMPLETED, ValidationStatus.SKIPPED) for s in statuses):
            return ValidationStatus.COMPLETED
        return ValidationStatus.PENDING


# ---------------------------------------------------------------------------
# Iteration (a full run of validations)
# ---------------------------------------------------------------------------

@dataclass
class ValidationIteration:
    """One complete run of validations – supports re-runs for comparison."""
    iteration_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    domain: str = ""
    started_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    completed_at: str = ""
    operator: str = ""
    description: str = ""
    results: list[ValidationResult] = field(default_factory=list)
    config_snapshot: dict[str, Any] = field(default_factory=dict)

    @property
    def confirmed_count(self) -> int:
        return sum(1 for r in self.results if r.overall_status == ValidationStatus.CONFIRMED)

    @property
    def partial_count(self) -> int:
        return sum(1 for r in self.results if r.overall_status == ValidationStatus.PARTIAL)

    @property
    def not_vulnerable_count(self) -> int:
        return sum(1 for r in self.results if r.overall_status == ValidationStatus.NOT_VULNERABLE)

    @property
    def inconclusive_count(self) -> int:
        return sum(1 for r in self.results if r.overall_status == ValidationStatus.INCONCLUSIVE)

    @property
    def error_count(self) -> int:
        return sum(1 for r in self.results if r.overall_status == ValidationStatus.ERROR)

    @property
    def completed_count(self) -> int:
        return sum(1 for r in self.results if r.overall_status == ValidationStatus.COMPLETED)

    @property
    def skipped_count(self) -> int:
        return sum(1 for r in self.results if r.overall_status == ValidationStatus.SKIPPED)


# ---------------------------------------------------------------------------
# Custom scenario
# ---------------------------------------------------------------------------

@dataclass
class Scenario:
    """A user-defined sequence of validation actions."""
    scenario_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    name: str = ""
    description: str = ""
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    steps: list[ValidationAction] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Import mapping (lazyhound finder finding → validator)
# ---------------------------------------------------------------------------

@dataclass
class ImportedFinding:
    """A finding imported from lazyhound scan/analysis results."""
    check_id: str = ""
    title: str = ""
    description: str = ""
    severity: str = ""
    category: str = ""
    affected_objects: list[str] = field(default_factory=list)
    mitre_technique: str = ""
    mitre_tactic: str = ""
    details: dict[str, Any] = field(default_factory=dict)
