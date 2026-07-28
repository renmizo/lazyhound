"""Core data models: findings, severity, scoring, scan results, domain metadata."""

from __future__ import annotations

import math
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def points(self) -> int:
        return _SEVERITY_POINTS[self]

    @property
    def sort_order(self) -> int:
        return _SEVERITY_ORDER[self]

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.sort_order < other.sort_order


_SEVERITY_POINTS = {
    Severity.CRITICAL: 40,
    Severity.HIGH: 20,
    Severity.MEDIUM: 10,
    Severity.LOW: 4,
    Severity.INFO: 0,
}
_SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


class CheckCategory(Enum):
    KERBEROS = "kerberos"
    DELEGATION = "delegation"
    PASSWORD_POLICY = "password_policy"
    ACCOUNT_HYGIENE = "account_hygiene"
    PRIVILEGED_ACCESS = "privileged_access"
    ADCS = "adcs"
    GPO = "gpo"
    PROTOCOL_SECURITY = "protocol_security"
    DNS = "dns"
    INFRASTRUCTURE = "infrastructure"
    TRUST = "trust"

    @property
    def weight(self) -> float:
        """Category weight for risk score calculation.  Higher = more impactful."""
        return _CATEGORY_WEIGHTS.get(self, 1.0)

    @property
    def label(self) -> str:
        acronyms = {"adcs": "ADCS", "gpo": "GPO", "dns": "DNS"}
        if self.value in acronyms:
            return acronyms[self.value]
        return self.value.replace("_", " ").title()


_CATEGORY_WEIGHTS: dict[CheckCategory, float] = {
    CheckCategory.KERBEROS: 1.3,
    CheckCategory.DELEGATION: 1.2,
    CheckCategory.PASSWORD_POLICY: 1.1,
    CheckCategory.ACCOUNT_HYGIENE: 1.0,
    CheckCategory.PRIVILEGED_ACCESS: 1.4,
    CheckCategory.ADCS: 1.3,
    CheckCategory.GPO: 1.0,
    CheckCategory.PROTOCOL_SECURITY: 1.1,
    CheckCategory.DNS: 0.8,
    CheckCategory.INFRASTRUCTURE: 0.9,
    CheckCategory.TRUST: 1.2,
}


# ---------------------------------------------------------------------------
# Scoring profiles — controls how risk_score and grade are computed
# ---------------------------------------------------------------------------
@dataclass
class ScoringProfile:
    """Tunable scoring model for risk score computation.

    curve:
        "linear"  — score = 100 - (wp * coefficient)
        "sqrt"    — score = 100 - (sqrt(wp) * coefficient)     [diminishing returns]
        "log"     — score = 100 - (log2(wp+1) * coefficient)   [gentlest]

    severity_points:
        Override default severity → points mapping.  Keys are severity value
        strings ("critical", "high", etc.).

    category_weights:
        Override default category → weight mapping.  Keys are category value
        strings ("kerberos", "privileged_access", etc.).

    grade_thresholds:
        Mapping from grade letter to minimum score required.
    """

    name: str = "balanced"
    curve: str = "sqrt"
    coefficient: float = 5.5
    health_weight: float = 0.4
    grade_thresholds: dict[str, int] = field(default_factory=lambda: {
        "A": 90, "B": 80, "C": 65, "D": 50,
    })
    severity_points: dict[str, int] | None = None
    category_weights: dict[str, float] | None = None

    def compute_score(self, weighted_points: float) -> int:
        """Compute 0-100 risk score from weighted risk points (before health blend)."""
        if weighted_points <= 0:
            return 100
        if self.curve == "sqrt":
            deduction = math.sqrt(weighted_points) * self.coefficient
        elif self.curve == "log":
            deduction = math.log2(weighted_points + 1) * self.coefficient
        else:  # linear
            deduction = weighted_points * self.coefficient
        return max(0, min(100, 100 - int(deduction)))

    def compute_blended_score(self, weighted_points: float, health_pct: float) -> int:
        """Compute blended score factoring in environment health.

        ``health_pct`` is 0-100 representing the percentage of objects
        without findings.  The final score blends the raw risk score with
        the health percentage using ``health_weight``.
        """
        raw = self.compute_score(weighted_points)
        hw = self.health_weight
        return max(0, min(100, int(raw * (1 - hw) + health_pct * hw)))

    def compute_grade(self, score: int) -> str:
        """Compute letter grade from risk score."""
        for letter in ("A", "B", "C", "D"):
            threshold = self.grade_thresholds.get(letter, 0)
            if score >= threshold:
                return letter
        return "F"

    @staticmethod
    def grade_to_rating(grade: str) -> str:
        """Convert a letter grade to a human-readable rating label."""
        return {
            "A": "Excellent",
            "B": "Good",
            "C": "Fair",
            "D": "Poor",
            "F": "Absent",
        }.get(grade, grade)

    def get_severity_points(self, severity: "Severity") -> int:
        """Return points for a severity, using overrides if set."""
        if self.severity_points:
            override = self.severity_points.get(severity.value)
            if override is not None:
                return override
        return _SEVERITY_POINTS[severity]

    def get_category_weight(self, category: "CheckCategory") -> float:
        """Return weight for a category, using overrides if set."""
        if self.category_weights:
            override = self.category_weights.get(category.value)
            if override is not None:
                return override
        return _CATEGORY_WEIGHTS.get(category, 1.0)


# Built-in profiles
SCORING_PROFILES: dict[str, ScoringProfile] = {
    "strict": ScoringProfile(
        name="strict",
        curve="linear",
        coefficient=0.45,
        health_weight=0.2,
        grade_thresholds={"A": 90, "B": 80, "C": 65, "D": 50},
    ),
    "balanced": ScoringProfile(
        name="balanced",
        curve="sqrt",
        coefficient=5.5,
        health_weight=0.4,
        grade_thresholds={"A": 90, "B": 75, "C": 60, "D": 40},
    ),
    "lenient": ScoringProfile(
        name="lenient",
        curve="log",
        coefficient=8.0,
        health_weight=0.5,
        grade_thresholds={"A": 85, "B": 70, "C": 50, "D": 30},
    ),
}

# Module-level active profile (default: balanced)
_active_profile: ScoringProfile = SCORING_PROFILES["balanced"]


def get_scoring_profile() -> ScoringProfile:
    """Return the currently active scoring profile."""
    return _active_profile


def set_scoring_profile(profile: ScoringProfile | str) -> ScoringProfile:
    """Set the active scoring profile (by name or instance)."""
    global _active_profile
    if isinstance(profile, str):
        if profile not in SCORING_PROFILES:
            raise ValueError(
                f"Unknown scoring profile '{profile}'. "
                f"Available: {', '.join(SCORING_PROFILES)}"
            )
        _active_profile = SCORING_PROFILES[profile]
    else:
        _active_profile = profile
    return _active_profile


@dataclass(frozen=True)
class MitreAttack:
    """MITRE ATT&CK technique mapping."""

    technique_id: str
    technique_name: str
    tactic: str
    url: str = ""
    known_tools: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "tactic": self.tactic,
            "url": self.url or f"https://attack.mitre.org/techniques/{self.technique_id.replace('.', '/')}/",
            "known_tools": list(self.known_tools),
        }


@dataclass(frozen=True)
class Remediation:
    """Actionable fix guidance."""

    description: str
    powershell: str | None = None
    gpo_path: str | None = None
    reference_url: str | None = None
    effort: str = "medium"

    def to_dict(self) -> dict[str, Any]:
        return {
            "description": self.description,
            "powershell": self.powershell,
            "gpo_path": self.gpo_path,
            "reference_url": self.reference_url,
            "effort": self.effort,
        }


@dataclass
class Finding:
    """A single security finding produced by a check."""

    title: str
    description: str
    severity: Severity
    category: CheckCategory
    check_id: str
    affected_objects: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)
    mitre: MitreAttack | None = None
    remediation: Remediation | None = None
    risk_points: int | None = None

    def __post_init__(self) -> None:
        if self.risk_points is None:
            self.risk_points = self.severity.points

    @property
    def affected_count(self) -> int:
        return len(self.affected_objects)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "category": self.category.value,
            "check_id": self.check_id,
            "risk_points": self.risk_points,
            "affected_count": self.affected_count,
            "affected_objects": self.affected_objects,
            "details": self.details,
        }
        if self.mitre:
            d["mitre"] = self.mitre.to_dict()
        if self.remediation:
            d["remediation"] = self.remediation.to_dict()
        return d


@dataclass
class CheckResult:
    """Result from a single check execution."""

    check_id: str
    check_name: str
    category: CheckCategory
    findings: list[Finding] = field(default_factory=list)
    error: str | None = None
    duration_ms: float = 0.0

    @property
    def total_risk_points(self) -> int:
        return sum(f.risk_points or 0 for f in self.findings)

    @property
    def weighted_risk_points(self) -> float:
        return self.total_risk_points * self.category.weight

    @property
    def max_severity(self) -> Severity:
        if not self.findings:
            return Severity.INFO
        return min(self.findings, key=lambda f: f.severity.sort_order).severity

    @property
    def passed(self) -> bool:
        return not self.findings and self.error is None

    def to_dict(self) -> dict[str, Any]:
        return {
            "check_id": self.check_id,
            "check_name": self.check_name,
            "category": self.category.value,
            "passed": self.passed,
            "total_risk_points": self.total_risk_points,
            "weighted_risk_points": round(self.weighted_risk_points, 1),
            "max_severity": self.max_severity.value,
            "error": self.error,
            "duration_ms": self.duration_ms,
            "findings": [f.to_dict() for f in self.findings],
        }


@dataclass
class DomainInfo:
    """Collected metadata about the target domain."""

    domain: str = ""
    domain_dn: str = ""
    domain_sid: str = ""
    forest_name: str = ""
    dc_hostname: str = ""
    dc_ip: str = ""
    functional_level: str = ""
    domain_controllers: list[str] = field(default_factory=list)
    total_users: int = 0
    total_computers: int = 0
    total_groups: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "domain": self.domain,
            "domain_dn": self.domain_dn,
            "domain_sid": self.domain_sid,
            "forest_name": self.forest_name,
            "dc_hostname": self.dc_hostname,
            "dc_ip": self.dc_ip,
            "functional_level": self.functional_level,
            "domain_controllers": self.domain_controllers,
            "total_users": self.total_users,
            "total_computers": self.total_computers,
            "total_groups": self.total_groups,
        }


@dataclass
class ScanResult:
    """Aggregated result of a full scan."""

    scan_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    target_domain: str = ""
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: datetime | None = None
    run_as_user: str = ""
    check_results: list[CheckResult] = field(default_factory=list)
    domain_info: DomainInfo = field(default_factory=DomainInfo)

    @property
    def total_risk_points(self) -> int:
        return sum(cr.total_risk_points for cr in self.check_results)

    @property
    def weighted_risk_points(self) -> float:
        return sum(cr.weighted_risk_points for cr in self.check_results)

    @property
    def total_objects(self) -> int:
        """Total AD objects in the domain (users + computers + groups)."""
        di = self.domain_info
        return di.total_users + di.total_computers + di.total_groups

    @property
    def affected_object_names(self) -> set[str]:
        """Unique object names that appear in any finding."""
        names: set[str] = set()
        for cr in self.check_results:
            for f in cr.findings:
                names.update(f.affected_objects)
        return names

    @property
    def affected_object_count(self) -> int:
        return len(self.affected_object_names)

    @property
    def health_pct(self) -> float:
        """Percentage of objects without any finding (0-100)."""
        total = self.total_objects
        if total <= 0:
            return 100.0
        affected = min(self.affected_object_count, total)
        return (total - affected) / total * 100

    @property
    def raw_risk_score(self) -> int:
        """Risk score before health blending."""
        profile = get_scoring_profile()
        return profile.compute_score(self.weighted_risk_points)

    @property
    def risk_score(self) -> int:
        """0-100 blended score (risk + health).  Uses the active scoring profile."""
        profile = get_scoring_profile()
        return profile.compute_blended_score(self.weighted_risk_points, self.health_pct)

    @property
    def grade(self) -> str:
        profile = get_scoring_profile()
        return profile.compute_grade(self.risk_score)

    @property
    def rating(self) -> str:
        """Human-readable rating label (Excellent/Good/Fair/Poor/Absent)."""
        return ScoringProfile.grade_to_rating(self.grade)

    @property
    def total_findings(self) -> int:
        return sum(len(cr.findings) for cr in self.check_results)

    @property
    def checks_passed(self) -> int:
        return sum(1 for cr in self.check_results if cr.passed)

    @property
    def checks_failed(self) -> int:
        return sum(1 for cr in self.check_results if not cr.passed)

    @property
    def duration_ms(self) -> float:
        return sum(cr.duration_ms for cr in self.check_results)

    def findings_by_severity(self) -> dict[Severity, list[Finding]]:
        result: dict[Severity, list[Finding]] = {s: [] for s in Severity}
        for cr in self.check_results:
            for f in cr.findings:
                result[f.severity].append(f)
        return result

    def findings_by_category(self) -> dict[CheckCategory, list[Finding]]:
        result: dict[CheckCategory, list[Finding]] = {}
        for cr in self.check_results:
            for f in cr.findings:
                result.setdefault(f.category, []).append(f)
        return result

    def to_dict(self) -> dict[str, Any]:
        profile = get_scoring_profile()
        return {
            "scan_id": self.scan_id,
            "target_domain": self.target_domain,
            "run_as_user": self.run_as_user,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "duration_ms": round(self.duration_ms, 1),
            "risk_score": self.risk_score,
            "grade": self.grade,
            "rating": self.rating,
            "scoring_profile": profile.name,
            "total_findings": self.total_findings,
            "total_risk_points": self.total_risk_points,
            "weighted_risk_points": round(self.weighted_risk_points, 1),
            "checks_passed": self.checks_passed,
            "checks_failed": self.checks_failed,
            "domain_info": self.domain_info.to_dict(),
            "check_results": [cr.to_dict() for cr in self.check_results],
        }
