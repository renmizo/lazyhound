"""Plugin-based check registry with decorator registration and concurrent execution.

Usage:

    from . import register_check
    from lazyhound.finder.finder_models import CheckCategory

    @register_check(
        check_id="kerb_001",
        name="Kerberoastable Accounts",
        category=CheckCategory.KERBEROS,
    )
    def check_kerberoastable(context):
        ...
        return findings
"""

from __future__ import annotations

import importlib
import logging
import pkgutil
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Callable, Protocol

from lazyhound.finder.finder_models import CheckCategory, CheckResult

if TYPE_CHECKING:
    from lazyhound.finder.finder_models import Finding

logger = logging.getLogger(__name__)


class ScanContext(Protocol):
    @property
    def ldap(self) -> Any: ...
    @property
    def domain_dn(self) -> str: ...
    @property
    def domain_sid(self) -> str: ...
    @property
    def dc_hostname(self) -> str: ...


CheckFunction = Callable[[Any], list["Finding"]]


@dataclass
class CheckDefinition:
    """Metadata and callable for a registered check."""

    check_id: str
    name: str
    category: CheckCategory
    description: str
    func: CheckFunction
    protocols: list[str] = field(default_factory=lambda: ["ldap"])
    enabled: bool = True
    tags: list[str] = field(default_factory=list)


class CheckRegistry:
    """Central registry for all security checks.

    Singleton pattern.  Supports decorator-based registration,
    auto-discovery via pkgutil, and filtered / concurrent execution.
    """

    _instance: CheckRegistry | None = None

    def __init__(self) -> None:
        self._checks: dict[str, CheckDefinition] = {}

    @classmethod
    def get_instance(cls) -> CheckRegistry:
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    @classmethod
    def reset(cls) -> None:
        """Reset singleton — useful for tests."""
        cls._instance = None

    # -- registration --

    def register(self, definition: CheckDefinition) -> None:
        if definition.check_id in self._checks:
            logger.warning("Overwriting check %s", definition.check_id)
        self._checks[definition.check_id] = definition

    def get(self, check_id: str) -> CheckDefinition | None:
        return self._checks.get(check_id)

    def all_checks(self) -> list[CheckDefinition]:
        return list(self._checks.values())

    def by_category(self, category: CheckCategory) -> list[CheckDefinition]:
        return [c for c in self._checks.values() if c.category == category]

    def by_tag(self, tag: str) -> list[CheckDefinition]:
        return [c for c in self._checks.values() if tag in c.tags]

    # -- filtering --

    def filter(
        self,
        include: list[str] | None = None,
        exclude: list[str] | None = None,
        categories: list[CheckCategory] | None = None,
        tags: list[str] | None = None,
    ) -> list[CheckDefinition]:
        checks = list(self._checks.values())
        if include:
            inc_set = set(include)
            checks = [c for c in checks if c.check_id in inc_set]
        if exclude:
            exc_set = set(exclude)
            checks = [c for c in checks if c.check_id not in exc_set]
        if categories:
            cat_set = set(categories)
            checks = [c for c in checks if c.category in cat_set]
        if tags:
            tag_set = set(tags)
            checks = [c for c in checks if tag_set & set(c.tags)]
        return [c for c in checks if c.enabled]

    # -- execution --

    def run_check(self, check_id: str, context: Any) -> CheckResult:
        defn = self._checks.get(check_id)
        if not defn:
            return CheckResult(
                check_id=check_id,
                check_name="Unknown",
                category=CheckCategory.INFRASTRUCTURE,
                error=f"Check {check_id} not found",
            )
        start = time.monotonic()
        try:
            findings = defn.func(context)
            dur = (time.monotonic() - start) * 1000
            return CheckResult(
                check_id=defn.check_id,
                check_name=defn.name,
                category=defn.category,
                findings=findings,
                duration_ms=round(dur, 2),
            )
        except Exception as exc:
            dur = (time.monotonic() - start) * 1000
            logger.exception("Check %s failed", check_id)
            return CheckResult(
                check_id=defn.check_id,
                check_name=defn.name,
                category=defn.category,
                error=str(exc),
                duration_ms=round(dur, 2),
            )

    def run_all(
        self,
        context: Any,
        include: list[str] | None = None,
        exclude: list[str] | None = None,
        categories: list[CheckCategory] | None = None,
        max_workers: int = 1,
        cancel_event: threading.Event | None = None,
    ) -> list[CheckResult]:
        """Run filtered checks.  Set max_workers > 1 for concurrency.

        If *cancel_event* is provided and becomes set, remaining checks are
        skipped and partial results are returned.
        """
        checks = self.filter(include=include, exclude=exclude, categories=categories)
        if max_workers <= 1:
            results = []
            for defn in checks:
                if cancel_event and cancel_event.is_set():
                    logger.info("Scan cancelled — skipping remaining checks")
                    break
                logger.info("Running: %s", defn.name)
                results.append(self.run_check(defn.check_id, context))
            return results

        results: list[CheckResult] = []
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = {
                pool.submit(self.run_check, defn.check_id, context): defn
                for defn in checks
            }
            for future in as_completed(futures):
                if cancel_event and cancel_event.is_set():
                    pool.shutdown(wait=False, cancel_futures=True)
                    logger.info("Scan cancelled — stopping workers")
                    break
                results.append(future.result())
        # Preserve a deterministic order by check_id
        results.sort(key=lambda r: r.check_id)
        return results

    # -- discovery --

    def discover_checks(self, package_name: str = "lazyhound.finder.scan.checks") -> None:
        try:
            package = importlib.import_module(package_name)
        except ImportError:
            logger.warning("Could not import %s", package_name)
            return
        if not hasattr(package, "__path__"):
            return
        for _imp, modname, _ispkg in pkgutil.iter_modules(package.__path__):
            if modname.startswith("_") or modname == "registry":
                continue
            full = f"{package_name}.{modname}"
            try:
                importlib.import_module(full)
            except Exception:
                logger.exception("Failed to import %s", full)


def register_check(
    check_id: str,
    name: str,
    category: CheckCategory,
    description: str = "",
    protocols: list[str] | None = None,
    tags: list[str] | None = None,
) -> Callable[[CheckFunction], CheckFunction]:
    """Decorator to register a function as a security check."""

    def decorator(func: CheckFunction) -> CheckFunction:
        defn = CheckDefinition(
            check_id=check_id,
            name=name,
            category=category,
            description=description or func.__doc__ or "",
            func=func,
            protocols=protocols or ["ldap"],
            tags=tags or [],
        )
        CheckRegistry.get_instance().register(defn)
        return func

    return decorator
