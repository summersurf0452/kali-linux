from collections.abc import Mapping
from dataclasses import asdict, dataclass, field
from typing import Literal

Status = Literal["pass", "fail", "unknown"]


class AuditError(Exception):
    pass


@dataclass(frozen=True)
class Check:
    id: str
    status: Status
    message: str


@dataclass(frozen=True)
class Report:
    scope: str
    checks: tuple[Check, ...]
    evidence: Mapping[str, str | int] = field(default_factory=dict)

    @property
    def result(self) -> Status:
        statuses = {check.status for check in self.checks}
        if "fail" in statuses:
            return "fail"
        if statuses == {"pass"}:
            return "pass"
        return "unknown"

    def as_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "schema_version": 1,
            "scope": self.scope,
            "result": self.result,
            "checks": [asdict(check) for check in self.checks],
        }
        if self.evidence:
            payload["evidence"] = dict(self.evidence)
        return payload
