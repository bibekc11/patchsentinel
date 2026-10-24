from __future__ import annotations
from dataclasses import dataclass, asdict
from typing import Any, Dict, List, Optional, TypedDict

CLASS_BY_RULE = {
    "B608": "sqli",
    "B602": "command_injection", "B604": "command_injection", "B605": "command_injection",
    "PS-PATH-TRAVERSAL": "path_traversal",
}
KIND_BY_CLASS = {"sqli": "truthy", "path_traversal": "canary_leak", "command_injection": "marker_file"}
SEVERITY_ORDER = {"HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNDEFINED": 0}


@dataclass
class Alert:
    id: str
    rule_id: str
    severity: str
    file: str          # path relative to repo root, '/' separated
    line: int
    message: str
    source: str        # bandit | builtin | sarif
    function: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class RunState(TypedDict, total=False):
    alert: Dict[str, Any]
    repo: str
    triage: Dict[str, Any]
    spec: Dict[str, Any]
    attempt: int
    feedback: str
    new_source: Optional[str]
    checks: Dict[str, Any]
    review: Dict[str, Any]
    status: str
    reason: str
    history: List[Dict[str, Any]]
