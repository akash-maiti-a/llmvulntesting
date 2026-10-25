"""Tool-agnostic finding model shared by scanners, triage and evaluation."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from pathlib import Path


@dataclass
class TraceStep:
    file: str
    line: int
    note: str = ""


@dataclass
class Finding:
    tool: str  # "semgrep" | "pysa"
    ruleset: str  # "registry" | "custom" | "pysa"
    rule_id: str
    cwe: str  # normalized, e.g. "CWE-89"
    file: str  # path relative to the target root, forward slashes
    line: int
    end_line: int
    message: str = ""
    snippet: str = ""
    trace: list[TraceStep] = field(default_factory=list)

    @property
    def id(self) -> str:
        key = f"{self.tool}|{self.rule_id}|{self.file}|{self.line}|{self.end_line}"
        return hashlib.sha1(key.encode()).hexdigest()[:12]

    def to_dict(self) -> dict:
        d = asdict(self)
        d["id"] = self.id
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "Finding":
        d = {k: v for k, v in d.items() if k != "id"}
        d["trace"] = [TraceStep(**t) for t in d.get("trace", [])]
        return cls(**d)


def save_findings(path: Path, findings: list[Finding]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps([f.to_dict() for f in findings], indent=2))


def load_findings(path: Path) -> list[Finding]:
    if not path.exists():
        return []
    return [Finding.from_dict(d) for d in json.loads(path.read_text())]
