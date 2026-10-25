"""Score findings (optionally filtered by LLM triage) against ground truth.

A finding *hits* an entry when it lies inside one of the entry's locations
and its CWE is in the same family (cwe.same_family). From that:

- a vulnerable entry is *detected* if any finding hits it (recall);
- a finding is a true positive if it hits a vulnerable entry (precision);
- a finding that hits a safe entry is a false positive on known-safe code;
- any other finding in a file the ground truth covers is a labelled false
  positive; findings in files the ground truth never mentions are unlabelled.

Recall is reported per scope: "taint" (flows a taint analyzer can see),
"other" (server-side flaws that are not source->sink flows) and "client"."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field

from .cwe import same_family
from .groundtruth import Entry
from .models import Finding

SCOPES = ("taint", "other", "client")


def hits(f: Finding, e: Entry) -> bool:
    if not same_family(f.cwe, e.cwe):
        return False
    return any(loc.file == f.file and loc.start <= f.end_line and f.line <= loc.end
               for loc in e.locations)


@dataclass
class Label:
    """How one finding relates to the ground truth."""
    kind: str  # "tp" | "fp_safe" | "fp_labelled" | "unlabelled"
    entries: list[str] = field(default_factory=list)


def label(f: Finding, gt: list[Entry]) -> Label:
    vuln = [e.id for e in gt if e.vulnerable and hits(f, e)]
    if vuln:
        return Label("tp", vuln)
    safe = [e.id for e in gt if not e.vulnerable and hits(f, e)]
    if safe:
        return Label("fp_safe", safe)
    if any(loc.file == f.file for e in gt if e.exhaustive for loc in e.locations):
        return Label("fp_labelled")
    return Label("unlabelled")


@dataclass
class Score:
    config: str
    findings: int = 0
    tp: int = 0
    fp_safe: int = 0
    fp_labelled: int = 0
    unlabelled: int = 0
    detected: dict[str, list[str]] = field(default_factory=dict)  # scope -> detected entry ids
    positives: dict[str, int] = field(default_factory=dict)  # scope -> vulnerable entries
    safe_entries: int = 0
    safe_flagged: list[str] = field(default_factory=list)

    def recall(self, scope: str) -> float | None:
        n = self.positives.get(scope, 0)
        return len(self.detected.get(scope, [])) / n if n else None

    @property
    def precision(self) -> float | None:
        """TP over findings the ground truth can judge (unlabelled excluded)."""
        judged = self.tp + self.fp_safe + self.fp_labelled
        return self.tp / judged if judged else None

    def to_dict(self) -> dict:
        d = asdict(self)
        d["recall"] = {s: self.recall(s) for s in SCOPES}
        d["precision"] = self.precision
        return d


def score(config: str, findings: list[Finding], gt: list[Entry]) -> Score:
    s = Score(config=config, findings=len(findings), safe_entries=sum(not e.vulnerable for e in gt))
    for scope in SCOPES:
        s.positives[scope] = sum(e.vulnerable and e.scope == scope for e in gt)
    detected: set[str] = set()
    flagged: set[str] = set()
    for f in findings:
        lab = label(f, gt)
        setattr(s, lab.kind, getattr(s, lab.kind) + 1)
        if lab.kind == "tp":
            detected.update(lab.entries)
        elif lab.kind == "fp_safe":
            flagged.update(lab.entries)
    by_id = {e.id: e for e in gt}
    for scope in SCOPES:
        s.detected[scope] = sorted(i for i in detected if by_id[i].scope == scope)
    s.safe_flagged = sorted(flagged)
    return s


def keep(verdict: dict | None) -> bool:
    """Triage drops a finding only on an explicit false_positive verdict.
    Missing, failed or malformed verdicts keep the finding (fail open)."""
    return not verdict or verdict.get("verdict") != "false_positive"


def apply_triage(findings: list[Finding], verdicts: dict[str, dict]) -> list[Finding]:
    return [f for f in findings if keep(verdicts.get(f.id))]


def two_tier(fast: dict[str, dict], slow: dict[str, dict]) -> dict[str, dict]:
    """Fast verdict for everything; a fast-mode rejection is re-judged by the slow model."""
    out = {}
    for fid, v in fast.items():
        out[fid] = slow.get(fid, v) if v.get("verdict") == "false_positive" else v
    return out


@dataclass
class TriageAccuracy:
    """How a triage run treated findings whose ground-truth label is known."""
    tag: str
    tp_kept: int = 0
    tp_dropped: int = 0
    fp_kept: int = 0
    fp_dropped: int = 0
    failed: int = 0  # timeouts, malformed replies
    seconds: float = 0.0
    calls: int = 0

    def to_dict(self) -> dict:
        d = asdict(self)
        tp, fp = self.tp_kept + self.tp_dropped, self.fp_kept + self.fp_dropped
        d["tp_retention"] = self.tp_kept / tp if tp else None
        d["fp_removal"] = self.fp_dropped / fp if fp else None
        d["mean_seconds"] = self.seconds / self.calls if self.calls else None
        return d


def triage_accuracy(tag: str, findings: list[Finding], gt: list[Entry],
                    verdicts: dict[str, dict]) -> TriageAccuracy:
    acc = TriageAccuracy(tag)
    for f in findings:
        v = verdicts.get(f.id)
        if v is None:
            continue
        acc.calls += 1
        acc.seconds += v.get("secs", 0) or 0
        if v.get("verdict") not in ("true_positive", "false_positive"):
            acc.failed += 1
        kind = label(f, gt).kind
        kept = keep(v)
        if kind == "tp":
            acc.tp_kept += kept
            acc.tp_dropped += not kept
        elif kind in ("fp_safe", "fp_labelled"):
            acc.fp_kept += kept
            acc.fp_dropped += not kept
    return acc
