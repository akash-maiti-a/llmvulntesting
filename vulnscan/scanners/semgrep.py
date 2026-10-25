"""Semgrep runner. Registry rulesets and our custom taint rules run as two
separate invocations so findings can be attributed to a ruleset in the eval."""

from __future__ import annotations

import glob
import json
import subprocess
from pathlib import Path

from .. import ROOT
from ..cwe import normalize
from ..models import Finding, TraceStep
from ..targets import Target

REGISTRY = {"php": ["p/php"], "python": ["p/python", "p/django", "p/flask"]}
CUSTOM_DIR = ROOT / "rules" / "semgrep"


def _scan_args(t: Target) -> list[str]:
    if not t.scan_paths:
        return ["."]
    paths: list[str] = []
    for pattern in t.scan_paths:
        paths += sorted(glob.glob(pattern, root_dir=t.src)) or [pattern]
    return paths


def run(t: Target, ruleset: str, raw_out: Path) -> list[Finding]:
    configs: list[str] = []
    for lang in t.langs():
        if ruleset == "registry":
            configs += REGISTRY[lang]
        else:
            configs.append(str(CUSTOM_DIR / lang))
    cmd = ["semgrep", "scan", "--json", "--metrics=off", "--dataflow-traces", "--quiet",
           "--timeout=60", "--max-target-bytes=2000000"]
    for c in configs:
        cmd += ["--config", c]
    if t.path:
        # Local trees (training/data) sit inside this repo's .gitignore; cloned targets
        # carry their own .git, so their scans are unaffected.
        cmd.append("--no-git-ignore")
    for ex in t.exclude:
        cmd += ["--exclude", ex]
    cmd += _scan_args(t)
    proc = subprocess.run(cmd, cwd=t.src, capture_output=True, text=True)
    if proc.returncode not in (0, 1):  # 1 = findings present
        raise RuntimeError(f"semgrep failed ({proc.returncode}): {proc.stderr[-2000:]}")
    raw_out.parent.mkdir(parents=True, exist_ok=True)
    raw_out.write_text(proc.stdout)
    return parse(json.loads(proc.stdout), ruleset)


def parse(data: dict, ruleset: str) -> list[Finding]:
    findings = []
    for r in data.get("results", []):
        extra = r.get("extra", {})
        meta = extra.get("metadata", {})
        findings.append(Finding(
            tool="semgrep",
            ruleset=ruleset,
            rule_id=r["check_id"],
            cwe=normalize(meta.get("cwe")),
            file=r["path"].replace("\\", "/").removeprefix("./"),
            line=r["start"]["line"],
            end_line=r["end"]["line"],
            message=extra.get("message", ""),
            snippet=extra.get("lines", ""),
            trace=_trace(extra.get("dataflow_trace")),
        ))
    return findings


def _loc(node) -> TraceStep | None:
    # Trace nodes are ["CliLoc", [{"path", "start", ...}, "content"]] in Semgrep's JSON.
    try:
        loc, content = node[1]
        return TraceStep(file=loc["path"].replace("\\", "/").removeprefix("./"),
                         line=loc["start"]["line"], note=content.strip()[:200])
    except (TypeError, KeyError, ValueError, IndexError):
        return None


def _trace(dt: dict | None) -> list[TraceStep]:
    if not dt:
        return []
    steps: list[TraceStep] = []
    src = _loc(dt.get("taint_source"))
    if src:
        src.note = "source: " + src.note
        steps.append(src)
    for var in dt.get("intermediate_vars", []) or []:
        loc = var.get("location", {})
        steps.append(TraceStep(file=loc.get("path", "").replace("\\", "/").removeprefix("./"),
                               line=loc.get("start", {}).get("line", 0),
                               note="via: " + var.get("content", "")[:200]))
    sink = _loc(dt.get("taint_sink"))
    if sink:
        sink.note = "sink: " + sink.note
        steps.append(sink)
    return steps
