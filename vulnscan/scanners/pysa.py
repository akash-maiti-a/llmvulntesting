"""Pysa runner. Pysa (Pyre's taint analyzer) is inter-procedural, so it can follow
a request value through function calls and across files, which Semgrep OSS
taint mode cannot.

Pysa only attaches taint to *resolved* callees, so it needs the target's
third-party packages on its search path (installed into .cache/pysa/<key>/site)
and a way to treat view functions as entry points. Pyre's bundled models cover
aiohttp/Flask/Django request objects; rules/pysa/ adds a model query that marks
any `request` parameter in the scanned code as user-controlled, plus sinks the
bundled models lack."""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

from .. import ROOT
from ..models import Finding, TraceStep
from ..targets import Target

PYRE_LIB = Path(sys.prefix) / "lib" / "pyre_check"
CUSTOM_MODELS = ROOT / "rules" / "pysa"
CACHE = ROOT / ".cache" / "pysa"

# Pysa rule code -> CWE. Codes come from pyre_check/taint/core_privacy_security/taint.config.
CODE_CWE = {
    5001: "CWE-78", 5301: "CWE-78", 6065: "CWE-78", 5365: "CWE-78",
    5005: "CWE-89", 5305: "CWE-89", 5051: "CWE-89", 5351: "CWE-89",
    5052: "CWE-79", 5352: "CWE-79", 5053: "CWE-918",
    5007: "CWE-611", 5307: "CWE-611",
    5008: "CWE-79", 5308: "CWE-79",
    5011: "CWE-22", 6060: "CWE-22",
    5012: "CWE-918",
    5018: "CWE-601",
    5029: "CWE-113",
    5034: "CWE-134",
    6064: "CWE-94", 5364: "CWE-94",
    6066: "CWE-502", 5366: "CWE-502", 5067: "CWE-502", 5367: "CWE-502",
    6073: "CWE-1336", 5373: "CWE-1336",
}


def _install_deps(t: Target, site: Path) -> None:
    """pip-install the target's third-party packages so Pyre can resolve them."""
    marker = site / ".installed"
    wanted = "\n".join(sorted(t.pysa_deps))
    if marker.exists() and marker.read_text() == wanted:
        return
    site.mkdir(parents=True, exist_ok=True)
    if t.pysa_deps:
        subprocess.run([sys.executable, "-m", "pip", "install", "--quiet", "--no-deps",
                        "--target", str(site), *t.pysa_deps], check=True)
    marker.write_text(wanted)


def _config(t: Target, work: Path, site: Path) -> Path:
    sources = [str(t.src / p) for p in (t.pysa_sources or t.scan_paths or ["."])]
    cfg = {
        "source_directories": sources,
        "search_path": [str(site)],
        "taint_models_path": [str(PYRE_LIB / "taint"), str(PYRE_LIB / "third_party_taint"),
                              str(CUSTOM_MODELS)],
        "typeshed": str(PYRE_LIB / "typeshed"),
        "site_package_search_strategy": "none",
        "exclude": [r".*/migrations/.*", r".*/tests?/.*"],
    }
    work.mkdir(parents=True, exist_ok=True)
    (work / ".pyre_configuration").write_text(json.dumps(cfg, indent=2))
    return work


def run(t: Target, raw_out: Path) -> list[Finding]:
    key = t.key.replace("@", "_")
    site = CACHE / key / "site"
    _install_deps(t, site)
    work = _config(t, CACHE / key / "project", site)
    results = CACHE / key / "results"
    proc = subprocess.run(
        ["pyre", "--noninteractive", "analyze", "--no-verify", "--save-results-to", str(results)],
        cwd=work, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f"pysa failed ({proc.returncode}): {proc.stderr[-3000:]}")
    issues = []
    for f in sorted(results.glob("taint-output*.json")):
        for line in f.read_text().splitlines():
            if not line.strip():
                continue
            row = json.loads(line)
            if row.get("kind") == "issue":
                issues.append(row["data"])
    raw_out.parent.mkdir(parents=True, exist_ok=True)
    raw_out.write_text(json.dumps(issues, indent=2))
    return parse(issues, t)


def _rel(t: Target, path: str) -> str:
    p = Path(path)
    if p.is_absolute():
        try:
            p = p.relative_to(t.src)
        except ValueError:
            pass
    return str(p).replace("\\", "/")


def _pos(root: dict) -> dict:
    """A trace root's location: the call site for a call frame, else the origin."""
    return root.get("call", {}).get("position") or root.get("origin") or {}


def _path(loc: dict, default: str = "") -> str:
    # file_version 3 writes filename "*" and puts the real path in "path".
    name = loc.get("filename", default)
    return loc.get("path", name) if name in ("*", "") else name


def _issue_path(issue: dict) -> str:
    """The file of the issue's callable: taken from the sink-side trace root."""
    for trace in sorted(issue.get("traces", []), key=lambda tr: tr.get("name") != "backward"):
        for root in trace.get("roots", []):
            path = _path(_pos(root))
            if path:
                return path
    return issue.get("filename", "")


def _trace(t: Target, issue: dict) -> list[TraceStep]:
    """Flatten Pysa's forward (toward the source) and backward (toward the sink) roots."""
    steps: list[TraceStep] = []
    for trace in sorted(issue.get("traces", []), key=lambda tr: tr.get("name") != "forward"):
        role = "source" if trace.get("name") == "forward" else "sink"
        for root in trace.get("roots", []):
            loc = _pos(root)
            if not loc:
                continue
            leaves = [leaf.get("name", "") for k in root.get("kinds", []) for leaf in k.get("leaves", [])]
            via = root.get("call", {}).get("resolves_to", [])
            note = ", ".join(dict.fromkeys(via or leaves))
            steps.append(TraceStep(file=_rel(t, _path(loc)), line=loc.get("line", 0),
                                   note=f"{role}: {note}"[:200]))
    return steps


def _cwe(issue: dict) -> str:
    """Map the rule code to a CWE. Pysa's RemoteCodeExecution sink covers both
    shell execution and eval/exec, so eval-like sinks are re-tagged CWE-95."""
    cwe = CODE_CWE.get(issue["code"], "CWE-UNKNOWN")
    if cwe == "CWE-78":
        callee = issue.get("sink_handle", {}).get("callee", "")
        leaves = [leaf.get("name", "") for tr in issue.get("traces", []) if tr.get("name") == "backward"
                  for root in tr.get("roots", []) for k in root.get("kinds", []) for leaf in k.get("leaves", [])]
        names = " ".join([callee, *leaves])
        if re.search(r"(^|[ .])(eval|exec)\b", names) and "subprocess" not in names:
            return "CWE-95"
    return cwe


def _line(t: Target, rel: str, n: int) -> str:
    try:
        return (t.src / rel).read_text(errors="replace").splitlines()[n - 1]
    except (OSError, IndexError):
        return ""


def parse(issues: list[dict], t: Target) -> list[Finding]:
    """Pysa analyzes whole packages; keep only issues inside the target's scan_paths."""
    prefixes = [p.rstrip("/") + "/" for p in t.scan_paths]
    out = []
    for i in issues:
        path = _issue_path(i)
        rel = _rel(t, path)
        if Path(path).is_absolute() and not Path(path).is_relative_to(t.src):
            continue  # inside an installed dependency
        if prefixes and not any(rel.startswith(p) for p in prefixes):
            continue
        out.append(Finding(
            tool="pysa",
            ruleset="pysa",
            rule_id=f"pysa-{i['code']}",
            cwe=_cwe(i),
            file=rel,
            line=i["line"],
            end_line=i["line"],
            message=f"{i.get('message', '')} [{i.get('callable', '')}]",
            snippet=_line(t, rel, i["line"]),
            trace=_trace(t, i),
        ))
    return out
