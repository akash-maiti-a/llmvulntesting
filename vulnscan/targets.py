"""Target manifest (targets/targets.yaml) and source checkout helpers."""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from . import ROOT, TARGETS_SRC

MANIFEST = ROOT / os.environ.get("VULNSCAN_MANIFEST", "targets/targets.yaml")


@dataclass
class Target:
    name: str
    lang: str  # "php" | "python" | "mixed"
    repo: str | None = None
    ref: str | None = None  # branch/tag/commit for app targets
    fix_commit: str | None = None  # CVE targets: the upstream fix
    cve: str | None = None
    cwe: str | None = None
    path: str | None = None  # local targets (synthetic suite)
    scan_paths: list[str] = field(default_factory=list)  # limit the scan to these subdirs
    pysa_sources: list[str] = field(default_factory=list)  # pyre source dirs, default scan_paths or "."
    pysa_deps: list[str] = field(default_factory=list)  # pip packages Pyre needs to resolve calls
    exclude: list[str] = field(default_factory=list)
    variant: str = ""  # "", "vuln" or "fixed" (CVE targets expand into both)

    @property
    def is_cve(self) -> bool:
        return self.fix_commit is not None

    @property
    def key(self) -> str:
        return f"{self.name}@{self.variant}" if self.variant else self.name

    @property
    def src(self) -> Path:
        if self.path:
            return ROOT / self.path
        return TARGETS_SRC / self.key

    def langs(self) -> list[str]:
        return ["php", "python"] if self.lang == "mixed" else [self.lang]


def load_targets(names: list[str] | None = None) -> list[Target]:
    raw = yaml.safe_load(MANIFEST.read_text())["targets"]
    out: list[Target] = []
    for entry in raw:
        t = Target(**entry)
        if names and t.name not in names and not any(n.startswith(t.name + "@") for n in names):
            continue
        if t.is_cve:
            for variant in ("vuln", "fixed"):
                v = Target(**{**entry, "variant": variant})
                if not names or v.name in names or v.key in names:
                    out.append(v)
        else:
            out.append(t)
    return out


def _git(*args: str, cwd: Path | None = None) -> str:
    return subprocess.run(
        ["git", *args], cwd=cwd, check=True, capture_output=True, text=True
    ).stdout.strip()


def fetch(t: Target) -> str:
    """Clone/checkout a target. Returns the resolved commit sha."""
    if t.path:
        return "local"
    dest = t.src
    if not (dest / ".git").exists():
        dest.parent.mkdir(parents=True, exist_ok=True)
        _git("clone", "--quiet", "--filter=blob:none", t.repo, str(dest))
    if t.is_cve:
        ref = t.fix_commit if t.variant == "fixed" else f"{t.fix_commit}^"
    else:
        ref = t.ref or "HEAD"
    _git("-c", "advice.detachedHead=false", "checkout", "--quiet", "--force", ref, cwd=dest)
    return _git("rev-parse", "HEAD", cwd=dest)


def fix_diff_lines(t: Target, side: str = "old") -> dict[str, list[int]]:
    """For a CVE target: lines the fix touched, keyed by file.

    side="old": lines in the *vulnerable* version that the fix removed or
    modified. These become ground-truth positives on `@vuln`.
    side="new": lines in the *fixed* version that the fix added or modified.
    A finding there on `@fixed` is a false positive on patched code."""
    repo = TARGETS_SRC / f"{t.name}@vuln"
    diff = _git("diff", "--unified=0", f"{t.fix_commit}^", t.fix_commit, cwd=repo)
    lines: dict[str, list[int]] = {}
    old_file = new_file = None
    for row in diff.splitlines():
        if row.startswith("--- "):
            old_file = row[6:] if row.startswith("--- a/") else None
        elif row.startswith("+++ "):
            new_file = row[6:] if row.startswith("+++ b/") else None
        elif row.startswith("@@"):
            # @@ -start,count +start,count @@
            old, new = row.split()[1][1:], row.split()[2][1:]
            current, span = (old_file, old) if side == "old" else (new_file, new)
            if not current:
                continue
            start, _, count = span.partition(",")
            n = int(count) if count else 1
            s = int(start)
            # Pure additions/removals (n == 0) anchor at the line before the change.
            lines.setdefault(current, []).extend(range(s, s + n) if n else [max(s, 1)])
    return lines
