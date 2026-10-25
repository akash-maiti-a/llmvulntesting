"""Ground truth: groundtruth/<target>.yaml for app and local targets, and the
fix diff for CVE targets.

An entry is a known flaw (vulnerable: true) or a known-safe region
(vulnerable: false) with a CWE and one or more locations. A location without
`lines` covers the whole file."""

from __future__ import annotations

import os
from dataclasses import dataclass, field

import yaml

from . import ROOT
from .cwe import family
from .targets import Target, fix_diff_lines

GT_DIR = ROOT / os.environ.get("VULNSCAN_GT", "groundtruth")
WHOLE_FILE = (1, 10**9)


@dataclass
class Location:
    file: str
    start: int = WHOLE_FILE[0]
    end: int = WHOLE_FILE[1]

    def contains(self, file: str, line: int) -> bool:
        return file == self.file and self.start <= line <= self.end


@dataclass
class Entry:
    id: str
    cwe: str
    vulnerable: bool
    scope: str = "taint"  # "taint" | "other" | "client"
    locations: list[Location] = field(default_factory=list)
    note: str = ""
    # Exhaustive ground truth claims to list every flaw in the files it covers,
    # so other findings there are false positives. CVE ground truth only knows
    # the fixed lines, so other findings in those files stay unlabelled.
    exhaustive: bool = True

    @property
    def family(self) -> str:
        return family(self.cwe)

    def covers(self, file: str, line: int) -> bool:
        return any(loc.contains(file, line) for loc in self.locations)


def _from_yaml(raw: dict) -> Entry:
    locs = []
    for loc in raw.get("locations", []):
        start, end = loc.get("lines", WHOLE_FILE)
        locs.append(Location(loc["file"], start, end))
    return Entry(id=raw["id"], cwe=raw["cwe"], vulnerable=raw["vulnerable"],
                 scope=raw.get("scope", "taint"), locations=locs, note=raw.get("note", ""),
                 exhaustive=raw.get("exhaustive", True))


def _cve_entries(t: Target) -> list[Entry]:
    """@vuln: the lines the fix removed or changed are one positive.
    @fixed: the lines the fix added or changed are one negative (patched code)."""
    side = "old" if t.variant == "vuln" else "new"
    lines = fix_diff_lines(t, side=side)
    prefixes = [p.rstrip("/") for p in t.scan_paths]
    locs = []
    for file, nums in sorted(lines.items()):
        if prefixes and not any(file == p or file.startswith(p + "/") for p in prefixes):
            continue
        for n in sorted(set(nums)):
            locs.append(Location(file, n, n))
    return [Entry(id=f"{t.cve}@{t.variant}", cwe=t.cwe or "CWE-UNKNOWN",
                  vulnerable=t.variant == "vuln", scope="taint", locations=locs, exhaustive=False,
                  note=f"{t.cve}: lines {'removed/changed' if side == 'old' else 'added/changed'} by fix {t.fix_commit[:10]}")]


def load(t: Target) -> list[Entry]:
    if t.is_cve:
        return _cve_entries(t)
    path = GT_DIR / f"{t.name}.yaml"
    if not path.exists():
        return []
    return [_from_yaml(e) for e in yaml.safe_load(path.read_text())["entries"]]
