"""CWE normalization. Matching is done on families so that e.g. a Semgrep
CWE-78 (OS command injection) finding matches a ground-truth CWE-77 entry."""

from __future__ import annotations

import re

FAMILIES: dict[str, set[str]] = {
    "sqli": {"CWE-89", "CWE-564", "CWE-943"},
    "cmdi": {"CWE-77", "CWE-78", "CWE-88"},
    "xss": {"CWE-79", "CWE-80", "CWE-116"},
    "path": {"CWE-22", "CWE-23", "CWE-36", "CWE-73", "CWE-98"},
    "code": {"CWE-94", "CWE-95", "CWE-1336"},  # eval / SSTI
    "deser": {"CWE-502"},
    "redirect": {"CWE-601"},
    "ssrf": {"CWE-918"},
    "xxe": {"CWE-611"},
    "upload": {"CWE-434"},
    "csrf": {"CWE-352"},
    "crypto": {"CWE-327", "CWE-328", "CWE-916", "CWE-330", "CWE-338"},
    "auth": {"CWE-287", "CWE-307", "CWE-798", "CWE-521", "CWE-384", "CWE-613"},
    "idor": {"CWE-639", "CWE-284", "CWE-285", "CWE-862", "CWE-863"},
    "info": {"CWE-200", "CWE-209", "CWE-532"},
}

_CWE_RE = re.compile(r"CWE-(\d+)", re.I)


def normalize(raw) -> str:
    """Return the first 'CWE-<n>' found in a string or list, else 'CWE-UNKNOWN'."""
    if isinstance(raw, (list, tuple)):
        raw = " ".join(map(str, raw))
    m = _CWE_RE.search(str(raw or ""))
    return f"CWE-{m.group(1)}" if m else "CWE-UNKNOWN"


def family(cwe: str) -> str:
    for name, members in FAMILIES.items():
        if cwe in members:
            return name
    return cwe


def same_family(a: str, b: str) -> bool:
    return family(a) == family(b)
