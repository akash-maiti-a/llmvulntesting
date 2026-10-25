"""Training corpus: intentionally vulnerable apps and test suites that are NOT
evaluation targets, copied into training/data/<name> with label hints removed,
plus ground truth in training/groundtruth/<name>.yaml and a manifest
(training/targets.yaml) that the normal pipeline can scan:

    python -m vulnscan.rl.corpus            # build training/data, groundtruth, manifest
    VULNSCAN_MANIFEST=training/targets.yaml VULNSCAN_GT=training/groundtruth \
    VULNSCAN_RESULTS=training/results vulnscan scan

Label hints are removed because a model trained on them would learn to read
comments instead of code: SARD files open with "Safe sample / sanitize: ...",
django.nV with "PURPOSELY INSECURE", and BenchmarkPython's safe cases use
string constants such as 'safe!' far more often than its vulnerable ones.
Comment lines are blanked rather than deleted, so line numbers (and line-level
labels) are unchanged.

Ground truth entries here are not exhaustive: each source only vouches for the
flaw class it documents, so an alert of another class stays unlabelled."""

from __future__ import annotations

import csv
import hashlib
import json
import os
import random
import re
import shutil
import subprocess
from collections import defaultdict
from functools import lru_cache
from pathlib import Path

import yaml

from .. import ROOT

TRAIN = ROOT / "training"
SRC = TRAIN / "src"
DATA = TRAIN / "data"
GT = TRAIN / "groundtruth"
MANIFEST = TRAIN / "targets.yaml"

HINT = re.compile(r"secur|vulnerab|exploit|unsafe|safe|purpose|sanitiz|inject|xss|attack|fix|bug|hint|"
                  r"dangerous|malicious|tainted|payload|flaw|weakness|cwe|idor|redirect|owasp|csrf|sqli|traversal|"
                  r"\bA\d+:|\b(rce|lfi|rfi)\b", re.I)


# --- cleaning ---------------------------------------------------------------------------------
# A removed comment becomes an empty line, never a bare marker: SARD's safe cases
# have an empty line where its unsafe cases say "//flaw", so even "//" would leak.

BLOCKS = (("/*", "*/"), ("<!--", "-->"))


def clean_php(text: str, strip_all: bool = False) -> str:
    """Empty //, # comment lines and /* */, <!-- --> blocks that mention a hint word
    (every comment when strip_all, used for generated suites such as SARD)."""
    lines = text.split("\n")
    out, i = [], 0
    while i < len(lines):
        s = lines[i].lstrip()
        block_end = next((end for start, end in BLOCKS if s.startswith(start)), None)
        if block_end:
            j = i
            while j < len(lines) and block_end not in lines[j]:
                j += 1
            block = lines[i:j + 1]
            trailing = block[-1].split(block_end, 1)[1].strip() if block_end in block[-1] else ""
            if (strip_all or any(HINT.search(b) for b in block)) and not trailing:
                out += [""] * len(block)
            else:
                out += block
            i = j + 1
            continue
        if s.startswith(("//", "#")) and (strip_all or HINT.search(s)):
            out.append("")
        else:
            out.append(re.sub(r"\s//[^'\"]*$", lambda m: "" if strip_all or HINT.search(m.group()) else m.group(),
                              lines[i]))
        i += 1
    return "\n".join(out)


def clean_py(text: str) -> str:
    """Empty # comment lines (and trailing # comments) that mention a hint word."""
    out = []
    for line in text.split("\n"):
        s = line.lstrip()
        if s.startswith("#") and HINT.search(s):
            out.append("")
        else:
            out.append(re.sub(r"\s#[^'\"]*$", lambda m: "" if HINT.search(m.group()) else m.group(), line))
    return "\n".join(out)


def neutralise_strings(text: str) -> str:
    """'safe!' -> 'const!' inside string literals only (imports such as markupsafe stay)."""
    return re.sub(r"(['\"])([^'\"\n]*?)safe([^'\"\n]*?)\1",
                  lambda m: f"{m.group(1)}{m.group(2)}const{m.group(3)}{m.group(1)}", text, flags=re.I)


def _write(dest: Path, text: str) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(text, encoding="utf-8", newline="\n")


def _copy_tree(src: Path, dest: Path, exts: tuple[str, ...], skip: tuple[str, ...] = ()) -> list[Path]:
    out = []
    for p in sorted(src.rglob("*")):
        rel = p.relative_to(src).as_posix()
        if not p.is_file() or p.suffix not in exts or any(s in f"/{rel}" for s in skip):
            continue
        text = p.read_text(encoding="utf-8", errors="replace")
        text = clean_py(text) if p.suffix == ".py" else clean_php(text) if p.suffix == ".php" else text
        _write(dest / rel, text)
        out.append(dest / rel)
    return out


def _entry(id_, cwe, vulnerable, file, lines=None, scope="taint", note=""):
    loc = {"file": file, **({"lines": list(lines)} if lines else {})}
    return {"id": id_, "cwe": cwe, "vulnerable": vulnerable, "scope": scope, "exhaustive": False,
            "locations": [loc], "note": note}


def _func_range(path: Path, name: str) -> tuple[int, int]:
    """1-based line range of def <name> in a Python file (decorators excluded)."""
    lines = path.read_text(encoding="utf-8").split("\n")
    for i, s in enumerate(lines):
        if re.match(rf"\s*def\s+{name}\s*\(", s):
            indent = len(s) - len(s.lstrip())
            end = i + 1
            while end < len(lines) and (not lines[end].strip() or len(lines[end]) - len(lines[end].lstrip()) > indent):
                end += 1
            return i + 1, end
    raise ValueError(f"def {name} not found in {path}")


def _line_of(path: Path, needle: str) -> int:
    for i, s in enumerate(path.read_text(encoding="utf-8").split("\n"), 1):
        if needle in s:
            return i
    raise ValueError(f"{needle!r} not found in {path}")


# --- sources ----------------------------------------------------------------------------------

def benchmarkpython() -> tuple[dict, list[dict]]:
    src, dest = SRC / "BenchmarkPython", DATA / "benchmarkpython"
    _copy_tree(src / "helpers", dest / "helpers", (".py",))
    entries = []
    with open(src / "expectedresults-0.1.csv") as fh:
        for row in csv.reader(fh):
            if row[0].startswith("#"):
                continue
            name, cat, real, cwe = (c.strip() for c in row[:4])
            text = (src / "testcode" / f"{name}.py").read_text(encoding="utf-8")
            _write(dest / "testcode" / f"{name}.py", neutralise_strings(clean_py(text)))
            entries.append(_entry(f"bp-{name[-5:]}", f"CWE-{cwe}", real == "true", f"testcode/{name}.py",
                                  note=cat))
    target = {"name": "benchmarkpython", "lang": "python", "path": "training/data/benchmarkpython",
              "scan_paths": ["testcode"], "pysa_sources": ["."],
              "pysa_deps": ["flask==1.1.4", "werkzeug==1.0.1", "jinja2==2.11.3", "markupsafe==1.1.1",
                            "itsdangerous==1.1.0", "click==7.1.2", "lxml", "pyyaml", "requests", "ldap3"]}
    return target, entries


SARD_SKIP = {"862"}  # "missing authorization" cases wrap SQL/file code; their sinks are not the flaw


def sard_php(per_bucket: int = 500, seed: int = 0, safe_only: bool = True) -> tuple[dict, list[dict]]:
    """NIST SARD PHP Vulnerability Test Suite: one file per case, each a single
    source -> sanitizer -> sink program with exactly one flaw (or none) of its CWE.
    Only the safe cases are used (safe_only): a hand audit of 30 labelled alerts agreed
    with 13, because many "unsafe" cases are not exploitable (FILTER_SANITIZE_SPECIAL_CHARS
    output inside single quotes, include paths that start with a literal quote, eval code
    that cannot parse), while the safe labels held up.
    Entries cover the whole file: the manifest marks the line where the tainted value
    is built, while scanners report the sink call a few lines later. Sampled evenly
    per (CWE, safe/unsafe), spreading the sample over the sanitizers case names record."""
    src, dest = SRC / "sard-php", DATA / "sard-php"
    buckets: dict[tuple[str, bool], dict[str, list]] = defaultdict(lambda: defaultdict(list))
    for man in sorted(src.glob("*/manifest.sarif")):
        run = json.loads(man.read_text(encoding="utf-8"))["runs"][0]
        uri = run["artifacts"][0]["location"]["uri"]
        # src/CWE_89__<input>__<sanitizer>__<construction>.php; parts may contain single underscores
        parts = uri.removeprefix("src/").removesuffix(".php").split("__")
        m = re.match(r"CWE_(\d+)", parts[0])
        if not m or m.group(1) in SARD_SKIP or len(parts) < 3:
            continue
        cwe, sanitizer = m.group(1), parts[2]
        bad = run["properties"]["state"] == "bad"
        lines = [loc["physicalLocation"]["region"]["startLine"]
                 for r in run.get("results", []) for loc in r["locations"]]
        if bad and (safe_only or not lines):
            continue
        buckets[(cwe, bad)][sanitizer].append((man.parent, uri, lines))
    rng = random.Random(seed)
    entries = []
    for (cwe, bad), by_sanitizer in sorted(buckets.items()):
        pools = [rng.sample(v, len(v)) for _, v in sorted(by_sanitizer.items())]
        picked = []
        while len(picked) < per_bucket and any(pools):
            for pool in pools:  # round-robin over sanitizers
                if pool and len(picked) < per_bucket:
                    picked.append(pool.pop())
        for case, uri, lines in picked:
            cid = case.name.split("-")[0]
            rel = f"CWE-{cwe}/{cid}.php"
            text = clean_php((case / uri).read_text(encoding="utf-8", errors="replace"), strip_all=True)
            # Every SARD case names its variable $tainted; with safe cases only, that name
            # would itself predict the label.
            _write(dest / rel, re.sub(r"\$tainted\b", "$data", text))
            span = None
            entries.append(_entry(f"sard-{cid}", f"CWE-{cwe}", bad, rel, span))
    target = {"name": "sard-php", "lang": "php", "path": "training/data/sard-php"}
    return target, entries


XVWA_CWE = {"cmdi": "CWE-78", "sqli": "CWE-89", "sqli_blind": "CWE-89", "reflected_xss": "CWE-79",
            "stored_xss": "CWE-79", "fi": "CWE-98", "redirect": "CWE-601", "ssrf_xspa": "CWE-918",
            "ssti": "CWE-1336", "php_object_injection": "CWE-502", "xpath": "CWE-643", "crypto": "CWE-327",
            "fileupload": "CWE-434"}


def xvwa() -> tuple[dict, list[dict]]:
    """XVWA: one vulnerable module per directory, documented by the module name."""
    src, dest = SRC / "xvwa", DATA / "xvwa"
    for p in _copy_tree(src, dest, (".php",), skip=("/vendor/", "/setup/")):
        # Page text names the attack ("OS Command Injection") next to the code; empty
        # those pure-HTML lines, since every XVWA label is "vulnerable".
        lines = p.read_text(encoding="utf-8").split("\n")
        lines = ["" if "<?" not in s and "$" not in s and ";" not in s and HINT.search(s) else s
                 for s in lines]
        _write(p, "\n".join(lines).replace("Xtreme Vulnerable Web Application", "Example Web Application"))
    entries = []
    for d, cwe in XVWA_CWE.items():
        for p in sorted((dest / "vulnerabilities" / d).glob("*.php")):
            if p.name == "index.php":
                continue  # page chrome only
            rel = p.relative_to(dest).as_posix()
            entries.append(_entry(f"xvwa-{d}-{p.stem}", cwe, True, rel, note=d))
    target = {"name": "xvwa", "lang": "php", "path": "training/data/xvwa", "scan_paths": ["vulnerabilities"]}
    return target, entries


def dsvw() -> tuple[dict, list[dict]]:
    """DSVW: one file; each attack case is one branch, located by its code."""
    dest = DATA / "dsvw"
    _write(dest / "dsvw.py", clean_py((SRC / "DSVW" / "dsvw.py").read_text(encoding="utf-8")))
    p = dest / "dsvw.py"
    cases = [
        ("sqli-id", "CWE-89", 'WHERE id=" + params["id"]'),
        ("sqli-comment", "CWE-89", "INSERT INTO comments VALUES(NULL, '%s'"),
        ("sqli-login", "CWE-89", "WHERE username='\" + re.sub"),
        ("xss-v", "CWE-79", 'params["v"]'),
        ("xss-callback", "CWE-79", 'params["callback"]'),
        ("deser", "CWE-502", "pickle.loads("),
        ("path", "CWE-22", 'open(os.path.abspath(params["path"])'),
        ("ssrf", "CWE-918", 'FETCH(params["path"])'),
        ("cmdi", "CWE-78", '"nslookup " + params["domain"]'),
        ("xxe", "CWE-611", "resolve_entities=True"),
        ("xpath", "CWE-643", "xpath(\".//user[name/text()='%s']\""),
        ("include", "CWE-94", "exec(program, envs)"),
        ("tmpl", "CWE-1336", 'params["tmpl"].format('),
    ]
    entries = []
    for cid, cwe, needle in cases:
        try:
            n = _line_of(p, needle)
        except ValueError:
            continue  # upstream changed; the case is simply not labelled
        entries.append(_entry(f"dsvw-{cid}", cwe, True, "dsvw.py", (n, n)))
    target = {"name": "dsvw", "lang": "python", "path": "training/data/dsvw", "pysa_sources": ["."]}
    return target, entries


def django_nv() -> tuple[dict, list[dict]]:
    """django.nV: flaws as located by the app's own tutorial pages."""
    src, dest = SRC / "django.nV", DATA / "django.nv"
    _copy_tree(src / "taskManager", dest / "taskManager", (".py", ".html"),
               skip=("/migrations/", "/static/", "/tutorials/"))
    views, misc = dest / "taskManager" / "views.py", dest / "taskManager" / "misc.py"
    entries = [
        _entry("dnv-sqli-upload", "CWE-89", True, "taskManager/views.py", _func_range(views, "upload")),
        _entry("dnv-cmdi-store", "CWE-78", True, "taskManager/misc.py", _func_range(misc, "store_uploaded_file")),
        _entry("dnv-redirect-logout", "CWE-601", True, "taskManager/views.py", _func_range(views, "logout_view")),
        _entry("dnv-authz-groups", "CWE-862", True, "taskManager/views.py", _func_range(views, "manage_groups"),
               scope="other"),
        _entry("dnv-idor-task-delete", "CWE-639", True, "taskManager/views.py", _func_range(views, "task_delete"),
               scope="other"),
    ]
    tpl = dest / "taskManager" / "templates" / "taskManager" / "base_backend.html"
    if tpl.exists():
        n = _line_of(tpl, "user.username|safe")
        entries.append(_entry("dnv-xss-username", "CWE-79", True,
                              "taskManager/templates/taskManager/base_backend.html", (n, n)))
    target = {"name": "django.nv", "lang": "python", "path": "training/data/django.nv",
              "scan_paths": ["taskManager"], "pysa_sources": ["."], "pysa_deps": ["django<2"]}
    return target, entries


VULPY_CWES = ["CWE-89", "CWE-79", "CWE-78", "CWE-22", "CWE-94", "CWE-502", "CWE-601", "CWE-327", "CWE-918"]


def vulpy() -> tuple[dict, list[dict]]:
    """vulpy ships a BAD and a (self-described unfinished) GOOD version of one Flask app.
    Weak labels: code in BAD that GOOD changed is taken as flawed, for whichever flaw
    class an alert there claims. GOOD is not used as negatives, since its author says
    it may still be vulnerable. The accuracy audit decides whether these labels are kept."""
    src, dest = SRC / "vulpy", DATA / "vulpy"
    _copy_tree(src / "bad", dest, (".py", ".html"))
    entries = []
    for p in sorted((src / "bad").glob("*.py")):
        good = src / "good" / p.name
        if not good.exists():
            continue
        diff = subprocess.run(["git", "diff", "--no-index", "--unified=0", str(p), str(good)],
                              capture_output=True, text=True).stdout
        for k, h in enumerate(re.finditer(r"^@@ -(\d+)(?:,(\d+))? ", diff, re.M)):
            start, count = int(h.group(1)), int(h.group(2) or 1)
            if count == 0:
                continue
            for cwe in VULPY_CWES:
                entries.append(_entry(f"vulpy-{p.stem}-{k}-{cwe[4:]}", cwe, True, p.name,
                                      (start, start + count - 1), note="changed in good/"))
    target = {"name": "vulpy", "lang": "python", "path": "training/data/vulpy", "pysa_sources": ["."],
              "pysa_deps": ["flask==1.1.4", "werkzeug==1.0.1", "jinja2==2.11.3", "markupsafe==1.1.1",
                            "itsdangerous==1.1.0", "click==7.1.2"]}
    return target, entries


SOURCES = {"benchmarkpython": benchmarkpython, "sard-php": sard_php, "xvwa": xvwa,
           "django.nv": django_nv, "vulpy": vulpy}

# Candidates that failed the feasibility gate, with the reason (kept for the report).
REJECTED = {
    "Vulnerable-Flask-App (we45)": "no license: all rights reserved",
    "bWAPP (raesene mirror)": "no license on the mirror; upstream terms unclear",
    "Mutillidae II": "no line-level truth: one code path is vulnerable or safe depending on a runtime "
                     "security-level switch",
    "DSVW": "label leak: the program's own data lists every attack by name (CASES), and it is shown "
            "in every prompt; it cannot be removed without editing the program",
}


# --- leakage check ----------------------------------------------------------------------------

def _norm_hash(p: Path) -> str:
    text = re.sub(r"\s+", "", p.read_text(encoding="utf-8", errors="replace"))
    return hashlib.sha1(text.encode()).hexdigest()


@lru_cache(maxsize=1)
def _held_out() -> dict[str, str]:
    """Hashes of every evaluation source file, cached in training/held_out_hashes.json
    (walking the target clones through a Docker bind mount is slow)."""
    cache = TRAIN / "held_out_hashes.json"
    if cache.exists():
        return json.loads(cache.read_text())
    out: dict[str, str] = {}
    for root in (ROOT / "targets" / "src", ROOT / "benchmarks"):
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in (".git", "node_modules")]
            for fn in filenames:
                p = Path(dirpath) / fn
                if p.suffix in (".py", ".php") and p.stat().st_size > 200:
                    out[_norm_hash(p)] = p.relative_to(ROOT).as_posix()
    cache.write_text(json.dumps(out))
    return out


def overlap(name: str) -> list[str]:
    """Training files whose whitespace-normalised content equals an evaluation file."""
    held_out = _held_out()
    hits = []
    for p in (DATA / name).rglob("*"):
        if p.is_file() and p.suffix in (".py", ".php") and p.stat().st_size > 200:
            h = _norm_hash(p)
            if h in held_out:
                hits.append(f"{p.relative_to(DATA).as_posix()} == {held_out[h]}")
    return hits


def leftover_hints(name: str) -> list[str]:
    """Comment lines still carrying a hint word after cleaning (should be empty)."""
    out = []
    for p in (DATA / name).rglob("*"):
        if p.suffix not in (".py", ".php"):
            continue
        for i, s in enumerate(p.read_text(encoding="utf-8").split("\n"), 1):
            t = s.strip()
            m = re.search(r"(//|#|/\*|<!--|^\*).*", t)
            if m and HINT.search(m.group()):
                out.append(f"{p.relative_to(DATA).as_posix()}:{i}: {t[:80]}")
    return out


def build(names: list[str] | None = None) -> dict:
    GT.mkdir(parents=True, exist_ok=True)
    targets, report = [], {}
    for name, fn in SOURCES.items():
        if names and name not in names:
            continue
        if (DATA / name).exists():
            shutil.rmtree(DATA / name)
        target, entries = fn()
        hits = overlap(name)
        if hits:
            raise RuntimeError(f"{name}: training files duplicate evaluation files: {hits[:5]}")
        (GT / f"{name}.yaml").write_text(yaml.safe_dump({"target": name, "entries": entries}, sort_keys=False))
        targets.append(target)
        report[name] = {"entries": len(entries), "vulnerable": sum(e["vulnerable"] for e in entries),
                        "leftover_hints": leftover_hints(name)[:10]}
    if not names:
        MANIFEST.write_text("# Generated by python -m vulnscan.rl.corpus. Training only; never evaluated on.\n"
                            + yaml.safe_dump({"targets": targets}, sort_keys=False))
    return report


if __name__ == "__main__":
    import sys
    print(json.dumps(build(sys.argv[1:] or None), indent=2))
