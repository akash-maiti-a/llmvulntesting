"""LLM triage of findings through a local Ollama server.

Each finding is judged on its own: the prompt carries the rule, CWE, message,
flagged line, dataflow trace and the surrounding source. The file path is
redacted by default, because benchmark paths (".../impossible.php") would leak
the answer. Replies are constrained to a JSON schema, decoding is greedy, and
verdicts are cached per finding ID, so a run can be resumed and repeated.

A failed call (timeout, HTTP error, malformed reply) is recorded with
verdict "error"; evaluation keeps such findings (fail open)."""

from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

import httpx

from .models import Finding
from .targets import Target

OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
MODEL = os.environ.get("VULNSCAN_MODEL", "qwen3:8b")

CWE_NAMES = {
    "CWE-22": "path traversal", "CWE-23": "path traversal", "CWE-73": "external control of a file path",
    "CWE-78": "OS command injection", "CWE-77": "command injection", "CWE-79": "cross-site scripting (XSS)",
    "CWE-89": "SQL injection", "CWE-94": "code injection", "CWE-95": "eval injection",
    "CWE-98": "PHP file inclusion", "CWE-113": "HTTP response splitting", "CWE-134": "format string",
    "CWE-327": "weak cryptography", "CWE-328": "weak hash", "CWE-352": "CSRF",
    "CWE-502": "unsafe deserialization", "CWE-522": "insufficiently protected credentials",
    "CWE-601": "open redirect", "CWE-611": "XML external entities (XXE)", "CWE-798": "hard-coded credentials",
    "CWE-918": "server-side request forgery (SSRF)", "CWE-1336": "server-side template injection",
    "CWE-93": "CRLF injection",
}

PROMPT_V1 = """You are a security engineer triaging static-analysis alerts in a {lang} web app.
Decide whether the alert is a real, exploitable vulnerability (true_positive) or not
(false_positive: input is validated/escaped/parameterized, or the flagged code is not a real sink).

Rule: {rule} ({cwe})
Message: {message}
Flagged line {line}: {snippet}
Taint trace:
{trace}

Source of the file (line-numbered):
{code}
{extra}
Answer ONLY with JSON: {{"verdict": "true_positive" | "false_positive", "confidence": 0-1, "reason": "<one sentence>"}}"""

PROMPT_V2 = """You are a senior application-security engineer triaging ONE static-analysis alert in a {lang} web app.
Judge ONLY {cwe_name} ({cwe}). If the code contains a different kind of flaw, ignore it: it does not make this alert a true positive.

Work through these checks in order:
1. sink_is_real: Is the flagged line, or the call it leads to, actually a dangerous operation for {cwe_name}?
   An assignment, a hash, a log line or a database write is not an XSS output sink. A query whose user values are bound as parameters is not a SQL injection sink.
2. attacker_reaches_sink: Can attacker-controlled input reach that operation on some path? Follow the trace, including calls into other functions.
3. defence_sufficient: Is there a defence on that path that is sufficient for THIS sink and THIS context?
   - String-escaping functions only protect values placed inside quotes. A value used in an unquoted, numeric context is still injectable.
   - HTML escaping protects element content and quoted attributes, not unquoted attributes, JavaScript contexts or URLs.
   - Strict allowlists, integer casts, and format validation that covers the whole value are sufficient defences.
   - Removing a few blocklisted strings (for example "<script>") is not sufficient.
4. verdict: true_positive if attacker input reaches a real sink without a sufficient defence, otherwise false_positive.

Rule: {rule} ({cwe})
Message: {message}
Flagged line {line}: {snippet}
Taint trace:
{trace}

Source of the file (line-numbered):
{code}
{extra}"""

SCHEMA_V1 = {
    "type": "object",
    "properties": {
        "verdict": {"type": "string", "enum": ["true_positive", "false_positive"]},
        "confidence": {"type": "number"},
        "reason": {"type": "string"},
    },
    "required": ["verdict", "confidence", "reason"],
}

SCHEMA_V2 = {
    "type": "object",
    "properties": {
        "sink_is_real": {"type": "boolean"},
        "attacker_reaches_sink": {"type": "boolean"},
        "defence_sufficient": {"type": "boolean"},
        "verdict": {"type": "string", "enum": ["true_positive", "false_positive"]},
        "confidence": {"type": "number"},
        "reason": {"type": "string"},
    },
    "required": ["sink_is_real", "attacker_reaches_sink", "defence_sufficient", "verdict",
                 "confidence", "reason"],
}

# v3 = v2's checks, but the reply opens with free-text analysis. Under v2's
# schema the boolean checks are decoded first, before any reasoning, and the
# model often committed to sink_is_real=false while its trailing "reason"
# argued for a true positive. v3 also shows the bodies of functions called
# from the flagged line and the call sites of the function containing it.
PROMPT_V3 = PROMPT_V2 + """
Reply with JSON. Write "analysis" FIRST: two to four sentences that work through checks 1-3 for this alert.
Then set the three checks and the verdict so that they agree with your analysis.
"confidence" is the probability (0.0 to 1.0) that your verdict is correct."""

SCHEMA_V3 = {
    "type": "object",
    "properties": {"analysis": {"type": "string"},
                   **{k: v for k, v in SCHEMA_V2["properties"].items() if k != "reason"}},
    "required": ["analysis", "sink_is_real", "attacker_reaches_sink", "defence_sufficient", "verdict",
                 "confidence"],
}

PROMPTS = {"v1": (PROMPT_V1, SCHEMA_V1), "v2": (PROMPT_V2, SCHEMA_V2), "v3": (PROMPT_V3, SCHEMA_V3)}


@dataclass
class Config:
    prompt: str = "v2"  # "v1" | "v2"
    think: bool = False
    model: str = MODEL
    redact_paths: bool = True
    timeout: float = 300.0
    num_ctx: int = 12288
    name: str = ""  # overrides the derived tag, e.g. for a partial second pass

    @property
    def tag(self) -> str:
        return self.name or f"{self.prompt}-{'think' if self.think else 'fast'}"


def _numbered(lines: list[str], lo: int, hi: int) -> str:
    return "\n".join(f"{i + 1:5} {lines[i]}" for i in range(lo, hi))


def context(f: Finding, src: Path, max_lines: int = 200) -> tuple[str, str]:
    """The flagged file (whole if short, else a window), plus excerpts of any
    trace steps that fall outside it: Pysa traces can cross files."""
    path = src / f.file
    lines = path.read_text(errors="replace").splitlines()
    if len(lines) <= max_lines:
        lo, hi = 0, len(lines)
    else:
        lo = max(0, f.line - max_lines // 2)
        hi = min(len(lines), lo + max_lines)
    code = _numbered(lines, lo, hi)
    extra = []
    for step in f.trace:
        if step.file == f.file and lo < step.line <= hi:
            continue
        try:
            other = (src / step.file).read_text(errors="replace").splitlines()
        except OSError:
            continue
        a, b = max(0, step.line - 6), min(len(other), step.line + 5)
        label = "this file" if step.file == f.file else "another file in the project"
        extra.append(f"\nExcerpt from {label} (trace step at line {step.line}):\n{_numbered(other, a, b)}")
    return code, "".join(extra)


# A call on the flagged line: optional receiver ("Student.", "$this->", "self.") and a name.
CALL = re.compile(r"(?:([$\w]+)\s*(?:\.|->|::)\s*)?([A-Za-z_]\w*)\s*\(")
NOT_CALLEES = {
    "if", "for", "while", "elif", "return", "and", "or", "not", "in", "print", "str", "int", "len",
    "dict", "list", "set", "tuple", "isinstance", "range", "super", "format", "open", "array",
    "isset", "empty", "echo", "die", "exit", "function", "def", "lambda", "await", "async",
}
DEF = {
    "py": r"^(\s*)(?:async\s+)?def\s+{name}\s*\(",
    "php": r"^(\s*)(?:(?:public|private|protected|static|final|abstract)\s+)*function\s+&?{name}\s*\(",
}
CLASS = re.compile(r"^(\s*)(?:(?:abstract|final)\s+)?class\s+(\w+)")
SELF = {"self", "cls", "$this", "static", "parent"}


@lru_cache(maxsize=None)
def _scope_files(src: Path, scan_paths: tuple[str, ...], ext: str) -> tuple[Path, ...]:
    roots = [src / p for p in scan_paths] or [src]
    out = []
    for r in roots:
        out.extend([r] if r.is_file() else sorted(r.rglob(f"*.{ext}")))
    return tuple(p for p in out if p.suffix == f".{ext}" and "/vendor/" not in p.as_posix())


@lru_cache(maxsize=None)
def _lines(path: Path) -> tuple[str, ...]:
    return tuple(path.read_text(errors="replace").splitlines())


def _indent(s: str) -> int:
    return len(s) - len(s.lstrip())


def _body(lines: tuple[str, ...], start: int, ext: str, cap: int) -> int:
    """End (exclusive) of the function defined at line index `start`."""
    if ext == "py":
        indent = _indent(lines[start])
        end = start + 1
        while end < len(lines) and end - start < cap:
            s = lines[end]
            if s.strip() and _indent(s) <= indent:
                break
            end += 1
        return end
    depth, seen = 0, False
    for end in range(start, min(len(lines), start + cap)):
        depth += lines[end].count("{") - lines[end].count("}")
        seen = seen or "{" in lines[end]
        if seen and depth <= 0:
            return end + 1
    return min(len(lines), start + cap)


def _owner(lines: tuple[str, ...], i: int, ext: str) -> str | None:
    """Name of the class a definition at line index i belongs to, if any."""
    indent = _indent(lines[i])
    for j in range(i - 1, -1, -1):
        m = CLASS.match(lines[j])
        if m and (ext == "php" or len(m.group(1)) < indent):
            return m.group(2)
        if ext == "py" and lines[j].strip() and _indent(lines[j]) < indent and not CLASS.match(lines[j]):
            if not lines[j].lstrip().startswith(("@", "#")):
                return None
    return None


def _in_string(s: str, pos: int) -> bool:
    before = s[:pos]
    return before.count('"') % 2 == 1 or before.count("'") % 2 == 1


def _defs(files: tuple[Path, ...], name: str, ext: str) -> list[tuple[Path, int]]:
    pat = re.compile(DEF[ext].format(name=re.escape(name)))
    return [(p, i) for p in files for i, s in enumerate(_lines(p)) if pat.match(s)]


def related(f: Finding, t: Target, max_funcs: int = 3, cap: int = 40) -> str:
    """Bodies of functions called on the flagged line (and Pysa sink callees),
    plus the call sites of the function that contains the flagged line.

    Resolution is by name, so it is kept conservative: a call qualified by a
    class name ("Student.create") only matches a method of that class, a call
    on self/$this only matches in the same file, and an unqualified call or a
    call on a variable only matches when the name has a single definition."""
    ext = Path(f.file).suffix.lstrip(".")
    if ext not in DEF:
        return ""
    files = _scope_files(t.src, tuple(t.scan_paths), ext)
    calls = [(m.group(1), m.group(2)) for m in CALL.finditer(f.snippet) if not _in_string(f.snippet, m.start(2))]
    for step in f.trace:
        if step.note.startswith("sink: "):
            for full in step.note[6:].split(", "):
                parts = full.split(".")
                calls.append((parts[-2] if len(parts) > 1 else None, parts[-1]))
    out: list[str] = []
    seen: set[tuple[Path, int]] = set()
    for recv, name in dict.fromkeys(calls):
        if name in NOT_CALLEES or len(name) < 3 or len(seen) >= max_funcs:
            continue
        defs = _defs(files, name, ext)
        if recv and recv[:1].isupper():
            defs = [(p, i) for p, i in defs if _owner(_lines(p), i, ext) == recv]
        elif recv in SELF:
            defs = [(p, i) for p, i in defs if p == t.src / f.file]
        elif len(defs) != 1:
            continue
        for p, i in defs[:1]:
            lines = _lines(p)
            end = _body(lines, i, ext, cap)
            rel = p.relative_to(t.src).as_posix()
            if (p, i) in seen or (rel == f.file and i < f.line <= end):
                continue  # already shown, or the flagged line is inside it
            seen.add((p, i))
            where = "this file" if rel == f.file else f"another file in the project"
            out.append(f"\nDefinition of {name}() called from the flagged line ({where}):\n"
                       f"{_numbered(list(lines), i, end)}")
    # Call sites of the enclosing function (nearest less-indented def above the line).
    flagged = _lines(t.src / f.file)
    if not 0 < f.line <= len(flagged):
        return "".join(out)
    indent = _indent(flagged[f.line - 1])
    anydef = re.compile(DEF[ext].format(name=r"(\w+)"))
    enclosing = None
    for i in range(f.line - 1, -1, -1):
        m = anydef.match(flagged[i])
        if m and (ext == "php" or len(m.group(1)) < indent):
            enclosing = m.group(2)
            break
    if not enclosing or enclosing.startswith("__") or len(_defs(files, enclosing, ext)) != 1:
        return "".join(out)
    call = re.compile(rf"(?<![\w$]){re.escape(enclosing)}\s*\(")
    sites = 0
    for p in files:
        lines = _lines(p)
        for i, s in enumerate(lines):
            m = call.search(s)
            if sites >= 2 or not m or anydef.match(s) or _in_string(s, m.start()):
                continue
            rel = p.relative_to(t.src).as_posix()
            where = "this file" if rel == f.file else "another file in the project"
            out.append(f"\nCall site of {enclosing}(), the function containing the flagged line ({where}):\n"
                       f"{_numbered(list(lines), max(0, i - 6), min(len(lines), i + 3))}")
            sites += 1
    return "".join(out)


def build_prompt(f: Finding, t: Target, cfg: Config) -> str:
    template, _ = PROMPTS[cfg.prompt]
    code, extra = context(f, t.src)
    if cfg.prompt == "v3":
        extra += related(f, t)
    ext = Path(f.file).suffix.lstrip(".")
    lang = {"php": "PHP", "py": "Python"}.get(ext, ext)
    trace = "\n".join(f"  line {s.line}: {s.note}" for s in f.trace) or "  (no trace)"
    message = f.message
    if not cfg.redact_paths:
        message = f"{message}\nFile: {f.file}"
    return template.format(lang=lang, rule=f.rule_id.split(".")[-1], cwe=f.cwe,
                           cwe_name=CWE_NAMES.get(f.cwe, f.cwe), message=message, line=f.line,
                           snippet=f.snippet.strip()[:400], trace=trace, code=code, extra=extra)


def ask(prompt: str, cfg: Config, client: httpx.Client) -> dict:
    _, schema = PROMPTS[cfg.prompt]
    body = {"model": cfg.model, "stream": False, "think": cfg.think, "format": schema,
            "options": {"temperature": 0, "num_ctx": cfg.num_ctx},
            "messages": [{"role": "user", "content": prompt}]}
    t0 = time.time()
    try:
        r = client.post(f"{OLLAMA_HOST}/api/chat", json=body, timeout=cfg.timeout)
        r.raise_for_status()
        reply = r.json()
    except (httpx.HTTPError, ValueError) as e:
        return {"verdict": "error", "error": f"{type(e).__name__}: {e}"[:300],
                "secs": round(time.time() - t0, 1)}
    try:
        v = json.loads(reply["message"]["content"])
    except (KeyError, json.JSONDecodeError):
        v = {"verdict": "error", "error": "unparsable reply",
             "raw": str(reply.get("message", {}).get("content", ""))[:300]}
    if "analysis" in v and "reason" not in v:
        v["reason"] = v["analysis"]  # v3 replies; reports read "reason"
    if v.get("verdict") not in ("true_positive", "false_positive"):
        v = {**v, "verdict": "error", "error": v.get("error", "no verdict in reply")}
    v["secs"] = round(time.time() - t0, 1)
    v["eval_tokens"] = reply.get("eval_count")
    return v


def cache_path(results: Path, t: Target, cfg: Config) -> Path:
    return results / t.key / f"triage-{cfg.tag}.json"


def load_verdicts(results: Path, t: Target, tag: str) -> dict[str, dict]:
    p = results / t.key / f"triage-{tag}.json"
    return json.loads(p.read_text()) if p.exists() else {}


def run(t: Target, findings: list[Finding], cfg: Config, results: Path, progress=None) -> dict[str, dict]:
    """Triage every finding not already in the cache; returns id -> verdict."""
    out = cache_path(results, t, cfg)
    verdicts: dict[str, dict] = json.loads(out.read_text()) if out.exists() else {}
    todo = [f for f in {f.id: f for f in findings}.values() if f.id not in verdicts]
    with httpx.Client() as client:
        for i, f in enumerate(todo, 1):
            v = ask(build_prompt(f, t, cfg), cfg, client)
            v.update(model=cfg.model, prompt=cfg.prompt, think=cfg.think)
            verdicts[f.id] = v
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(json.dumps(verdicts, indent=2))
            if progress:
                progress(i, len(todo), f, v)
    return verdicts
