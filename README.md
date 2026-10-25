# vulnscan

An LLM-assisted vulnerability scanner. Static analyzers (Semgrep, and Pysa for
Python) produce candidate findings. A local LLM served by
[Ollama](https://ollama.com) then triages them. The results are scored against
ground truth from deliberately vulnerable apps, a synthetic benchmark and real
CVEs.

## How it works

```
targets/targets.yaml ──► fetch (git clone + pinned checkout) ──► targets/src/<key>/
                                                                    │
            ┌───────────────────────────────┬───────────────────────┤
            ▼                               ▼                       ▼
  Semgrep: registry rulesets     Semgrep: custom taint rules    Pysa (Python only)
  (p/php, p/python, p/django,    (rules/semgrep/<lang>/)        inter-procedural taint,
   p/flask)                                                     rules/pysa/ + bundled models
            │                               │                       │
            └──────────────────► Finding (models.py) ◄──────────────┘
                                        │
                                        ▼
                      LLM triage via Ollama (triage.py)
                      prompt v1 / v2, fast or reasoning mode
                                        │
                                        ▼
        Evaluation against ground truth (groundtruth/, evaluate.py)
        ──► results/summary.json, results/report.md
```

### Targets (`vulnscan/targets.py`, `targets/targets.yaml`)

Every scanned codebase is listed in `targets/targets.yaml`. There are three
kinds:

| Kind | Fields | Behavior |
|---|---|---|
| App target | `repo`, `ref` | Cloned into `targets/src/<name>/` and checked out at the pinned `ref`. |
| CVE target | `repo`, `fix_commit`, `cve`, `cwe` | Expanded into `<name>@vuln` (at `fix_commit^`) and `<name>@fixed` (at `fix_commit`). |
| Local target | `path` | Scanned in place and never fetched. |

Optional fields:

- `scan_paths`: limits the scan to these subdirectories (globs are allowed).
- `exclude`: Semgrep `--exclude` patterns.
- `pysa_sources`: source directories for Pyre/Pysa (relative to the target).
- `pysa_deps`: pip packages that Pyre needs to resolve library calls. They are
  installed into `.cache/pysa/<key>/site`, never imported or run.
- `lang`: one of `php`, `python` or `mixed` (`mixed` runs both rule sets).

Current targets: [DVWA](https://github.com/digininja/DVWA) (PHP),
[DVPWA](https://github.com/anxolerd/dvpwa) (aiohttp),
[PyGoat](https://github.com/adeyosemanputra/pygoat) (Django), the local
`synthetic` benchmark, and four CVEs (pheditor, YesWiki, RaspAP, WsgiDAV; see
`groundtruth/cves.md`).

### Scanning

**Semgrep** (`vulnscan/scanners/semgrep.py`) runs twice per target, so each
finding can be attributed to a ruleset:

- `registry`: `p/php`, or `p/python` + `p/django` + `p/flask`.
- `custom`: the taint rules in `rules/semgrep/php/` and `rules/semgrep/python/`.
  They cover SQLi, command injection, XSS, path traversal and file inclusion,
  code injection and SSTI, deserialization, open redirect, SSRF and XXE.

Semgrep is invoked with `--dataflow-traces`, so a taint finding carries its
source → intermediate variables → sink path. OSS Semgrep taint is
intra-procedural.

**Pysa** (`vulnscan/scanners/pysa.py`) is inter-procedural, so it follows a
value through function calls and across files. Pysa only attaches taint to
calls it can resolve, so the runner:

1. installs `pysa_deps` into a private directory used as Pyre's search path;
2. writes a `.pyre_configuration` that combines Pyre's bundled taint models
   with `rules/pysa/vulnscan.pysa`. That file marks every `request` parameter
   and Flask's global `request` as user-controlled, adds missing sinks (aiopg
   `Cursor.execute`, PIL `ImageMath.eval`), and sanitizes the `request`
   argument of template renderers;
3. runs `pyre --noninteractive analyze --no-verify`, and maps Pysa rule codes
   to CWEs (for example 5005/5051 → CWE-89, 5001 → CWE-78, or CWE-95 when the
   sink is `eval`/`exec`).

### Findings (`vulnscan/models.py`) and CWEs (`vulnscan/cwe.py`)

All tools emit the same `Finding` dataclass: tool, ruleset, rule ID,
normalized CWE, file, line range, message, snippet and dataflow trace. Each
finding has a stable 12-character ID, `sha1(tool|rule_id|file|line|end_line)`.
Tools label the same bug with different CWEs, so CWEs are grouped into
families (`sqli`, `cmdi`, `xss`, `path`, `code`, `deser`, …) and matched by
family.

### LLM triage (`vulnscan/triage.py`)

Each finding is sent on its own to Ollama's `/api/chat` with `temperature: 0`
and a JSON-schema `format`. The prompt contains the rule, CWE, message,
flagged line, trace, the source file (whole if it has up to 200 lines, else a
200-line window), and excerpts of any trace steps outside that window. The file
path is redacted by default, because benchmark paths would leak the answer.

- **Prompt v1**: the original one-paragraph prompt.
- **Prompt v2**: judges only the alert's CWE, walks through `sink_is_real`,
  `attacker_reaches_sink` and `defence_sufficient` before the verdict, and
  lists general defence pitfalls (escaping in unquoted contexts, HTML escaping
  in attributes, blocklists).
- **Fast or reasoning mode**: `--think` enables qwen3's chain of thought. It is
  about seven times slower, so `vulnscan run` uses it only as a second pass on
  alerts the fast pass rejected (two-tier).

Verdicts are cached in `results/<target>/triage-<tag>.json` by finding ID, so
runs resume. Timeouts and malformed replies are recorded as `error`, and
evaluation keeps those findings (fail open).

### Evaluation (`vulnscan/groundtruth.py`, `vulnscan/evaluate.py`)

Ground truth lives in `groundtruth/<target>.yaml`: entries with a CWE,
`vulnerable: true|false`, a scope (`taint`, `other`, `client`) and locations
(file plus optional line range). CVE ground truth is derived from the fix diff
(see `groundtruth/cves.md`).

A finding hits an entry when it lies inside one of the entry's locations and
its CWE is in the same family. The evaluator reports, per tool, for the union
of tools, and for the union after each triage run:

- recall per scope: detected vulnerable entries / vulnerable entries;
- precision: true-positive findings / findings the ground truth can judge;
- false positives on known-safe code (DVWA `impossible`, safe synthetic cases,
  patched CVE lines);
- triage accuracy: share of true positives kept, share of false positives
  removed, failed replies, seconds per alert.

## Deployment

### Prerequisites

- Docker with Compose v2. This is the recommended setup, because Semgrep and
  Pyre are pinned in the image.
- [Ollama](https://ollama.com) running **on the host**, with the triage model
  pulled:

  ```sh
  ollama pull qwen3:8b
  ollama serve            # listens on :11434
  ```

### Run with Docker Compose

```sh
docker compose build
docker compose run --rm scanner vulnscan list                 # show targets
docker compose run --rm scanner vulnscan run                  # everything below, in order
docker compose run --rm scanner vulnscan fetch [TARGET ...]
docker compose run --rm scanner vulnscan scan [TARGET ...] [--tool semgrep --tool pysa]
docker compose run --rm scanner vulnscan triage [TARGET ...] --prompt v2 [--think]
docker compose run --rm scanner vulnscan triage --prompt v2 --think --only-rejected-by v2-fast --tag v2-think-rejects
docker compose run --rm scanner vulnscan evaluate [TARGET ...]   # writes results/summary.json and results/report.md
docker compose run --rm scanner python -m pytest
```

The `scanner` service:

- Builds from `docker/Dockerfile`: Python 3.11 with `git`, `php-cli`,
  `semgrep==1.95.0`, `pyre-check==0.9.23` and `click<8.2` (Pyre 0.9.23's CLI
  fails on newer click). Git is configured with `safe.directory '*'`, because
  the bind-mounted clones belong to the host user.
- Bind-mounts the repo at `/work`, so `targets/src/`, `.cache/` and `results/`
  persist on the host.
- Reaches Ollama on the host through `host.docker.internal`. This also works on
  Linux because of the `host-gateway` mapping.

| Variable | Default | Purpose |
|---|---|---|
| `OLLAMA_HOST` | `http://host.docker.internal:11434` | Ollama endpoint used for triage |
| `VULNSCAN_MODEL` | `qwen3:8b` | Model name passed to Ollama |

Don't expose Ollama's port publicly, because it has no authentication.

### Run locally (without Docker)

You need Python 3.11+, git, and the same scanner versions as the image:

```sh
python -m venv .venv
. .venv/bin/activate              # Windows: .venv\Scripts\activate
pip install semgrep==1.95.0 pyre-check==0.9.23 "click<8.2"
pip install -e ".[dev]"
vulnscan --help
```

Pyre/Pysa doesn't run natively on Windows. On Windows, use Docker or WSL.

## Repository layout

```
docker/Dockerfile          scanner image (pinned Semgrep + Pyre)
docker-compose.yml         `scanner` service wired to host Ollama
pyproject.toml             package metadata; installs the `vulnscan` entry point
rules/semgrep/{php,python} custom Semgrep taint rules
rules/pysa/                extra Pysa models (entry points, sinks, sanitizers)
targets/targets.yaml       target manifest
targets/src/               fetched target sources (git-ignored)
benchmarks/synthetic/      38 labelled PHP/Python cases (see its README)
groundtruth/               ground truth per target; cves.md explains CVE selection
results/                   findings, triage verdicts, summary.json, report.md (git-ignored)
tests/                     pytest suite (parsers, fix-diff ground truth, scoring, triage)
vulnscan/
  cli.py                   Typer CLI: list, fetch, scan, triage, evaluate, run
  targets.py               manifest loading, fetch, CVE fix-diff lines
  scanners/semgrep.py      Semgrep runner + JSON parser
  scanners/pysa.py         Pysa runner + taint-output parser
  models.py                Finding / TraceStep model and JSON I/O
  cwe.py                   CWE normalization and family matching
  triage.py                Ollama client, prompts, verdict cache
  groundtruth.py           ground-truth loading
  evaluate.py              matching, scores, triage accuracy
  report.py                Markdown report
```

## Adding a target

1. Add an entry to `targets/targets.yaml`. Pin `ref` to a commit SHA, not a
   branch, so that results are reproducible.
2. For a CVE, set `fix_commit`, `cve` and `cwe` instead of `ref`. The vulnerable
   and fixed variants, and their ground truth, are created automatically.
3. Set `scan_paths` to the code that contains the vulnerabilities. This keeps
   scans fast and reduces noise from vendored code.
4. For an app target, add `groundtruth/<name>.yaml`.

## Safety note

The targets are **intentionally vulnerable applications**. vulnscan only
analyzes their source statically and never runs them. If you deploy any target
yourself (for example, with its own `docker-compose.yml`), keep it on an
isolated network.
