"""vulnscan command line: fetch -> scan -> triage -> evaluate.

    vulnscan fetch [TARGET ...]
    vulnscan scan [TARGET ...] [--tool semgrep --tool pysa]
    vulnscan triage [TARGET ...] [--prompt v2] [--think]
    vulnscan evaluate [TARGET ...]
    vulnscan run [TARGET ...]          # all of the above with the default triage configs

TARGET is a manifest name; a CVE name selects both variants, name@vuln one."""

from __future__ import annotations

import json
import time
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from . import RESULTS
from . import evaluate as ev
from . import groundtruth, report, triage
from .models import Finding, load_findings, save_findings
from .scanners import pysa, semgrep
from .targets import Target, fetch as fetch_target, load_targets

app = typer.Typer(add_completion=False, no_args_is_help=True, help=__doc__)
console = Console()

FINDING_FILES = {"semgrep-registry": "semgrep-registry.json", "semgrep-custom": "semgrep-custom.json",
                 "pysa": "pysa.json"}


def _targets(names: Optional[list[str]]) -> list[Target]:
    ts = load_targets(names or None)
    if names and not ts:
        raise typer.BadParameter(f"no targets match {names}")
    return ts


def findings_for(t: Target) -> dict[str, list[Finding]]:
    return {src: load_findings(RESULTS / t.key / name) for src, name in FINDING_FILES.items()}


def all_findings(t: Target) -> list[Finding]:
    return [f for fs in findings_for(t).values() for f in fs]


@app.command("list")
def list_targets():
    """Show the manifest."""
    table = Table("key", "lang", "kind", "scan paths")
    for t in load_targets():
        kind = f"CVE {t.cve}" if t.is_cve else ("local" if t.path else "app")
        table.add_row(t.key, t.lang, kind, ", ".join(t.scan_paths) or ".")
    console.print(table)


@app.command()
def fetch(targets: Optional[list[str]] = typer.Argument(None)):
    """Clone targets and check out their pinned commits."""
    for t in _targets(targets):
        console.print(f"{t.key}: {fetch_target(t)}")


@app.command()
def scan(targets: Optional[list[str]] = typer.Argument(None),
         tool: list[str] = typer.Option(["semgrep", "pysa"], help="semgrep and/or pysa")):
    """Run the static analyzers and save findings under results/<target>/."""
    for t in _targets(targets):
        fetch_target(t)
        out = RESULTS / t.key
        if "semgrep" in tool:
            for ruleset in ("registry", "custom"):
                t0 = time.time()
                fs = semgrep.run(t, ruleset, out / f"semgrep-{ruleset}.raw.json")
                save_findings(out / f"semgrep-{ruleset}.json", fs)
                console.print(f"{t.key} semgrep-{ruleset}: {len(fs)} findings ({time.time() - t0:.0f}s)")
        if "pysa" in tool and "python" in t.langs():
            t0 = time.time()
            fs = pysa.run(t, out / "pysa.raw.json")
            save_findings(out / "pysa.json", fs)
            console.print(f"{t.key} pysa: {len(fs)} findings ({time.time() - t0:.0f}s)")


@app.command("triage")
def triage_cmd(targets: Optional[list[str]] = typer.Argument(None),
               prompt: str = typer.Option("v2", help="prompt version: v1 or v2"),
               think: bool = typer.Option(False, help="enable the model's reasoning mode"),
               model: str = typer.Option(triage.MODEL),
               only_rejected_by: Optional[str] = typer.Option(
                   None, help="triage only findings this tag rejected (two-tier second pass)"),
               tag: str = typer.Option("", help="name for this run's verdict file (default: <prompt>-<fast|think>)")):
    """Ask the LLM to judge each finding; verdicts go to results/<target>/triage-<tag>.json."""
    cfg = triage.Config(prompt=prompt, think=think, model=model, name=tag)
    for t in _targets(targets):
        fs = all_findings(t)
        if only_rejected_by:
            prior = triage.load_verdicts(RESULTS, t, only_rejected_by)
            fs = [f for f in fs if prior.get(f.id, {}).get("verdict") == "false_positive"]

        def progress(i, n, f, v):
            # markup=False: rich would otherwise read "[dvwa v2-fast]" as a style tag and drop it.
            console.print(f"  [{t.key} {cfg.tag}] {i}/{n} {f.file}:{f.line} {f.cwe} -> "
                          f"{v.get('verdict')} ({v.get('secs')}s)", markup=False)

        console.print(f"{t.key}: triaging {len(fs)} findings with {cfg.model} [{cfg.tag}]", markup=False)
        triage.run(t, fs, cfg, RESULTS, progress)


def evaluate_target(t: Target) -> dict:
    gt = groundtruth.load(t)
    by_src = findings_for(t)
    union = [f for fs in by_src.values() for f in fs]
    scores = [ev.score(src, fs, gt) for src, fs in by_src.items()
              if src != "pysa" or "python" in t.langs()]
    scores.append(ev.score("all tools", union, gt))
    tags = sorted(p.stem.removeprefix("triage-") for p in (RESULTS / t.key).glob("triage-*.json"))
    verdicts = {tag: triage.load_verdicts(RESULTS, t, tag) for tag in tags}
    slow = verdicts.get("v2-think") or verdicts.get("v2-think-rejects")
    if "v2-fast" in verdicts and slow is not None:
        verdicts["v2-two-tier"] = ev.two_tier(verdicts["v2-fast"], slow)
    accuracy = []
    for tag, v in verdicts.items():
        # A "-rejects" pass only judged what another pass rejected; on its own it
        # would keep everything else, so it is scored only through the two-tier row.
        if not tag.endswith("-rejects"):
            scores.append(ev.score(f"all tools + triage {tag}", ev.apply_triage(union, v), gt))
        accuracy.append(ev.triage_accuracy(tag, union, gt, v))
    labels = {f.id: ev.label(f, gt).kind for f in union}
    return {"target": t.key, "group": report.group(t), "gt_entries": len(gt),
            "scores": [s.to_dict() for s in scores],
            "triage": [a.to_dict() for a in accuracy], "labels": labels}


@app.command("evaluate")
def evaluate_cmd(targets: Optional[list[str]] = typer.Argument(None)):
    """Score findings and triage against ground truth; writes results/summary.json and report.md."""
    rows = [evaluate_target(t) for t in _targets(targets)]
    (RESULTS / "summary.json").write_text(json.dumps(rows, indent=2))
    md = report.render(rows)
    (RESULTS / "report.md").write_text(md)
    console.print(md)


@app.command()
def run(targets: Optional[list[str]] = typer.Argument(None),
        think: bool = typer.Option(True, help="also run the v2 reasoning-mode pass")):
    """Fetch, scan, triage (v1-fast, v2-fast, v2-think on v2-fast rejections) and evaluate."""
    scan(targets, ["semgrep", "pysa"])
    triage_cmd(targets, prompt="v1", think=False, model=triage.MODEL, only_rejected_by=None, tag="")
    triage_cmd(targets, prompt="v2", think=False, model=triage.MODEL, only_rejected_by=None, tag="")
    if think:
        # Reasoning mode is ~7x slower, so it re-judges only the fast pass's rejections.
        triage_cmd(targets, prompt="v2", think=True, model=triage.MODEL, only_rejected_by="v2-fast",
                   tag="v2-think-rejects")
    evaluate_cmd(targets)


if __name__ == "__main__":
    app()
