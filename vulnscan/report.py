"""Render evaluation rows (cli.evaluate_target) as a Markdown report."""

from __future__ import annotations

from collections import defaultdict

from .targets import Target

GROUPS = ("apps", "synthetic", "cves")


def group(t: Target) -> str:
    if t.is_cve:
        return "cves"
    return "synthetic" if t.path else "apps"


def _pct(num: float, den: float) -> str:
    return f"{num / den:.0%}" if den else "n/a"


def aggregate(rows: list[dict]) -> dict[str, dict]:
    """Sum each config's counts over targets; recall and precision are recomputed from sums."""
    agg: dict[str, dict] = defaultdict(lambda: defaultdict(int))
    for row in rows:
        for s in row["scores"]:
            a = agg[s["config"]]
            for k in ("findings", "tp", "fp_safe", "fp_labelled", "unlabelled", "safe_entries"):
                a[k] += s[k]
            a["safe_flagged"] += len(s["safe_flagged"])
            for scope, n in s["positives"].items():
                a[f"pos_{scope}"] += n
                a[f"det_{scope}"] += len(s["detected"][scope])
    return agg


def aggregate_triage(rows: list[dict]) -> dict[str, dict]:
    agg: dict[str, dict] = defaultdict(lambda: defaultdict(float))
    for row in rows:
        for a in row["triage"]:
            for k in ("tp_kept", "tp_dropped", "fp_kept", "fp_dropped", "failed", "seconds", "calls"):
                agg[a["tag"]][k] += a[k]
    return agg


def _order(cfg: str) -> tuple:
    base = ["semgrep-registry", "semgrep-custom", "pysa", "all tools"]
    return (base.index(cfg), "") if cfg in base else (len(base), cfg)


def _score_table(agg: dict[str, dict]) -> list[str]:
    out = ["| Configuration | Alerts | TP | FP on safe code | Other FP | Unlabelled | Precision | "
           "Recall (taint) | Recall (other) | Safe regions flagged |",
           "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |"]
    for cfg, a in sorted(agg.items(), key=lambda kv: _order(kv[0])):
        judged = a["tp"] + a["fp_safe"] + a["fp_labelled"]
        out.append(
            f"| {cfg} | {a['findings']} | {a['tp']} | {a['fp_safe']} | {a['fp_labelled']} | {a['unlabelled']} | "
            f"{_pct(a['tp'], judged)} | {a['det_taint']}/{a['pos_taint']} ({_pct(a['det_taint'], a['pos_taint'])}) | "
            f"{a['det_other']}/{a['pos_other']} | {a['safe_flagged']}/{a['safe_entries']} |")
    return out


def _triage_table(agg: dict[str, dict]) -> list[str]:
    out = ["| Triage | Judged | True positives kept | False positives removed | Failed replies | Mean s/alert |",
           "| --- | --- | --- | --- | --- | --- |"]
    for tag, a in agg.items():
        tp, fp = a["tp_kept"] + a["tp_dropped"], a["fp_kept"] + a["fp_dropped"]
        mean = f"{a['seconds'] / a['calls']:.1f}" if a["calls"] and tag != "v2-two-tier" else "-"
        out.append(f"| {tag} | {int(a['calls'])} | {int(a['tp_kept'])}/{int(tp)} ({_pct(a['tp_kept'], tp)}) | "
                   f"{int(a['fp_dropped'])}/{int(fp)} ({_pct(a['fp_dropped'], fp)}) | {int(a['failed'])} | {mean} |")
    return out


def render(rows: list[dict]) -> str:
    md = ["# vulnscan evaluation", ""]
    for g in GROUPS:
        sub = [r for r in rows if r["group"] == g]
        if not sub:
            continue
        md += [f"## {g} ({', '.join(r['target'] for r in sub)})", ""]
        md += _score_table(aggregate(sub)) + [""]
        tri = aggregate_triage(sub)
        if tri:
            md += _triage_table(tri) + [""]
    md += ["## Per target", ""]
    for r in rows:
        md += [f"### {r['target']} ({r['gt_entries']} ground-truth entries)", ""]
        md += _score_table(aggregate([r])) + [""]
    return "\n".join(md)
