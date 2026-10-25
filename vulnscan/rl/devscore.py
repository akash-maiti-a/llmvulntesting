"""Score an Ollama model on held-back training-corpus prompts (the dev split).

    python -m vulnscan.rl.devscore --model qwen3:4b --data training/dataset/all.dev.jsonl

Replies go through triage.ask, the same path as real triage (JSON schema,
greedy decoding), and are cached per model in training/dev-<model>.json."""

from __future__ import annotations

import argparse
import json
from collections import Counter

import httpx

from .. import triage
from .corpus import TRAIN


def summary(rows: list[dict], verdicts: dict[str, dict]) -> dict:
    c = Counter()
    brier = []
    for r in rows:
        v = verdicts.get(r["id"])
        if not v:
            continue
        said = v.get("verdict")
        if said not in ("true_positive", "false_positive"):
            c["error"] += 1
            continue
        correct = (said == "true_positive") == r["vulnerable"]
        c[("tp_" if r["vulnerable"] else "fp_") + ("kept" if said == "true_positive" else "dropped")] += 1
        p = min(1.0, max(0.0, float(v.get("confidence", 0.5))))
        brier.append((p - correct) ** 2)
    tp, fp = c["tp_kept"] + c["tp_dropped"], c["fp_kept"] + c["fp_dropped"]
    return {"n": tp + fp, "errors": c["error"], "tp_retention": c["tp_kept"] / tp if tp else None,
            "fp_removal": c["fp_dropped"] / fp if fp else None,
            "accuracy": (c["tp_kept"] + c["fp_dropped"]) / (tp + fp) if tp + fp else None,
            "brier": sum(brier) / len(brier) if brier else None, **dict(c)}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True)
    ap.add_argument("--data", default=str(TRAIN / "dataset" / "all.dev.jsonl"))
    ap.add_argument("--limit", type=int, default=0)
    args = ap.parse_args()
    rows = [json.loads(line) for line in open(args.data, encoding="utf-8")]
    if args.limit:
        rows = rows[:args.limit]
    out = TRAIN / f"dev-{args.model.replace(':', '_').replace('/', '_')}.json"
    verdicts = json.loads(out.read_text()) if out.exists() else {}
    cfg = triage.Config(prompt="v3", model=args.model)
    with httpx.Client() as client:
        for i, r in enumerate(rows, 1):
            if r["id"] in verdicts:
                continue
            verdicts[r["id"]] = triage.ask(r["prompt"], cfg, client)
            out.write_text(json.dumps(verdicts))
            if i % 25 == 0:
                print(i, len(rows), json.dumps(summary(rows, verdicts)), flush=True)
    s = summary(rows, verdicts)
    by_src = {src: summary([r for r in rows if r["source"] == src], verdicts)
              for src in sorted({r["source"] for r in rows})}
    print(json.dumps({"model": args.model, "all": s, "by_source": by_src}, indent=2))


if __name__ == "__main__":
    main()
