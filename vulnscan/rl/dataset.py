"""Turn scanner alerts on the training corpus into labelled triage prompts.

Run with the training corpus selected (see corpus.py):

    VULNSCAN_MANIFEST=training/targets.yaml VULNSCAN_GT=training/groundtruth \
    VULNSCAN_RESULTS=training/results python -m vulnscan.rl.dataset [--audit 30] [--exclude vulpy]

Only alerts whose label the ground truth vouches for are used: "tp" (hits a
documented flaw) and "fp_safe" (hits a documented safe case). The prompt is
exactly what `vulnscan triage --prompt v3` sends, so the trained model sees the
same format at inference. Rows are split train/dev by file, so alerts from one
file never land on both sides.

--audit N writes training/audit/<source>.md: N random labelled alerts per
source with the flagged code, for the label-accuracy check by hand."""

from __future__ import annotations

import argparse
import hashlib
import json
import random
from collections import Counter

from .. import RESULTS, groundtruth, triage
from .. import evaluate as ev
from ..cli import all_findings
from ..targets import load_targets
from .corpus import TRAIN

OUT = TRAIN / "dataset"


def rows(exclude: set[str] = frozenset()) -> list[dict]:
    cfg = triage.Config(prompt="v3")
    out = []
    for t in load_targets():
        if t.name in exclude:
            continue
        gt = groundtruth.load(t)
        seen = set()
        for f in all_findings(t):
            if f.id in seen:
                continue
            seen.add(f.id)
            lab = ev.label(f, gt)
            if lab.kind not in ("tp", "fp_safe"):
                continue
            out.append({"id": f"{t.name}:{f.id}", "source": t.name, "file": f.file, "line": f.line,
                        "tool": f.tool, "rule": f.rule_id, "cwe": f.cwe, "vulnerable": lab.kind == "tp",
                        "entries": lab.entries, "prompt": triage.build_prompt(f, t, cfg)})
    return out


def split(data: list[dict], dev_frac: float = 0.1) -> tuple[list[dict], list[dict]]:
    def bucket(r):
        return int(hashlib.sha1(f"{r['source']}/{r['file']}".encode()).hexdigest(), 16) % 1000
    dev = [r for r in data if bucket(r) < dev_frac * 1000]
    train = [r for r in data if bucket(r) >= dev_frac * 1000]
    return train, dev


def audit(data: list[dict], n: int, seed: int = 0) -> None:
    rng = random.Random(seed)
    d = TRAIN / "audit"
    d.mkdir(parents=True, exist_ok=True)
    targets = {t.name: t for t in load_targets()}
    by_src: dict[str, list[dict]] = {}
    for r in data:
        by_src.setdefault(r["source"], []).append(r)
    for src, rs in by_src.items():
        pick = rng.sample(rs, min(n, len(rs)))
        lines = [f"# Label audit: {src} ({len(pick)} of {len(rs)} labelled alerts)\n",
                 "Mark each row: agree / disagree / unsure, comparing the label with the code.\n"]
        for k, r in enumerate(pick, 1):
            text = (targets[src].src / r["file"]).read_text(errors="replace").split("\n")
            lo, hi = max(0, r["line"] - 25), min(len(text), r["line"] + 12)
            excerpt = "\n".join(f"{i + 1:5}{'>' if i + 1 == r['line'] else ' '} {text[i]}" for i in range(lo, hi))
            lines.append(f"\n## {k}. {r['file']}:{r['line']} {r['cwe']} ({r['tool']} {r['rule'].split('.')[-1]})\n"
                         f"label: **{'vulnerable' if r['vulnerable'] else 'safe'}** (entries {r['entries']})\n"
                         f"verdict: \n\n```\n{excerpt}\n```\n")
        (d / f"{src}.md").write_text("".join(lines), encoding="utf-8")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--audit", type=int, default=0)
    ap.add_argument("--exclude", action="append", default=[])
    args = ap.parse_args()
    data = rows(set(args.exclude))
    if args.audit:
        audit(data, args.audit)
    train, dev = split(data)
    OUT.mkdir(parents=True, exist_ok=True)
    tag = "-".join(["all", *[f"no-{e}" for e in args.exclude]])
    for name, part in (("train", train), ("dev", dev)):
        with open(OUT / f"{tag}.{name}.jsonl", "w", encoding="utf-8") as fh:
            for r in part:
                fh.write(json.dumps(r) + "\n")
    stats = {src: dict(Counter("tp" if r["vulnerable"] else "fp" for r in data if r["source"] == src))
             for src in sorted({r["source"] for r in data})}
    stats["_total"] = {"train": len(train), "dev": len(dev)}
    (OUT / f"{tag}.stats.json").write_text(json.dumps(stats, indent=2))
    print(json.dumps(stats, indent=2))


if __name__ == "__main__":
    main()
