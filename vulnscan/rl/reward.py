"""Reward for one triage reply, given the alert's ground-truth label.

The reply must be the v3 JSON object (analysis, three checks, verdict,
confidence). Terms:

- format: unparsable or incomplete JSON scores FORMAT_PENALTY and nothing else;
- verdict: +1 when correct; a real flaw judged false_positive costs MISS_COST,
  a false alarm judged true_positive costs KEEP_COST. The asymmetry mirrors the
  fail-open policy: dropping a real bug is worse than keeping noise;
- calibration: minus the Brier score of "confidence" read as the probability
  that the verdict is correct (clamped to [0, 1]);
- consistency: the verdict must follow from the checks
  (true_positive iff sink_is_real and attacker_reaches_sink and not defence_sufficient).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass

FORMAT_PENALTY = -1.0
MISS_COST = -2.0
KEEP_COST = -0.5
CALIBRATION_WEIGHT = 0.5
CONSISTENCY_WEIGHT = 0.2
CHECKS = ("sink_is_real", "attacker_reaches_sink", "defence_sufficient")


@dataclass
class Scored:
    total: float
    verdict: str | None = None
    correct: bool | None = None
    calibration: float = 0.0
    consistent: bool | None = None


def parse(reply: str) -> dict | None:
    """The JSON object in a reply; Qwen3 may prefix an (empty) <think> block."""
    reply = re.sub(r"<think>.*?</think>", "", reply, flags=re.S).strip()
    start, end = reply.find("{"), reply.rfind("}")
    if start < 0 or end < start:
        return None
    try:
        v = json.loads(reply[start:end + 1])
    except json.JSONDecodeError:
        return None
    if not isinstance(v, dict) or v.get("verdict") not in ("true_positive", "false_positive"):
        return None
    if not all(isinstance(v.get(c), bool) for c in CHECKS) or not isinstance(v.get("confidence"), (int, float)):
        return None
    return v


def score(reply: str, vulnerable: bool) -> Scored:
    v = parse(reply)
    if v is None:
        return Scored(FORMAT_PENALTY)
    said_tp = v["verdict"] == "true_positive"
    correct = said_tp == vulnerable
    if correct:
        base = 1.0
    else:
        base = MISS_COST if vulnerable else KEEP_COST
    p = min(1.0, max(0.0, float(v["confidence"])))
    brier = (p - float(correct)) ** 2
    implied = v["sink_is_real"] and v["attacker_reaches_sink"] and not v["defence_sufficient"]
    consistent = implied == said_tp
    total = base - CALIBRATION_WEIGHT * brier + (CONSISTENCY_WEIGHT if consistent else -CONSISTENCY_WEIGHT)
    return Scored(total, v["verdict"], correct, -brier, consistent)
