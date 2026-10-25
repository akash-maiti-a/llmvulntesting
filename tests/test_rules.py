"""Guards for the custom Semgrep rules."""
from pathlib import Path

import yaml

RULES = Path(__file__).resolve().parent.parent / "rules" / "semgrep" / "php" / "taint.yaml"


def test_xss_assignment_sinks_are_name_constrained():
    """An unconstrained `$HTML = $X` sink matches every assignment of request data."""
    rule = next(r for r in yaml.safe_load(RULES.read_text())["rules"] if r["id"] == "php-taint-xss")
    sinks = rule["pattern-sinks"][0]["pattern-either"]
    bare = [s for s in sinks if s.get("pattern", "").startswith("$HTML")]
    assert not bare, f"unconstrained assignment sinks: {bare}"
