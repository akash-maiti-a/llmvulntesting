import json

import pytest

from vulnscan.rl import reward
from vulnscan.rl.corpus import clean_php, clean_py, neutralise_strings


def reply(verdict, conf=0.9, sink=True, reach=True, defence=False, think=""):
    body = {"analysis": "a", "sink_is_real": sink, "attacker_reaches_sink": reach,
            "defence_sufficient": defence, "verdict": verdict, "confidence": conf}
    return think + json.dumps(body)


def test_malformed_replies_get_the_format_penalty():
    for bad in ["", "not json", '{"verdict": "maybe"}', '{"verdict": "true_positive"}']:
        assert reward.score(bad, True).total == reward.FORMAT_PENALTY


def test_missing_a_real_bug_costs_more_than_keeping_noise():
    miss = reward.score(reply("false_positive", sink=False), vulnerable=True)
    keep = reward.score(reply("true_positive"), vulnerable=False)
    hit = reward.score(reply("true_positive"), vulnerable=True)
    assert miss.total < keep.total < 0 < hit.total


def test_calibration_rewards_honest_confidence_when_wrong():
    sure = reward.score(reply("true_positive", conf=0.99), vulnerable=False)
    unsure = reward.score(reply("true_positive", conf=0.3), vulnerable=False)
    assert unsure.total > sure.total


def test_confidence_outside_unit_range_is_clamped():
    assert reward.score(reply("true_positive", conf=95), True).calibration == pytest.approx(0.0)


def test_inconsistent_checks_are_penalised():
    ok = reward.score(reply("true_positive"), True)
    odd = reward.score(reply("true_positive", sink=False), True)
    assert ok.consistent and not odd.consistent and ok.total > odd.total


def test_think_prefix_is_ignored():
    assert reward.score(reply("true_positive", think="<think>\n\n</think>\n"), True).correct


def test_cleaning_blanks_hint_comments_but_keeps_line_numbers():
    php = "<?php\n/*\nUnsafe sample\nsanitize : none\n*/\n$a = $_GET['x']; // tainted input\necho $a;\n"
    out = clean_php(php)
    assert out.count("\n") == php.count("\n")
    assert "Unsafe" not in out and "tainted" not in out and "echo $a;" in out
    py = "# PURPOSELY INSECURE\nx = 1  # keep me\n"
    assert clean_py(py) == "\nx = 1  # keep me\n"
    sard = "<!--\nUnsafe sample\n-->\n<?php\n//flaw\necho $x; // note\n"
    assert clean_php(sard, strip_all=True) == "\n\n\n<?php\n\necho $x;\n"


def test_neutralise_only_touches_string_literals():
    src = "import markupsafe\nbar = 'safe!'\nlst.append(\"moresafe\")\n"
    assert neutralise_strings(src) == "import markupsafe\nbar = 'const!'\nlst.append(\"moreconst\")\n"
