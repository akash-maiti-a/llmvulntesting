from vulnscan import evaluate as ev
from vulnscan.groundtruth import Entry, Location

GT = [
    Entry("sqli-low", "CWE-89", True, "taint", [Location("low.php")]),
    Entry("sqli-safe", "CWE-89", False, "taint", [Location("impossible.php")]),
    Entry("upload", "CWE-434", True, "other", [Location("up.php", 5, 9)]),
]


def test_label_kinds(make_finding):
    assert ev.label(make_finding("low.php"), GT).kind == "tp"
    assert ev.label(make_finding("impossible.php"), GT).kind == "fp_safe"
    assert ev.label(make_finding("low.php", cwe="CWE-79"), GT).kind == "fp_labelled"
    assert ev.label(make_finding("elsewhere.php"), GT).kind == "unlabelled"


def test_line_ranges_and_multiline_findings(make_finding):
    assert ev.label(make_finding("up.php", 4, cwe="CWE-434"), GT).kind == "fp_labelled"
    assert ev.label(make_finding("up.php", 3, cwe="CWE-434", end_line=6), GT).kind == "tp"


def test_score_recall_precision(make_finding):
    fs = [make_finding("low.php"), make_finding("low.php", 20), make_finding("impossible.php"),
          make_finding("elsewhere.php")]
    s = ev.score("x", fs, GT)
    assert (s.tp, s.fp_safe, s.unlabelled) == (2, 1, 1)
    assert s.recall("taint") == 1.0 and s.recall("other") == 0.0
    assert s.precision == 2 / 3
    assert s.safe_flagged == ["sqli-safe"]


def test_triage_fails_open(make_finding):
    a, b, c = make_finding(line=1), make_finding(line=2), make_finding(line=3)
    verdicts = {a.id: {"verdict": "false_positive"}, b.id: {"verdict": "error"}}
    assert ev.apply_triage([a, b, c], verdicts) == [b, c]


def test_two_tier_rejudges_only_fast_rejections():
    fast = {"1": {"verdict": "true_positive"}, "2": {"verdict": "false_positive"},
            "3": {"verdict": "false_positive"}}
    slow = {"1": {"verdict": "false_positive"}, "2": {"verdict": "true_positive"}}
    out = ev.two_tier(fast, slow)
    assert [out[k]["verdict"] for k in "123"] == ["true_positive", "true_positive", "false_positive"]


def test_triage_accuracy_counts(make_finding):
    tp, fp = make_finding("low.php"), make_finding("impossible.php")
    verdicts = {tp.id: {"verdict": "false_positive", "secs": 2}, fp.id: {"verdict": "false_positive", "secs": 4}}
    acc = ev.triage_accuracy("t", [tp, fp], GT, verdicts)
    d = acc.to_dict()
    assert (acc.tp_dropped, acc.fp_dropped) == (1, 1)
    assert d["tp_retention"] == 0.0 and d["fp_removal"] == 1.0 and d["mean_seconds"] == 3.0
