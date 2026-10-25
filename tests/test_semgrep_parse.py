from vulnscan.scanners.semgrep import parse

LOW = "vulnerabilities/sqli/source/low.php"
RESULT = {"results": [{
    "check_id": "rules.semgrep.php.php-taint-sqli",
    "path": "./" + LOW,
    "start": {"line": 11}, "end": {"line": 11},
    "extra": {
        "message": "User input flows into a SQL query",
        "lines": "$result = mysqli_query($c, $query);",
        "metadata": {"cwe": ["CWE-89: SQL Injection"]},
        "dataflow_trace": {
            "taint_source": ["CliLoc", [{"path": LOW, "start": {"line": 5}}, "$_REQUEST"]],
            "intermediate_vars": [{"location": {"path": LOW, "start": {"line": 10}}, "content": "$query"}],
            "taint_sink": ["CliLoc", [{"path": LOW, "start": {"line": 11}}, "$query"]],
        },
    },
}]}


def test_parse_builds_finding_with_trace():
    [f] = parse(RESULT, "custom")
    assert (f.tool, f.ruleset, f.cwe, f.line) == ("semgrep", "custom", "CWE-89", 11)
    assert f.file == LOW
    assert [s.note.split(":")[0] for s in f.trace] == ["source", "via", "sink"]
    assert [s.line for s in f.trace] == [5, 10, 11]


def test_finding_id_is_stable_and_short():
    a, b = parse(RESULT, "custom")[0], parse(RESULT, "custom")[0]
    assert a.id == b.id and len(a.id) == 12


def test_missing_trace_and_cwe_are_tolerated():
    data = {"results": [{"check_id": "x", "path": "a.py", "start": {"line": 1}, "end": {"line": 2}, "extra": {}}]}
    [f] = parse(data, "registry")
    assert f.cwe == "CWE-UNKNOWN" and f.trace == []
