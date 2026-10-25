from vulnscan.scanners import pysa
from vulnscan.targets import Target

ISSUE = {
    "callable": "app.views.students", "code": 5051, "line": 57, "filename": "*",
    "message": "Data from [UserControlled] source(s) may reach [PartialSink[...]] sink(s)",
    "traces": [
        {"name": "forward", "roots": [{
            "kinds": [{"leaves": [{"name": "aiohttp.web_request.BaseRequest.post"}]}],
            "origin": {"filename": "*", "path": "/repo/app/views.py", "line": 55}}]},
        {"name": "backward", "roots": [{"kinds": [], "call": {
            "position": {"filename": "*", "path": "/repo/app/views.py", "line": 57},
            "resolves_to": ["app.dao.Student.create"]}}]},
    ],
}


def test_parse_maps_code_and_v3_paths():
    t = Target(name="demo", lang="python", path="/repo", scan_paths=["app"])
    [f] = pysa.parse([ISSUE], t)
    assert (f.tool, f.cwe, f.file, f.line) == ("pysa", "CWE-89", "app/views.py", 57)
    assert [s.note for s in f.trace] == ["source: aiohttp.web_request.BaseRequest.post",
                                         "sink: app.dao.Student.create"]


def test_eval_sink_is_retagged_cwe_95():
    rce = {"code": 5001, "sink_handle": {"kind": "Call", "callee": "eval"}, "traces": [
        {"name": "backward", "roots": [{"kinds": [{"leaves": [{"name": "eval"}]}]}]}]}
    shell = {"code": 5001, "sink_handle": {"kind": "Call", "callee": "subprocess.run"}, "traces": []}
    evaluator = {"code": 5001, "sink_handle": {"kind": "Call", "callee": "app.evaluator"}, "traces": []}
    assert pysa._cwe(rce) == "CWE-95"
    assert pysa._cwe(shell) == "CWE-78"
    assert pysa._cwe(evaluator) == "CWE-78"


def test_parse_drops_issues_outside_scan_paths():
    t = Target(name="demo", lang="python", path="/repo", scan_paths=["other"])
    assert pysa.parse([ISSUE], t) == []
