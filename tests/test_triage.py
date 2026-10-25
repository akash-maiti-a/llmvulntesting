import json

import httpx

from vulnscan import triage
from vulnscan.targets import Target


def test_prompt_redacts_path_and_names_cwe(tmp_path, make_finding):
    src = tmp_path / "src"
    src.mkdir()
    (src / "page.php").write_text("<?php\n$id = $_GET['id'];\nmysqli_query($c, \"SELECT 1 WHERE id=$id\");\n")
    t = Target(name="demo", lang="php", path=str(src))
    p = triage.build_prompt(make_finding("page.php", 3), t, triage.Config(prompt="v2"))
    assert "page.php" not in p
    assert "SQL injection (CWE-89)" in p
    assert "    3 mysqli_query" in p


def test_ask_parses_reply_and_flags_missing_verdict():
    def handler(request):
        body = json.loads(request.content)
        assert body["options"]["temperature"] == 0 and body["format"]["type"] == "object"
        content = ({"verdict": "false_positive", "confidence": 0.7, "reason": "escaped"}
                   if body["think"] is False else {"reason": "no verdict"})
        return httpx.Response(200, json={"message": {"content": json.dumps(content)}, "eval_count": 9})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    ok = triage.ask("p", triage.Config(prompt="v1"), client)
    bad = triage.ask("p", triage.Config(prompt="v1", think=True), client)
    assert ok["verdict"] == "false_positive" and ok["eval_tokens"] == 9
    assert bad["verdict"] == "error"


def test_ask_records_timeouts_as_errors():
    def handler(request):
        raise httpx.ReadTimeout("slow")

    client = httpx.Client(transport=httpx.MockTransport(handler))
    v = triage.ask("p", triage.Config(), client)
    assert v["verdict"] == "error" and "ReadTimeout" in v["error"]
