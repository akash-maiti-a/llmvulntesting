import pytest

from vulnscan.models import Finding, TraceStep


@pytest.fixture
def make_finding():
    def make(file="app.php", line=10, cwe="CWE-89", tool="semgrep", rule_id="r", end_line=None, trace=None):
        return Finding(tool=tool, ruleset="custom", rule_id=rule_id, cwe=cwe, file=file, line=line,
                       end_line=end_line or line, message="m", snippet="s",
                       trace=trace or [TraceStep(file, line, "sink: x")])
    return make
