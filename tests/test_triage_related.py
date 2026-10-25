from vulnscan import triage
from vulnscan.models import Finding, TraceStep
from vulnscan.targets import Target

VIEWS = """from dao import Student, Course

async def students(request):
    data = await request.post()
    await Student.create(conn, data['name'])
"""

DAO = """class Course:
    async def create(conn, title):
        await conn.execute('INSERT INTO c VALUES (%s)', (title,))

class Student:
    async def create(conn, name):
        q = "INSERT INTO students (name) VALUES ('%s')" % name
        await conn.execute(q)
"""

HELPER = """import subprocess

def run_it(cmd):
    return subprocess.Popen(cmd, shell=True)

def view(request):
    ip = request.POST.get('ip')
    q = "SELECT run_it(x) FROM t"
    return run_it("nmap " + ip)
"""


def _finding(file, line, snippet, trace=()):
    return Finding(tool="semgrep", ruleset="custom", rule_id="r", cwe="CWE-89", file=file, line=line,
                   end_line=line, snippet=snippet, trace=list(trace))


def _target(tmp_path, files):
    for name, text in files.items():
        (tmp_path / name).write_text(text)
    return Target(name="demo", lang="python", path=str(tmp_path))


def test_qualified_call_resolves_to_its_class_only(tmp_path):
    t = _target(tmp_path, {"views.py": VIEWS, "dao.py": DAO})
    out = triage.related(_finding("views.py", 5, "    await Student.create(conn, data['name'])"), t)
    assert "INSERT INTO students" in out
    assert "INSERT INTO c VALUES" not in out


def test_ambiguous_unqualified_call_is_not_resolved(tmp_path):
    t = _target(tmp_path, {"views.py": VIEWS, "dao.py": DAO})
    assert "Definition" not in triage.related(_finding("views.py", 5, "    create(conn, x)"), t)


def test_pysa_sink_callee_is_resolved(tmp_path):
    t = _target(tmp_path, {"views.py": VIEWS, "dao.py": DAO})
    f = _finding("views.py", 5, "x", [TraceStep("views.py", 5, "sink: app.dao.Student.create")])
    assert "INSERT INTO students" in triage.related(f, t)


def test_call_sites_of_enclosing_function_skip_strings(tmp_path):
    t = _target(tmp_path, {"helper.py": HELPER})
    out = triage.related(_finding("helper.py", 4, "    return subprocess.Popen(cmd, shell=True)"), t)
    assert "Call site of run_it()" in out
    assert out.count("Call site") == 1  # the match inside the SQL string is ignored
    assert '"nmap " + ip' in out


def test_v3_schema_puts_analysis_first():
    assert list(triage.SCHEMA_V3["properties"])[0] == "analysis"
    assert "reason" not in triage.SCHEMA_V3["properties"]
