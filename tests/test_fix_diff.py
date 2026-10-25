import subprocess

import pytest

from vulnscan import targets
from vulnscan.targets import Target, fix_diff_lines


def git(cwd, *args):
    return subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True).stdout.strip()


@pytest.fixture
def cve_repo(tmp_path, monkeypatch):
    repo = tmp_path / "demo@vuln"
    repo.mkdir()
    git(repo, "init", "-q")
    git(repo, "config", "user.email", "t@example.com")
    git(repo, "config", "user.name", "t")
    (repo / "app.py").write_text("a = 1\nq = 'SELECT ' + x\nrun(q)\nb = 2\n")
    git(repo, "add", ".")
    git(repo, "commit", "-qm", "vuln")
    (repo / "app.py").write_text("a = 1\nq = 'SELECT ?'\nrun(q, (x,))\nlog(q)\nb = 2\n")
    git(repo, "commit", "-qam", "fix")
    monkeypatch.setattr(targets, "TARGETS_SRC", tmp_path)
    return git(repo, "rev-parse", "HEAD")


def test_old_side_is_lines_removed_from_vulnerable_version(cve_repo):
    t = Target(name="demo", lang="python", fix_commit=cve_repo, variant="vuln")
    assert fix_diff_lines(t, "old") == {"app.py": [2, 3]}


def test_new_side_is_lines_added_in_fixed_version(cve_repo):
    t = Target(name="demo", lang="python", fix_commit=cve_repo, variant="fixed")
    assert fix_diff_lines(t, "new") == {"app.py": [2, 3, 4]}
