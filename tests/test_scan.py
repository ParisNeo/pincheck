import ast
import builtins
from datetime import datetime, timedelta, timezone

import pytest

import pincheck.core as core
from pincheck import scan

SRC = '''import pipmaster as pm
from pipmaster import ensure_packages as ep, install_if_missing

REQS = ["pandas==2.0.0", "requests"]
pm.ensure_packages(["numpy>=1.20", "rich"], verbose=True)
pm.ensure_packages({"torch": {"specifier": ">=2.0.0", "index_url": "x"}, "tqdm": None,
                    "lib": {"vcs": "git+https://github.com/a/lib.git"}})
ep(REQS)
pm.ensure_packages(some_var)
pm.ensure_packages("flask")
install_if_missing("pillow", ">=1")
pm.ensure_requirements("reqs.txt")
# pm.ensure_packages(["commented"])
s = "pm.ensure_packages(['instring'])"
'''


def _now():
    return datetime.now(timezone.utc)


def _fake(osv=None, records=None):
    osv = osv or {}

    def fn(url, payload=None, headers=None):
        if url == core.OSV_BATCH:
            return {"results": [{"vulns": [{"id": i} for i in osv.get((q["package"]["name"], q["version"]), [])]}
                                for q in payload["queries"]]}
        if "osv.dev/v1/vulns" in url:
            return records[url.rsplit("/", 1)[1]]
        name = url.rstrip("/").rsplit("/", 1)[1]
        mk = lambda v, d: {"filename": f"{name}-{v}-py3-none-any.whl",
                           "upload-time": (_now() - timedelta(days=d)).isoformat(), "yanked": False}
        files = [mk("1.0", 400), mk("2.0", 100)] + ([mk("8.1.7", 400)] if name == "click" else [])
        return {"files": files, "project-status": {"status": "active"}}
    return fn


@pytest.fixture
def proj(tmp_path, monkeypatch):
    (tmp_path / "app.py").write_text(SRC)
    (tmp_path / "other.py").write_text('foo.ensure_packages(["x"])\n')   # no pipmaster import: ignored
    (tmp_path / "reqs.txt").write_text("click==8.1.7\n")
    (tmp_path / "venv").mkdir()
    (tmp_path / "venv" / "skip.py").write_text(SRC)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(core, "http_json", _fake())
    return tmp_path


def test_extraction(proj):
    items, unres, bad, n = scan.scan_paths(["."])
    assert n == 2 and not bad
    names = sorted(i.name for i in items)
    assert names == ["click", "flask", "lib", "numpy", "pandas", "pillow", "requests", "rich", "torch", "tqdm"] or \
        names == ["click", "flask", "git+https://github.com/a/lib.git", "numpy", "pandas", "pillow", "requests", "rich", "torch", "tqdm"]
    assert not any(i.name in ("commented", "instring", "x") for i in items)
    by = {i.name: i for i in items}
    assert by["numpy"].spec == ">=1.20" and by["rich"].spec is None
    assert by["torch"].spec == ">=2.0.0" and by["pandas"].spec == "==2.0.0"
    assert by["click"].via == "reqs.txt" and by["click"].edit is None
    assert any(i.unverifiable and "VCS" in i.unverifiable for i in items)
    assert [u.reason for u in unres if "some_var" in u.reason]
    assert all(i.path == "app.py" for i in items)   # venv/ skipped


def test_apply_all_rewrites_code_and_still_parses(proj):
    items, *_ = scan.scan_paths(["."])
    uniq = list(dict.fromkeys(i.req for i in items if i.req))
    results, _ = core.check(uniq)
    by_req = dict(zip(uniq, results))
    findings = [(i, by_req[i.req]) for i in items if i.req]
    by_path, manual = scan.interactive([f for f in findings if f[1].suggest], apply_all=True, out=lambda *_: None)
    scan.write_changes(by_path, assume_yes=True, out=lambda *_: None)
    new = (proj / "app.py").read_text()
    ast.parse(new)
    assert '"numpy==2.0"' in new and '"rich==2.0"' in new           # list items pinned to latest
    assert '"requests==2.0"' in new and '"pandas==2.0.0"' in new   # via REQS constant; existing pin untouched
    assert '"specifier": "==2.0"' in new and '"tqdm": "==2.0"' in new
    assert 'ensure_packages("flask==2.0")' in new and 'install_if_missing("pillow", "==2.0")' in new
    assert "git+https://github.com/a/lib.git" in new               # VCS untouched
    assert (proj / "venv" / "skip.py").read_text() == SRC            # skipped dir untouched


def test_interactive_choices(proj, monkeypatch):
    items, *_ = scan.scan_paths(["app.py"])
    uniq = list(dict.fromkeys(i.req for i in items if i.req))
    by_req = dict(zip(uniq, core.check(uniq)[0]))
    fixable = [(i, by_req[i.req]) for i in items if i.req and by_req[i.req].suggest]
    answers = iter(["s", "e", "bogus", "e", "==9.9", "p", "q"])
    monkeypatch.setattr(builtins, "input", lambda *_: next(answers))
    by_path, _ = scan.interactive(fixable, out=lambda *_: None)
    specs = sorted(s for _, s in by_path["app.py"])
    assert "==9.9" in specs and len(specs) == 2     # 1st skipped, 2nd custom (after invalid input), 3rd pinned, then quit
