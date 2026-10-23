from datetime import datetime, timedelta, timezone

import pincheck.core as core

NOW = datetime(2026, 10, 23, 12, tzinfo=timezone.utc)


def test_parse(tmp_path):
    (tmp_path / "base.txt").write_text("click==8.1.7\n")
    f = tmp_path / "r.txt"
    f.write_text(
        "-r base.txt\nrequests==2.31.0 \\\n  --hash=sha256:abc\n"
        'Flask[async]==3.0.0 ; python_version>"3.8"\nnumpy>=1.2\n# c\nPyYAML==6.0.1  # x\n'
    )
    pins, skipped = core.parse_requirements(str(f))
    assert pins == [("click", "8.1.7"), ("requests", "2.31.0"), ("flask", "3.0.0"), ("pyyaml", "6.0.1")]
    assert skipped == ["numpy>=1.2"]


def _fake(uploads, osv):
    def fn(url, payload=None):
        if url == core.OSV_BATCH:
            return {"results": [{"vulns": [{"id": i} for i in osv.get(q["package"]["name"], [])]}
                                for q in payload["queries"]]}
        if url.startswith("https://api.osv.dev/v1/vulns/"):
            vid = url.rsplit("/", 1)[1]
            return {"id": vid, "summary": "s", "aliases": []}
        name = url.split("/pypi/")[1].split("/")[0]
        return {"urls": [{"upload_time_iso_8601": uploads[name].isoformat()}], "info": {}}
    return fn


def test_verdicts(monkeypatch):
    uploads = {
        "old": NOW - timedelta(days=30),
        "fresh": NOW - timedelta(hours=5),
        "evil": NOW - timedelta(days=30),
        "vuln": NOW - timedelta(days=30),
    }
    monkeypatch.setattr(core, "http_json", _fake(uploads, {"evil": ["MAL-2026-1"], "vuln": ["GHSA-x"]}))
    res, code = core.check([(n, "1") for n in uploads], hours=48, now=NOW)
    st = {r.package: r.status for r in res}
    assert st["old"] == ["OK"]
    assert st["fresh"] == ["TOO_NEW"]
    assert st["evil"] == ["MALWARE"]
    assert st["vuln"] == ["VULN"]
    assert code == 1


def test_ignore_and_clean(monkeypatch):
    monkeypatch.setattr(core, "http_json", _fake({"vuln": NOW - timedelta(days=9)}, {"vuln": ["GHSA-x"]}))
    res, code = core.check([("vuln", "1")], hours=48, ignore=["GHSA-x"], now=NOW)
    assert res[0].status == ["OK"] and code == 0
