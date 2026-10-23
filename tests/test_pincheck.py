from datetime import datetime, timedelta, timezone

import pytest

import pincheck.core as core
from pincheck.core import Req, check, fixed_in, parse_requirements
from pincheck.pep440 import parse, parse_specs, satisfies

NOW = datetime(2026, 10, 23, 12, tzinfo=timezone.utc)

# Real OSV shapes (GHSA-9wx4-h78v-vm56 / PYSEC-2018-28 as published for `requests`)
GHSA = {"id": "GHSA-9wx4-h78v-vm56", "aliases": ["CVE-2024-35195"], "summary": "verify=False sticks",
        "database_specific": {"severity": "MODERATE"},
        "affected": [{"package": {"ecosystem": "PyPI", "name": "requests"},
                      "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.32.0"}]}]}]}
PYSEC = {"id": "PYSEC-2018-28", "aliases": [], "details": "auth header leak",
         "affected": [{"package": {"ecosystem": "PyPI", "name": "requests"},
                       "ranges": [{"type": "GIT", "events": [{"introduced": "0"}, {"fixed": "c45d7c49ea"}]},
                                  {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.20.0"}]}]}]}


def test_parse(tmp_path):
    (tmp_path / "base.txt").write_text("click==8.1.7\n")
    f = tmp_path / "r.txt"
    f.write_text(
        "-r base.txt\nrequests==2.31.0 \\\n  --hash=sha256:abc\n"
        'Flask[async]==3.0.0 ; python_version>"3.8"\nnumpy>=1.2,<3\nrich\n# c\nPyYAML==6.0.1  # x\n'
        "foo @ https://x/y.whl\ngit+https://github.com/a/b\n-e .\n"
    )
    reqs, skipped = parse_requirements(str(f))
    assert [(r.name, r.pinned) for r in reqs] == [
        ("click", "8.1.7"), ("requests", "2.31.0"), ("flask", "3.0.0"),
        ("numpy", None), ("rich", None), ("pyyaml", "6.0.1")]
    assert reqs[3].spec == ">=1.2,<3" and reqs[4].spec == ""
    assert len(skipped) == 3


def test_fixed_in_real_shapes():
    assert fixed_in(GHSA, "requests", parse("2.19.0")) == "2.32.0"
    assert fixed_in(PYSEC, "requests", parse("2.19.0")) == "2.20.0"   # GIT range ignored
    assert fixed_in(PYSEC, "requests", parse("2.20.0")) is None        # already fixed
    la = {"affected": [{"package": {"ecosystem": "PyPI", "name": "x"},
                        "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "1.0"}, {"last_affected": "1.5"}]}]}]}
    assert fixed_in(la, "x", parse("1.2")) is None                     # no fix recorded


def _fake(releases, osv, records, status="active"):
    """releases: {name: {version: age_hours}}; osv: {(name, ver): [ids]}"""
    def fn(url, payload=None, headers=None):
        if url == core.OSV_BATCH:
            return {"results": [{"vulns": [{"id": i} for i in osv.get((q["package"]["name"], q["version"]), [])]}
                                for q in payload["queries"]]}
        if url.startswith("https://api.osv.dev/v1/vulns/"):
            return records[url.rsplit("/", 1)[1]]
        name = url.rstrip("/").rsplit("/", 1)[1]
        files = [{"filename": f"{name}-{v}-py3-none-any.whl",
                  "upload-time": (NOW - timedelta(hours=h)).isoformat(), "yanked": False}
                 for v, h in releases[name].items()]
        return {"files": files, "project-status": {"status": status}}
    return fn


REQS = {"requests": {"2.19.0": 24 * 2000, "2.20.0": 24 * 1900, "2.31.0": 24 * 500, "2.32.0": 24 * 300,
                     "2.32.3": 24 * 200, "2.34.2": 24 * 5, "2.35.0": 5}}


def test_vuln_gets_smallest_fix_and_latest(monkeypatch):
    monkeypatch.setattr(core, "http_json", _fake(
        REQS, {("requests", "2.19.0"): ["GHSA-9wx4-h78v-vm56", "PYSEC-2018-28"]},
        {"GHSA-9wx4-h78v-vm56": GHSA, "PYSEC-2018-28": PYSEC}))
    (r,), code = check([Req("requests", "==2.19.0", (("==", "2.19.0"),))], now=NOW)
    assert code == 2 and r.status == ["VULN"]
    assert {v["id"]: v["fixed_in"] for v in r.vulns} == {"GHSA-9wx4-h78v-vm56": "2.32.0", "PYSEC-2018-28": "2.20.0"}
    assert r.suggest == "requests==2.32.0"                 # max of the fixes, not 2.20.0
    assert "2.34.2" in r.advice[0]                          # newest clean, and 2.35.0 (5h old) is skipped


def test_range_assumes_latest_warns_and_pins(monkeypatch):
    monkeypatch.setattr(core, "http_json", _fake(
        REQS, {("requests", "2.19.0"): ["GHSA-9wx4-h78v-vm56"]}, {"GHSA-9wx4-h78v-vm56": GHSA}))
    r_ = Req("requests", ">=2.19.0", (( ">=", "2.19.0"),))
    (r,), code = check([r_], now=NOW)
    assert r.assumed_latest and r.version == "2.35.0"       # latest matching, cooldown applies -> TOO_NEW
    assert "RANGE" in r.status and "FLOOR_VULN" in r.status and "TOO_NEW" in r.status
    assert any("may be running an older" in n for n in r.notes)
    assert any("requests>=2.32.0" in a for a in r.advice)   # raise the floor
    assert r.suggest == "requests==2.34.2"                  # pin latest clean past cooldown
    assert code == 1


def test_clean_range_pins_latest_and_strict(monkeypatch):
    monkeypatch.setattr(core, "http_json", _fake({"requests": {"2.31.0": 24 * 90, "2.32.0": 24 * 30}}, {}, {}))
    r_ = Req("requests", ">=2.31", ((">=", "2.31"),))
    (r,), code = check([r_], now=NOW)
    assert r.suggest == "requests==2.32.0" and code == 0
    assert check([r_], strict=True, now=NOW)[1] == 2


def test_malware_and_quarantine(monkeypatch):
    mal = {"id": "MAL-2026-1", "aliases": [], "summary": "malicious", "affected": []}
    monkeypatch.setattr(core, "http_json", _fake(
        {"evil": {"1.0": 24 * 30, "0.9": 24 * 60}}, {("evil", "1.0"): ["MAL-2026-1"]}, {"MAL-2026-1": mal}))
    (r,), code = check([Req("evil", "==1.0", (("==", "1.0"),))], now=NOW)
    assert r.status == ["MALWARE"] and code == 1 and r.suggest == "evil==0.9"
    monkeypatch.setattr(core, "http_json", _fake({"q": {"1.0": 99}}, {}, {}, status="quarantined"))
    (r,), code = check([Req("q", "==1.0", (("==", "1.0"),))], now=NOW)
    assert "QUARANTINED" in r.status and code == 1


def test_ignore(monkeypatch):
    monkeypatch.setattr(core, "http_json", _fake(
        {"requests": {"2.19.0": 24 * 90}}, {("requests", "2.19.0"): ["PYSEC-2018-28"]}, {"PYSEC-2018-28": PYSEC}))
    (r,), code = check([Req("requests", "==2.19.0", (("==", "2.19.0"),))], ignore=["PYSEC-2018-28"], now=NOW)
    assert r.status == ["OK"] and code == 0
