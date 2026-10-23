"""Parsing, OSV / PyPI lookups and verdict logic. Stdlib only."""
from __future__ import annotations

import json
import os
import re
import sys
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Iterable, Optional

from . import __version__

OSV_BATCH = "https://api.osv.dev/v1/querybatch"
OSV_VULN = "https://api.osv.dev/v1/vulns/{}"
PYPI_VERSION = "https://pypi.org/pypi/{}/{}/json"
TIMEOUT = 20

PIN_RE = re.compile(
    r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*===?\s*([A-Za-z0-9._+!-]+)"
)
INCLUDE_RE = re.compile(r"^\s*(?:-r|--requirement)[\s=]+(\S+)")


def norm(name: str) -> str:
    """PEP 503 name normalisation."""
    return re.sub(r"[-_.]+", "-", name).lower()


def _logical_lines(text: str) -> Iterable[str]:
    buf = ""
    for raw in text.splitlines():
        if raw.rstrip().endswith("\\"):
            buf += raw.rstrip()[:-1] + " "
            continue
        yield buf + raw
        buf = ""
    if buf:
        yield buf


def parse_requirements(path: str, _seen: Optional[set] = None):
    """Return (pins, skipped). Follows `-r other.txt`. `path == '-'` reads stdin."""
    seen = _seen if _seen is not None else set()
    if path == "-":
        text, base = sys.stdin.read(), os.getcwd()
    else:
        real = os.path.realpath(path)
        if real in seen:
            return [], []
        seen.add(real)
        with open(path, encoding="utf-8") as f:
            text = f.read()
        base = os.path.dirname(real)

    pins, skipped = [], []
    for raw in _logical_lines(text):
        line = re.split(r"\s#", raw, maxsplit=1)[0].strip()
        if not line or line.startswith("#"):
            continue
        inc = INCLUDE_RE.match(line)
        if inc:
            p, s = parse_requirements(os.path.join(base, inc.group(1)), seen)
            pins += p
            skipped += s
            continue
        if line.startswith("-"):  # other pip options
            continue
        m = PIN_RE.match(line)
        if m:
            pins.append((norm(m.group(1)), m.group(2)))
        else:
            skipped.append(line)
    return list(dict.fromkeys(pins)), skipped


def http_json(url: str, payload=None):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json", "User-Agent": f"pincheck/{__version__}"},
    )
    with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
        return json.load(r)


def osv_ids(pins):
    """{(name, version): [advisory ids]} via OSV querybatch, following pagination."""
    out = {p: [] for p in pins}
    pending = [(p, None) for p in pins]
    while pending:
        queries = []
        for (name, ver), token in pending:
            q = {"package": {"name": name, "ecosystem": "PyPI"}, "version": ver}
            if token:
                q["page_token"] = token
            queries.append(q)
        resp = http_json(OSV_BATCH, {"queries": queries})
        nxt = []
        for (pin, _), res in zip(pending, resp["results"]):
            out[pin].extend(v["id"] for v in res.get("vulns", []))
            if res.get("next_page_token"):
                nxt.append((pin, res["next_page_token"]))
        pending = nxt
    return out


def osv_detail(vid: str) -> dict:
    try:
        d = http_json(OSV_VULN.format(vid))
        return {
            "id": vid,
            "summary": d.get("summary") or d.get("details", "")[:120],
            "aliases": d.get("aliases", []),
            "withdrawn": bool(d.get("withdrawn")),
        }
    except Exception as e:  # keep the id even if the detail fetch fails
        return {"id": vid, "summary": f"(detail fetch failed: {e})", "aliases": [], "withdrawn": False}


def pypi_info(name: str, ver: str) -> dict:
    try:
        d = http_json(PYPI_VERSION.format(name, ver))
    except urllib.error.HTTPError as e:
        return {"error": f"PyPI HTTP {e.code} (version not found?)"}
    except Exception as e:
        return {"error": f"PyPI error: {e}"}
    files = d.get("urls", [])
    times = [
        datetime.fromisoformat(f["upload_time_iso_8601"].replace("Z", "+00:00"))
        for f in files
        if f.get("upload_time_iso_8601")
    ]
    if not times:
        return {"error": "no files / upload time on PyPI"}
    return {
        "first_upload": min(times),
        "yanked": any(f.get("yanked") for f in files) or bool(d.get("info", {}).get("yanked")),
    }


@dataclass
class Result:
    package: str
    version: str
    age_hours: Optional[float]
    status: list = field(default_factory=list)
    malware: list = field(default_factory=list)
    vulns: list = field(default_factory=list)
    error: Optional[str] = None

    def to_dict(self):
        return self.__dict__.copy()


def check(pins, hours: int = 48, ignore: Iterable[str] = (), now: Optional[datetime] = None):
    """Return (results, exit_code). Exit: 0 clean | 1 malware/too new | 2 vulns/yanked/unverified."""
    now = now or datetime.now(timezone.utc)
    ignore = set(ignore)
    cutoff = timedelta(hours=hours)
    ids = osv_ids(pins)
    with ThreadPoolExecutor(max_workers=8) as ex:
        infos = dict(zip(pins, ex.map(lambda p: pypi_info(*p), pins)))
        all_ids = sorted({i for v in ids.values() for i in v} - ignore)
        details = {d["id"]: d for d in ex.map(osv_detail, all_ids)}

    results, hard, soft = [], False, False
    for pin in pins:
        name, ver = pin
        info = infos[pin]
        vulns = [details[i] for i in ids[pin] if i in details and not details[i]["withdrawn"]]
        mal = [v for v in vulns if v["id"].startswith("MAL-")]
        cve = [v for v in vulns if not v["id"].startswith("MAL-")]

        status, age_h = [], None
        if mal:
            status.append("MALWARE")
        if "error" in info:
            status.append("UNVERIFIED")
        else:
            age_h = round((now - info["first_upload"]).total_seconds() / 3600, 1)
            if now - info["first_upload"] < cutoff:
                status.append("TOO_NEW")
            if info["yanked"]:
                status.append("YANKED")
        if cve:
            status.append("VULN")

        hard |= bool({"MALWARE", "TOO_NEW"} & set(status))
        soft |= bool({"VULN", "UNVERIFIED", "YANKED"} & set(status))

        results.append(
            Result(
                name, ver, age_h, status or ["OK"],
                [v["id"] for v in mal],
                [{"id": v["id"], "aliases": v["aliases"], "summary": v["summary"]} for v in cve],
                info.get("error"),
            )
        )
    return results, 1 if hard else 2 if soft else 0
