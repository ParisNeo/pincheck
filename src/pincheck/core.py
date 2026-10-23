"""Parsing, OSV / PyPI lookups, fix analysis and advice. Stdlib only."""
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
from typing import Dict, Iterable, List, Optional

from . import __version__
from .pep440 import Version, lower_bound, parse, parse_specs, satisfies

OSV_BATCH = "https://api.osv.dev/v1/querybatch"
OSV_VULN = "https://api.osv.dev/v1/vulns/{}"
PYPI_SIMPLE = "https://pypi.org/simple/{}/"
SIMPLE_ACCEPT = "application/vnd.pypi.simple.v1+json"
TIMEOUT = 20

REQ_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(.*)$")
INCLUDE_RE = re.compile(r"^\s*(?:-r|--requirement)[\s=]+(\S+)")


def norm(name: str) -> str:
    """PEP 503 name normalisation."""
    return re.sub(r"[-_.]+", "-", name).lower()


# --------------------------------------------------------------------------- parsing
@dataclass(frozen=True)
class Req:
    name: str
    spec: str  # raw specifier text, e.g. ">=1.2,<3" ('' = unconstrained)
    specs: tuple  # parsed [(op, version)]

    @property
    def pinned(self) -> Optional[str]:
        if len(self.specs) == 1:
            op, v = self.specs[0]
            if op in ("==", "===") and not v.endswith(".*"):
                return v
        return None

    def __str__(self):
        return f"{self.name}{self.spec}"


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
    """Return (reqs, skipped). Follows `-r other.txt`. `path == '-'` reads stdin."""
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

    reqs, skipped = [], []
    for raw in _logical_lines(text):
        line = re.split(r"\s#", raw, maxsplit=1)[0].strip()
        if not line.startswith("-"):  # per-requirement options such as --hash=...
            line = re.split(r"\s+--[A-Za-z]", line, maxsplit=1)[0].strip()
        if not line or line.startswith("#"):
            continue
        inc = INCLUDE_RE.match(line)
        if inc:
            r, s = parse_requirements(os.path.join(base, inc.group(1)), seen)
            reqs += r
            skipped += s
            continue
        if line.startswith("-"):
            if line.startswith(("-e", "--editable")):
                skipped.append(line)
            continue  # other pip options
        m = REQ_RE.match(line)
        if not m:
            skipped.append(line)
            continue
        rest = m.group(2).split(";")[0].strip()  # drop environment markers
        if rest.startswith("@"):
            skipped.append(line)  # direct URL: nothing to check against an index
            continue
        specs = parse_specs(rest)
        if specs is None:
            skipped.append(line)
            continue
        reqs.append(Req(norm(m.group(1)), ",".join(f"{o}{v}" for o, v in specs), tuple(specs)))
    return list(dict.fromkeys(reqs)), skipped


# --------------------------------------------------------------------------- network
def http_json(url: str, payload=None, headers=None):
    data = json.dumps(payload).encode() if payload is not None else None
    h = {"Content-Type": "application/json", "User-Agent": f"pincheck/{__version__}"}
    h.update(headers or {})
    req = urllib.request.Request(url, data=data, headers=h)
    with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
        return json.load(r)


def _file_version(fn: str) -> Optional[str]:
    if fn.endswith(".whl"):
        parts = fn.split("-")
        return parts[1] if len(parts) > 1 else None
    for ext in (".tar.gz", ".tar.bz2", ".tar.xz", ".tgz", ".zip"):
        if fn.endswith(ext):
            stem = fn[: -len(ext)]
            return stem.rsplit("-", 1)[1] if "-" in stem else None
    return None


def fetch_index(name: str) -> dict:
    """PyPI Simple JSON (PEP 691/700): every release with its first upload time and yank state."""
    try:
        d = http_json(PYPI_SIMPLE.format(name), headers={"Accept": SIMPLE_ACCEPT})
    except urllib.error.HTTPError as e:
        return {"error": f"PyPI HTTP {e.code} (package not found?)"}
    except Exception as e:
        return {"error": f"PyPI error: {e}"}
    rel: Dict[str, dict] = {}
    for f in d.get("files", []):
        vt = _file_version(f.get("filename", ""))
        v = parse(vt) if vt else None
        if v is None or not f.get("upload-time"):
            continue
        t = datetime.fromisoformat(f["upload-time"].replace("Z", "+00:00"))
        r = rel.setdefault(v.text, {"v": v, "upload": t, "yanked": True})
        r["upload"] = min(r["upload"], t)
        r["yanked"] = r["yanked"] and bool(f.get("yanked"))  # yanked only if every file is
    return {
        "releases": rel,
        "status": (d.get("project-status") or {}).get("status", "active"),
        "reason": (d.get("project-status") or {}).get("reason"),
    }


def find_release(idx: dict, text: str) -> Optional[dict]:
    v = parse(text)
    if v is None:
        return None
    for r in idx.get("releases", {}).values():
        if r["v"].public_key == v.public_key:
            return r
    return None


def osv_ids(pairs) -> Dict[tuple, List[str]]:
    """{(name, version): [advisory ids]} via OSV querybatch, following pagination."""
    pairs = list(dict.fromkeys(pairs))
    out: Dict[tuple, List[str]] = {p: [] for p in pairs}
    pending = [(p, None) for p in pairs]
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


def osv_record(vid: str) -> dict:
    try:
        d = http_json(OSV_VULN.format(vid))
    except Exception as e:  # keep the id even if the detail fetch fails
        return {"id": vid, "summary": f"(detail fetch failed: {e})", "aliases": [],
                "withdrawn": False, "severity": None, "affected": []}
    return {
        "id": vid,
        "summary": d.get("summary") or (d.get("details") or "")[:120].replace("\n", " "),
        "aliases": d.get("aliases", []),
        "withdrawn": bool(d.get("withdrawn")),
        "severity": (d.get("database_specific") or {}).get("severity"),
        "affected": d.get("affected", []),
    }


# --------------------------------------------------------------------------- fix analysis
def fixed_in(record: dict, name: str, v: Version) -> Optional[str]:
    """Release that fixes `record` for installed version `v`, or None if no fix is recorded."""
    zero = parse("0")
    best: Optional[Version] = None
    for aff in record.get("affected", []):
        pkg = aff.get("package") or {}
        if pkg.get("ecosystem") != "PyPI" or norm(pkg.get("name", "")) != name:
            continue
        for rng in aff.get("ranges", []):
            if rng.get("type") not in ("ECOSYSTEM", "SEMVER"):
                continue  # GIT ranges hold commit hashes, not versions
            evs = []
            for e in rng.get("events", []):
                kind, val = next(iter(e.items()))
                ver = zero if val == "0" else parse(val)
                if ver is not None and kind in ("introduced", "fixed", "last_affected"):
                    evs.append((ver, kind))
            evs.sort(key=lambda x: x[0].key)
            start = None
            for ver, kind in evs:
                if kind == "introduced":
                    start = ver
                elif start is not None and kind == "fixed":
                    if start <= v < ver:
                        best = ver if best is None or ver > best else best
                    start = None
                elif start is not None and kind == "last_affected":
                    start = None  # affected through `ver`, but no fixed release is recorded
    return best.text if best else None


# --------------------------------------------------------------------------- result
@dataclass
class Result:
    package: str
    spec: str
    version: Optional[str]
    assumed_latest: bool = False
    released: Optional[str] = None
    age_hours: Optional[float] = None
    status: list = field(default_factory=list)
    malware: list = field(default_factory=list)
    vulns: list = field(default_factory=list)
    floor: Optional[dict] = None
    notes: list = field(default_factory=list)
    advice: list = field(default_factory=list)
    suggest: Optional[str] = None
    error: Optional[str] = None

    def to_dict(self):
        return self.__dict__.copy()


def _vuln_view(rec, name, v):
    return {"id": rec["id"], "aliases": rec["aliases"], "severity": rec["severity"],
            "summary": rec["summary"], "fixed_in": fixed_in(rec, name, v) if v else None}


def _major(v: Version) -> int:
    return v.release[0] if v.release else 0


def check(reqs, hours: int = 48, ignore: Iterable[str] = (), strict: bool = False,
          now: Optional[datetime] = None):
    """Return (results, exit_code). Exit: 0 clean | 1 malware/too new/quarantined | 2 vulns, yanked,
    unverified (or any unpinned range with strict=True)."""
    now = now or datetime.now(timezone.utc)
    ignore = set(ignore)
    cutoff = timedelta(hours=hours)

    def old_enough(r):
        return hours <= 0 or now - r["upload"] >= cutoff

    names = sorted({r.name for r in reqs})
    with ThreadPoolExecutor(max_workers=8) as ex:
        indexes = dict(zip(names, ex.map(fetch_index, names)))

    # ---- resolve what to inspect for each requirement
    plans = []
    for req in reqs:
        idx = indexes[req.name]
        p = {"req": req, "idx": idx, "text": None, "rel": None, "assumed": False,
             "floor": None, "error": idx.get("error")}
        if req.pinned:
            p["text"] = req.pinned
            if not p["error"]:
                p["rel"] = find_release(idx, req.pinned)
                if p["rel"] is None:
                    p["error"] = f"{req.pinned} not found on PyPI"
        elif not p["error"]:
            p["assumed"] = True
            cands = [r for r in idx["releases"].values()
                     if not r["v"].is_prerelease and not r["yanked"] and satisfies(r["v"], req.specs)]
            if cands:
                p["rel"] = max(cands, key=lambda r: r["v"])
                p["text"] = p["rel"]["v"].text
            else:
                p["error"] = f"no stable release satisfies '{req.spec or '*'}'"
            lb = lower_bound(req.specs)
            if lb is not None:
                p["floor"] = lb
        plans.append(p)

    # ---- OSV: target versions + range floors
    pairs = []
    for p in plans:
        if p["text"]:
            pairs.append((p["req"].name, p["text"]))
        if p["floor"] is not None and p["floor"].text != p["text"]:
            pairs.append((p["req"].name, p["floor"].text))
    ids = osv_ids(pairs)
    all_ids = sorted({i for v in ids.values() for i in v} - ignore)
    with ThreadPoolExecutor(max_workers=8) as ex:
        records = {r["id"]: r for r in ex.map(osv_record, all_ids)}

    def recs(pair):
        return [records[i] for i in ids.get(pair, []) if i in records and not records[i]["withdrawn"]]

    # ---- verdicts
    for p in plans:
        name, req, idx, rel = p["req"].name, p["req"], p["idx"], p["rel"]
        v = rel["v"] if rel else (parse(p["text"]) if p["text"] else None)
        rs = recs((name, p["text"])) if p["text"] else []
        p["mal"] = [r for r in rs if r["id"].startswith("MAL-")]
        p["vul"] = [_vuln_view(r, name, v) for r in rs if not r["id"].startswith("MAL-")]
        st = []
        if idx.get("status") == "quarantined":
            st.append("QUARANTINED")
        if p["mal"]:
            st.append("MALWARE")
        if p["error"]:
            st.append("UNVERIFIED")
        elif rel:
            if not old_enough(rel):
                st.append("TOO_NEW")
            if rel["yanked"]:
                st.append("YANKED")
        if p["vul"]:
            st.append("VULN")
        p["st"] = st

        p["floor_vulns"] = []
        if p["floor"] is not None and p["floor"].text != p["text"]:
            p["floor_vulns"] = [_vuln_view(r, name, p["floor"]) for r in recs((name, p["floor"].text))
                                if not r["id"].startswith("MAL-")]

    # ---- counsellor: find safe versions to recommend (second OSV pass, only where needed)
    for p in plans:
        p["cand_asc"], p["cand_desc"], p["floor_req"], p["unfixable"] = [], [], None, False
        if not ({"MALWARE", "TOO_NEW", "VULN", "YANKED", "QUARANTINED"} & set(p["st"])):
            continue
        if "QUARANTINED" in p["st"]:
            continue
        fixes = [parse(x["fixed_in"]) for x in p["vul"] if x["fixed_in"]]
        p["unfixable"] = any(not x["fixed_in"] for x in p["vul"])
        p["floor_req"] = max(fixes) if fixes and not p["unfixable"] else None
        elig = sorted(
            (r for r in p["idx"].get("releases", {}).values()
             if not r["v"].is_prerelease and not r["yanked"] and old_enough(r)
             and (not p["assumed"] or satisfies(r["v"], p["req"].specs))),
            key=lambda r: r["v"],
        )
        if p["floor_req"] is not None:
            p["cand_asc"] = [r for r in elig if r["v"] >= p["floor_req"]][:4]
        p["cand_desc"] = list(reversed(elig))[:3]
    cpairs = [(p["req"].name, r["v"].text) for p in plans for r in p["cand_asc"] + p["cand_desc"]]
    cids = osv_ids(cpairs) if cpairs else {}

    def clean(name, r):
        return not [i for i in cids.get((name, r["v"].text), []) if i not in ignore]

    # ---- assemble
    results, hard, soft = [], False, False
    for p in plans:
        req, name, rel = p["req"], p["req"].name, p["rel"]
        st, notes, advice = list(p["st"]), [], []
        idx = p["idx"]
        age = round((now - rel["upload"]).total_seconds() / 3600, 1) if rel else None

        minimum = next((r["v"].text for r in p["cand_asc"] if clean(name, r)), None)
        latest = next((r["v"].text for r in p["cand_desc"] if clean(name, r)), None)
        pin = minimum or latest

        if "QUARANTINED" in st:
            advice.append("PyPI has quarantined this project (the index serves no files; typically suspected "
                          "malware). Don't install it; it may be lifted later, so re-check before relying on it.")
        if "MALWARE" in st:
            advice.append("Known-malicious release. Remove it, and treat any machine or CI job that installed "
                          "it as compromised: rotate every secret it could read."
                          + (f" Newest clean release past the cooldown: {latest}." if latest else ""))
        if "TOO_NEW" in st:
            ok_at = (rel["upload"] + cutoff).strftime("%Y-%m-%d %H:%M UTC")
            advice.append(f"Released {age:.0f}h ago, inside the {hours}h cooldown (unreviewed by the community). "
                          f"Wait until {ok_at}" + (f", or use {latest}, the newest clean release past the cooldown." if latest else "."))
        if "YANKED" in st:
            advice.append("Yanked by its maintainers (usually a broken or bad release)."
                          + (f" Move to {pin}." if pin else ""))
        if "VULN" in st:
            if p["unfixable"]:
                nofix = ", ".join(x["id"] for x in p["vul"] if not x["fixed_in"])
                advice.append(f"No fixed release recorded for {nofix}. Mitigate or replace the package, and watch the advisory."
                              + (f" {latest} is the newest clean release." if latest else ""))
            elif minimum:
                s = f"Upgrade to {minimum}: the smallest release that fixes every advisory above."
                if parse(minimum) != p["floor_req"]:
                    s = (f"Advisories list {p['floor_req']} as the fix, but that release is yanked, not clean, or inside "
                         f"the cooldown. Upgrade to {minimum}, the next usable release.")
                if latest and latest != minimum:
                    lv = parse(latest)
                    major = lv and rel and _major(lv) != _major(rel["v"])
                    s += f" Newest clean release: {latest}" + (" (major bump, check the changelog)." if major else ".")
                advice.append(s)
            elif p["floor_req"] is not None:
                advice.append(f"Advisories say fixed in {p['floor_req']}, but no clean release at or above it is past "
                              "the cooldown yet. Wait, or check the advisory for a mitigation.")

        if p["assumed"]:
            st.append("RANGE")
            shown = req.spec or "no version constraint"
            notes.append(f"'{shown}' doesn't fix a version: pip installs whatever is newest at that moment. "
                         "Checked the latest matching release"
                         + (f" ({p['text']})" if p["text"] else "")
                         + "; anyone who installed earlier, or from an old cache or lockfile, may be running an older, "
                           "possibly vulnerable, version.")
            fv = p["floor_vulns"]
            if fv:
                st.append("FLOOR_VULN")
                fx = [parse(x["fixed_in"]) for x in fv if x["fixed_in"]]
                if fx and all(x["fixed_in"] for x in fv):
                    raise_to = max(fx).text
                    advice.append(f"The range's lower bound {p['floor'].text} is itself vulnerable "
                                  f"({', '.join(x['id'] for x in fv)}). Raise it: {name}>={raise_to}.")
                else:
                    advice.append(f"The range's lower bound {p['floor'].text} is vulnerable "
                                  f"({', '.join(x['id'] for x in fv)}) and some advisories have no fix recorded.")
        if p["assumed"] and not p["error"]:
            target = pin if (pin and p["st"]) else p["text"]
            if target and (not p["st"] or pin):
                advice.append(f"Pin it: {name}=={target}"
                              + ("" if p["st"] else " (the latest release; clean and past the cooldown)."))
        suggest = None
        if p["assumed"] and not p["error"]:
            suggest = f"{name}=={pin if (p['st'] and pin) else p['text']}" if (not p["st"] or pin) else None
        elif pin and p["st"]:
            suggest = f"{name}=={pin}"

        if idx.get("status") in ("archived", "deprecated"):
            notes.append(f"PyPI marks this project as {idx['status']}"
                         + (f": {idx['reason']}" if idx.get("reason") else "") + ".")

        hard |= bool({"MALWARE", "TOO_NEW", "QUARANTINED"} & set(st))
        soft |= bool({"VULN", "UNVERIFIED", "YANKED", "FLOOR_VULN"} & set(st)) or (strict and p["assumed"])

        results.append(Result(
            name, req.spec, p["text"], p["assumed"],
            rel["upload"].isoformat() if rel else None, age,
            st or ["OK"], [r["id"] for r in p["mal"]], p["vul"],
            ({"version": p["floor"].text, "vulns": p["floor_vulns"]} if p["floor"] is not None else None),
            notes, advice, suggest, p["error"],
        ))
    return results, 1 if hard else 2 if soft else 0
