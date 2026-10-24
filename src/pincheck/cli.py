from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from .core import check, parse_requirements


def format_result(r, indent=""):
    """Lines describing one Result (shared by the requirements and scan commands)."""
    ver = r.version or "?"
    head = f"{r.package}=={ver}" if not r.assumed_latest else f"{r.package}{r.spec}  (latest match: {ver})"
    age = ""
    if r.age_hours is not None:
        age = f"  released {r.age_hours / 24:.0f}d ago" if r.age_hours >= 48 else f"  released {r.age_hours:.0f}h ago"
    lines = [f"[{','.join(r.status)}] {head}{age}"]
    if r.error:
        lines.append(f"    ! {r.error}")
    for m in r.malware:
        lines.append(f"    MALWARE {m}  https://osv.dev/vulnerability/{m}")
    for v in r.vulns:
        sev = f" [{v['severity']}]" if v.get("severity") else ""
        fix = f"fixed in {v['fixed_in']}" if v.get("fixed_in") else "no fix recorded"
        lines.append(f"    - {v['id']}{sev}: {v['summary']}  -> {fix}")
    lines += [f"    note: {n}" for n in r.notes]
    lines += [f"    advice: {a}" for a in r.advice]
    return [indent + x for x in lines]


def _render(results, skipped, hours):
    for r in results:
        print("\n".join(format_result(r)))
    changes = [r.suggest for r in results if r.suggest]
    if changes:
        print("\nSuggested pins:")
        for c in changes:
            print(f"    {c}")
    if skipped:
        print(f"\nskipped {len(skipped)} line(s) that can't be checked against an index (URLs, editable installs):")
        for s in skipped:
            print(f"    {s}")


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv and argv[0] == "scan":
        from .scan import main as scan_main

        return scan_main(argv[1:])
    ap = argparse.ArgumentParser(
        prog="pincheck",
        description="Check requirements against OSV (vulns + malware) and a release-age cooldown, "
                    "and suggest which version to use.  Also: `pincheck scan PATH` vets pipmaster calls in Python code.",
    )
    ap.add_argument("files", nargs="*", default=["requirements.txt"], help="requirements files ('-' = stdin)")
    ap.add_argument("--hours", type=int, default=48, help="minimum release age in hours (default 48; 0 disables)")
    ap.add_argument("--ignore", action="append", default=[], metavar="ID", help="advisory ID to ignore (repeatable)")
    ap.add_argument("--strict", action="store_true", help="treat unpinned ranges (>=, ~=, bare names) as failures")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--version", action="version", version=f"pincheck {__version__}")
    args = ap.parse_args(argv)

    reqs, skipped = [], []
    try:
        for f in args.files:
            r, s = parse_requirements(f)
            reqs += r
            skipped += s
    except OSError as e:
        print(f"error: {e}", file=sys.stderr)
        return 3
    reqs = list(dict.fromkeys(reqs))
    if not reqs:
        print("error: no checkable requirements found", file=sys.stderr)
        return 3

    try:
        results, code = check(reqs, hours=args.hours, ignore=args.ignore, strict=args.strict)
    except Exception as e:
        print(f"error: {e}", file=sys.stderr)
        return 3

    if args.json:
        print(json.dumps({"results": [r.to_dict() for r in results], "skipped": skipped}, indent=2))
    else:
        _render(results, skipped, args.hours)
    return code
