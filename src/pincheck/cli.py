from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from .core import check, parse_requirements


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="pincheck",
        description="Check pinned requirements against OSV (vulns + malware) and a release-age cooldown.",
    )
    ap.add_argument("files", nargs="*", default=["requirements.txt"], help="requirements files ('-' = stdin)")
    ap.add_argument("--hours", type=int, default=48, help="minimum release age in hours (default 48; 0 disables)")
    ap.add_argument("--ignore", action="append", default=[], metavar="ID", help="advisory ID to ignore (repeatable)")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--version", action="version", version=f"pincheck {__version__}")
    args = ap.parse_args(argv)

    pins, skipped = [], []
    try:
        for f in args.files:
            p, s = parse_requirements(f)
            pins += p
            skipped += s
    except OSError as e:
        print(f"error: {e}", file=sys.stderr)
        return 3
    pins = list(dict.fromkeys(pins))
    if not pins:
        print("error: no pinned requirements (name==version) found", file=sys.stderr)
        return 3

    try:
        results, code = check(pins, hours=args.hours, ignore=args.ignore)
    except Exception as e:
        print(f"error: {e}", file=sys.stderr)
        return 3

    if args.json:
        print(json.dumps({"results": [r.to_dict() for r in results], "unpinned_skipped": skipped}, indent=2))
        return code

    for r in results:
        age = "?" if r.age_hours is None else f"{r.age_hours:.0f}h"
        print(f"[{','.join(r.status):<12}] {r.package}=={r.version}  (age {age})")
        if r.error:
            print(f"    ! {r.error}")
        for m in r.malware:
            print(f"    MALWARE {m}  https://osv.dev/vulnerability/{m}")
        for v in r.vulns:
            print(f"    - {v['id']}: {v['summary']}")
    if skipped:
        print(f"\nskipped {len(skipped)} unpinned/unsupported line(s) — pin with == to check them:")
        for s in skipped:
            print(f"    {s}")
    return code
