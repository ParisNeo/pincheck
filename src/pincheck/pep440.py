"""Minimal PEP 440 versions and specifiers (stdlib only; enough to order releases)."""
from __future__ import annotations

import re
from functools import total_ordering
from typing import List, Optional, Tuple

INF, NINF = float("inf"), float("-inf")

_VERSION_RE = re.compile(
    r"""^\s*v?
    (?:(?P<epoch>\d+)!)?
    (?P<release>\d+(?:\.\d+)*)
    (?:[-_.]?(?P<pre_l>alpha|a|beta|b|preview|pre|c|rc)[-_.]?(?P<pre_n>\d+)?)?
    (?:(?:-(?P<post_n1>\d+))|(?:[-_.]?(?P<post_l>post|rev|r)[-_.]?(?P<post_n2>\d+)?))?
    (?:[-_.]?(?P<dev_l>dev)[-_.]?(?P<dev_n>\d+)?)?
    (?:\+(?P<local>[a-z0-9]+(?:[-_.][a-z0-9]+)*))?
    \s*$""",
    re.I | re.X,
)
_PRE = {"alpha": "a", "a": "a", "beta": "b", "b": "b", "c": "rc", "rc": "rc", "pre": "rc", "preview": "rc"}
_RANK = {"a": 0, "b": 1, "rc": 2}


@total_ordering
class Version:
    def __init__(self, text: str, m: "re.Match[str]"):
        self.text = text.strip()
        self.epoch = int(m.group("epoch") or 0)
        self.release: Tuple[int, ...] = tuple(int(x) for x in m.group("release").split("."))
        self.pre = (_PRE[m.group("pre_l").lower()], int(m.group("pre_n") or 0)) if m.group("pre_l") else None
        if m.group("post_n1") is not None:
            self.post: Optional[int] = int(m.group("post_n1"))
        elif m.group("post_l"):
            self.post = int(m.group("post_n2") or 0)
        else:
            self.post = None
        self.dev = int(m.group("dev_n") or 0) if m.group("dev_l") else None
        self.local = m.group("local")

        rel = list(self.release)
        while rel and rel[-1] == 0:
            rel.pop()
        if self.pre is None and self.post is None and self.dev is not None:
            pre = (NINF, 0)
        elif self.pre is None:
            pre = (INF, 0)
        else:
            pre = (_RANK[self.pre[0]], self.pre[1])
        local = () if self.local is None else tuple(
            (1, int(p), "") if p.isdigit() else (0, 0, p.lower()) for p in re.split(r"[-_.]", self.local)
        )
        self.public_key = (
            self.epoch, tuple(rel), pre,
            NINF if self.post is None else self.post,
            INF if self.dev is None else self.dev,
        )
        self.key = self.public_key + (local,)

    @property
    def is_prerelease(self) -> bool:
        return self.pre is not None or self.dev is not None

    def __eq__(self, o):
        return isinstance(o, Version) and self.key == o.key

    def __lt__(self, o):
        return self.key < o.key

    def __hash__(self):
        return hash(self.key)

    def __repr__(self):
        return f"Version({self.text!r})"

    __str__ = lambda self: self.text


def parse(text: str) -> Optional[Version]:
    m = _VERSION_RE.match(text or "")
    return Version(text, m) if m else None


_SPEC_RE = re.compile(r"^\s*(===|==|!=|~=|<=|>=|<|>)\s*([^\s,;]+)\s*$")
Specs = List[Tuple[str, str]]


def parse_specs(s: str) -> Optional[Specs]:
    """'>=1.2,<3' -> [('>=','1.2'),('<','3')]; '' -> []; invalid -> None."""
    s = s.strip().strip("()").strip()
    if not s:
        return []
    out = []
    for part in s.split(","):
        m = _SPEC_RE.match(part)
        if not m:
            return None
        out.append((m.group(1), m.group(2)))
    return out


def _clause(v: Version, op: str, rhs: str) -> bool:
    if op == "===":
        return v.text.lower() == rhs.lower()
    if rhs.endswith(".*") and op in ("==", "!="):
        base = parse(rhs[:-2])
        if base is None:
            return False
        eq = v.epoch == base.epoch and v.release[: len(base.release)] == base.release
        return eq if op == "==" else not eq
    r = parse(rhs)
    if r is None:
        return False
    if op == "==":
        return (v.key == r.key) if r.local else (v.public_key == r.public_key)
    if op == "!=":
        return (v.key != r.key) if r.local else (v.public_key != r.public_key)
    if op == ">=":
        return v.key >= r.key
    if op == "<=":
        return v.public_key <= r.public_key
    if op == ">":
        return v.key > r.key
    if op == "<":
        return v.public_key < r.public_key
    if op == "~=":
        if len(r.release) < 2:
            return False
        prefix = r.release[:-1]
        return v.key >= r.key and v.epoch == r.epoch and v.release[: len(prefix)] == prefix
    return False


def satisfies(v: Version, specs: Specs) -> bool:
    return all(_clause(v, op, rhs) for op, rhs in specs)


def lower_bound(specs: Specs) -> Optional[Version]:
    """Highest explicit lower bound (>=, >, ~=, ==X.*) — the oldest release the range allows."""
    best = None
    for op, rhs in specs:
        if op in (">=", ">", "~=") or (op == "==" and rhs.endswith(".*")):
            v = parse(rhs[:-2] if rhs.endswith(".*") else rhs)
            if v and (best is None or v > best):
                best = v
    return best
