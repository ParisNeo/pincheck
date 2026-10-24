"""`pincheck scan`: find pipmaster calls in Python code, vet the packages, propose fixes.

Static analysis only (ast): nothing is imported or executed. Understands
  ensure_packages / async_ensure_packages   str | list[str] | dict (values: None, "spec", "latest",
                                            {"specifier"|"condition"|"version": ..., "vcs": ...})
  install_if_missing / async_install_if_missing   (package, version_specifier)
  ensure_requirements / async_ensure_requirements (requirements_file: followed if the file exists)
through `import pipmaster as pm`, `from pipmaster import ensure_packages as ep`, and manager instances.
Requirements held in a module-level constant (`REQS = [...]; pm.ensure_packages(REQS)`) are resolved.
"""
from __future__ import annotations

import argparse
import ast
import difflib
import json
import os
import re
import sys
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from . import __version__
from .core import Req, check, parse_requirement_line, parse_requirements
from .pep440 import parse_specs

TARGETS = {
    "ensure_packages", "async_ensure_packages",
    "install_if_missing", "async_install_if_missing",
    "ensure_requirements", "async_ensure_requirements",
}
SKIP_DIRS = {".git", ".hg", ".svn", ".venv", "venv", "env", ".tox", ".nox", "node_modules", "__pycache__",
             "site-packages", "build", "dist", ".mypy_cache", ".pytest_cache", ".ruff_cache"}
NAME_SPEC_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*(?:\[[^\]]*\])?)\s*(.*)$", re.S)
VCS_RE = re.compile(r"^\s*(git|hg|svn|bzr)\+|://")
SPEC_KEYS = ("specifier", "condition", "version")


# --------------------------------------------------------------------------- model
@dataclass
class Edit:
    path: str
    start: int            # byte offsets of the literal to replace
    end: int
    mode: str             # "req": literal holds the whole requirement | "spec": literal holds only the specifier
    name: str = ""        # original name text (mode "req")
    suffix: str = ""      # environment marker to preserve (mode "req")
    quote: str = '"'

    def render(self, spec: str) -> str:
        body = f"{self.name}{spec}{self.suffix}" if self.mode == "req" else spec
        return f"{self.quote}{body}{self.quote}"


@dataclass
class Item:
    path: str
    line: int
    call: str
    name: str
    spec: Optional[str]
    raw: str
    req: Optional[Req] = None
    unverifiable: Optional[str] = None
    edit: Optional[Edit] = None
    via: Optional[str] = None  # requirements file followed from ensure_requirements()


@dataclass
class Unresolved:
    path: str
    line: int
    call: str
    reason: str


# --------------------------------------------------------------------------- per-file analysis
class _FileScan:
    def __init__(self, path: str, src: bytes, tree: ast.AST, root: str):
        self.path, self.src, self.tree, self.root = path, src, tree, root
        self.starts = [0]
        for ln in src.split(b"\n")[:-1]:
            self.starts.append(self.starts[-1] + len(ln) + 1)
        self.assigns: Dict[str, List[ast.AST]] = {}
        self.mod_alias, self.func_alias, self.imports = set(), {}, False
        self.items: List[Item] = []
        self.unresolved: List[Unresolved] = []
        self._index()

    # -- indexing: imports and constant assignments
    def _index(self):
        for n in ast.walk(self.tree):
            if isinstance(n, ast.Import):
                for a in n.names:
                    if a.name == "pipmaster" or a.name.startswith("pipmaster."):
                        self.imports = True
                        self.mod_alias.add(a.asname or a.name.split(".")[0])
            elif isinstance(n, ast.ImportFrom) and n.module and n.module.split(".")[0] == "pipmaster":
                self.imports = True
                for a in n.names:
                    if a.name in TARGETS:
                        self.func_alias[a.asname or a.name] = a.name
            elif isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name):
                self.assigns.setdefault(n.targets[0].id, []).append(n.value)
            elif isinstance(n, ast.AnnAssign) and isinstance(n.target, ast.Name) and n.value is not None:
                self.assigns.setdefault(n.target.id, []).append(n.value)
            elif isinstance(n, ast.AugAssign) and isinstance(n.target, ast.Name):
                self.assigns.setdefault(n.target.id, []).append(None)  # makes the name ambiguous

    def _call_name(self, call: ast.Call) -> Optional[str]:
        f = call.func
        if isinstance(f, ast.Name):
            return self.func_alias.get(f.id)
        if isinstance(f, ast.Attribute) and f.attr in TARGETS and self.imports:
            return f.attr
        return None

    # -- value resolution
    def resolve(self, node, depth=0):
        if isinstance(node, ast.Constant):
            if isinstance(node.value, str):
                return ("str", node, node.value)
            if node.value is None:
                return ("none", node)
            return ("dyn", f"constant {node.value!r}")
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            return ("seq", [("dyn", "starred expression") if isinstance(e, ast.Starred) else self.resolve(e, depth)
                            for e in node.elts])
        if isinstance(node, ast.Dict):
            return ("map", [(self.resolve(k, depth) if k is not None else ("dyn", "** unpacking"),
                             self.resolve(v, depth)) for k, v in zip(node.keys, node.values)])
        if isinstance(node, ast.Name):
            vals = self.assigns.get(node.id, [])
            if depth > 5 or len(vals) != 1 or vals[0] is None:
                why = "not assigned in this file" if not vals else f"assigned {len(vals)} times"
                return ("dyn", f"variable '{node.id}' ({why})")
            return self.resolve(vals[0], depth + 1)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            a, b = self.resolve(node.left, depth), self.resolve(node.right, depth)
            if a[0] == "seq" and b[0] == "seq":
                return ("seq", a[1] + b[1])
            return ("dyn", "concatenation of non-literals")
        return ("dyn", type(node).__name__ + " expression")

    # -- edits
    def _offset(self, line, col):
        return self.starts[line - 1] + col

    def edit_for(self, node, mode, name="", suffix="") -> Optional[Edit]:
        s, e = self._offset(node.lineno, node.col_offset), self._offset(node.end_lineno, node.end_col_offset)
        if isinstance(node, ast.Constant) and node.value is None:
            return Edit(self.path, s, e, mode, name, suffix, '"')
        seg = self.src[s:e].decode("utf-8", "replace")
        if not seg or seg[0] not in "'\"" or seg.startswith(('"""', "'''")):
            return None  # prefixed (r"", f"") or triple-quoted: leave to the human
        try:
            if ast.literal_eval(seg) != node.value:
                return None
        except Exception:
            return None
        return Edit(self.path, s, e, mode, name, suffix, seg[0])

    # -- item construction
    def _make(self, call, line, name, spec, raw, edit, via=None):
        it = Item(self.path, line, call, name, spec, raw, edit=edit, via=via)
        if VCS_RE.match(name) or (spec and VCS_RE.match(spec)):
            it.unverifiable = "VCS/URL source: can't be checked against an index"
        else:
            s = (spec or "").strip()
            line_text = name + ("" if s.lower() == "latest" else s)
            it.req = parse_requirement_line(line_text)
            if it.req is None:
                it.unverifiable = f"can't parse requirement '{line_text}'"
        self.items.append(it)

    def _from_string(self, call, line, res, key_value=None):
        _, node, value = res
        head, _, tail = value.partition(";")
        m = NAME_SPEC_RE.match(head)
        if not m:
            self.unresolved.append(Unresolved(self.path, line, call, f"unparseable requirement {value!r}"))
            return
        name, spec = m.group(1), m.group(2).strip() or None
        suffix = f"; {tail.strip()}" if tail.strip() else ""
        self._make(call, line, name, spec, value, self.edit_for(node, "req", name, suffix))

    def _from_requirements(self, call, line, res):
        k = res[0]
        if k == "str":
            self._from_string(call, line, res)
        elif k == "seq":
            for sub in res[1]:
                if sub[0] == "str":
                    self._from_string(call, line, sub)
                else:
                    self.unresolved.append(Unresolved(self.path, line, call, f"list element: {sub[1] if sub[0] == 'dyn' else sub[0]}"))
        elif k == "map":
            for key, val in res[1]:
                if key[0] != "str":
                    self.unresolved.append(Unresolved(self.path, line, call, f"dict key: {key[1] if key[0] == 'dyn' else key[0]}"))
                    continue
                self._from_dict_entry(call, line, key, val)
        else:
            self.unresolved.append(Unresolved(self.path, line, call, res[1] if k == "dyn" else "no packages found"))

    def _from_dict_entry(self, call, line, key, val):
        _, knode, kval = key
        m = NAME_SPEC_RE.match(kval)
        name = m.group(1) if m else kval
        embedded = (m.group(2).strip() or None) if m else None
        if val[0] == "none":
            if embedded:  # {"numpy>=1.2": None}: the key carries the specifier
                self._make(call, line, name, embedded, kval, self.edit_for(knode, "req", name))
            else:
                self._make(call, line, name, None, f"{kval}: None", self.edit_for(val[1], "spec"))
        elif val[0] == "str":
            self._make(call, line, name, val[2], f"{kval}: {val[2]!r}", self.edit_for(val[1], "spec"))
        elif val[0] == "map":
            spec, edit, vcs = None, None, None
            for ik, iv in val[1]:
                if ik[0] != "str":
                    continue
                if ik[2] in SPEC_KEYS and iv[0] == "str":
                    spec, edit = iv[2], self.edit_for(iv[1], "spec")
                elif ik[2] == "vcs" and iv[0] == "str":
                    vcs = iv[2]
            self._make(call, line, vcs or name, spec, f"{kval}: {{...}}", edit)
        else:
            self.unresolved.append(Unresolved(self.path, line, call, f"value for '{kval}': {val[1] if val[0] == 'dyn' else val[0]}"))

    # -- calls
    @staticmethod
    def _arg(call, pos, kw):
        if len(call.args) > pos and not isinstance(call.args[pos], ast.Starred):
            return call.args[pos]
        for k in call.keywords:
            if k.arg == kw:
                return k.value
        return None

    def run(self):
        for n in ast.walk(self.tree):
            if not isinstance(n, ast.Call):
                continue
            name = self._call_name(n)
            if not name:
                continue
            base = name.replace("async_", "")
            if base == "ensure_packages":
                arg = self._arg(n, 0, "requirements")
                if arg is None:
                    self.unresolved.append(Unresolved(self.path, n.lineno, name, "no `requirements` argument found"))
                else:
                    self._from_requirements(name, n.lineno, self.resolve(arg))
            elif base == "install_if_missing":
                pkg, spec = self._arg(n, 0, "package"), self._arg(n, 1, "version_specifier")
                rp = self.resolve(pkg) if pkg is not None else ("dyn", "no `package` argument")
                if rp[0] != "str":
                    self.unresolved.append(Unresolved(self.path, n.lineno, name, rp[1] if rp[0] == "dyn" else rp[0]))
                    continue
                rs = self.resolve(spec) if spec is not None else ("none", None)
                if rs[0] == "str":
                    m = NAME_SPEC_RE.match(rp[2])
                    self._make(name, n.lineno, m.group(1) if m else rp[2], rs[2], f"{rp[2]}, {rs[2]!r}",
                               self.edit_for(rs[1], "spec"))
                elif rs[0] == "none":
                    self._from_string(name, n.lineno, rp)
                else:
                    self.unresolved.append(Unresolved(self.path, n.lineno, name, "version_specifier is dynamic"))
            elif base == "ensure_requirements":
                arg = self._arg(n, 0, "requirements_file")
                r = self.resolve(arg) if arg is not None else ("dyn", "no file argument")
                if r[0] != "str":
                    self.unresolved.append(Unresolved(self.path, n.lineno, name, f"requirements file path: {r[1] if r[0] == 'dyn' else r[0]}"))
                    continue
                self._follow_requirements_file(name, n.lineno, r[2])
        return self

    def _follow_requirements_file(self, call, line, rel):
        for base in (os.path.dirname(os.path.abspath(self.path)), self.root, os.getcwd()):
            cand = os.path.normpath(os.path.join(base, rel))
            if os.path.isfile(cand):
                reqs, _ = parse_requirements(cand)
                for r in reqs:
                    self.items.append(Item(self.path, line, call, r.name, r.spec or None, f"{r.name}{r.spec}",
                                           req=r, via=os.path.relpath(cand)))
                return
        self.unresolved.append(Unresolved(self.path, line, call, f"requirements file '{rel}' not found (path is relative to the runtime cwd)"))


# --------------------------------------------------------------------------- discovery
def scan_paths(paths, exclude=()):
    """Return (items, unresolved, skipped_files, n_files)."""
    skip = SKIP_DIRS | set(exclude)
    files = []
    for p in paths:
        if os.path.isfile(p):
            files.append((p, os.path.dirname(os.path.abspath(p))))
        else:
            for d, dirs, names in os.walk(p):
                dirs[:] = sorted(x for x in dirs if x not in skip and not x.endswith(".egg-info"))
                files += [(os.path.join(d, n), os.path.abspath(p)) for n in sorted(names) if n.endswith(".py")]
    items, unres, bad = [], [], []
    for f, root in files:
        try:
            src = open(f, "rb").read()
            tree = ast.parse(src.decode("utf-8"), filename=f)
        except (SyntaxError, UnicodeDecodeError, ValueError, OSError) as e:
            bad.append((f, str(e).splitlines()[0] if str(e) else type(e).__name__))
            continue
        fs = _FileScan(os.path.relpath(f), src, tree, root).run()
        items += fs.items
        unres += fs.unresolved
    return items, unres, bad, len(files)


# --------------------------------------------------------------------------- applying edits
def apply_edits(src: bytes, edits: List[Tuple[Edit, str]]) -> bytes:
    for e, spec in sorted(edits, key=lambda x: x[0].start, reverse=True):
        src = src[: e.start] + e.render(spec).encode("utf-8") + src[e.end:]
    return src


def _spec_of(pin: str) -> str:
    """'numpy==2.1.0' -> '==2.1.0' ; 'numpy>=1.22' -> '>=1.22'"""
    return re.sub(r"^[A-Za-z0-9][A-Za-z0-9._-]*(?:\[[^\]]*\])?", "", pin)


def interactive(findings, apply_all=False, out=print):
    """Walk the user through fixes. Returns {path: [(Edit, spec)]}; nothing is written here."""
    chosen: Dict[Tuple[str, int, int], Tuple[Edit, str]] = {}
    manual = []
    todo = [(it, r) for it, r in findings if (r.suggest or r.raise_floor)]
    for i, (it, r) in enumerate(todo, 1):
        pin = _spec_of(r.suggest) if r.suggest else None
        fl = _spec_of(r.raise_floor) if r.raise_floor else None
        if it.edit is None:
            manual.append((it, r))
            continue
        key = (it.edit.path, it.edit.start, it.edit.end)
        if key in chosen:
            continue
        out(f"\n({i}/{len(todo)}) {it.path}:{it.line}  {it.call}  {it.raw}")
        out("\n".join(_fmt(r, "    ")))
        if apply_all:
            pick = pin or fl
            chosen[key] = (it.edit, pick)
            out(f"    -> applying {it.name}{pick}")
            continue
        opts = []
        if pin:
            opts.append(f"[p]in {it.name}{pin}")
        if fl:
            opts.append(f"[f]loor {it.name}{fl}")
        opts += ["[e]dit", "[s]kip", "[a]ccept all remaining", "[q]uit"]
        default = "p" if pin else "f"
        while True:
            try:
                ans = (input(f"    {'  '.join(opts)}  (default {default}): ") or default).strip().lower()
            except EOFError:
                ans = "q"
            if ans == "p" and pin:
                chosen[key] = (it.edit, pin)
            elif ans == "f" and fl:
                chosen[key] = (it.edit, fl)
            elif ans == "a":
                chosen[key] = (it.edit, pin or fl)
                apply_all = True
            elif ans == "e":
                try:
                    custom = input("    specifier (e.g. ==2.1.0 or >=2.1,<3): ").strip()
                except EOFError:
                    custom = ""
                if not custom or not parse_specs(custom):
                    out("    not a valid specifier")
                    continue
                chosen[key] = (it.edit, custom)
            elif ans == "s":
                pass
            elif ans == "q":
                out("    stopping; changes chosen so far are kept for review")
                return _group(chosen), manual
            else:
                continue
            break
    return _group(chosen), manual


def _group(chosen):
    by: Dict[str, List[Tuple[Edit, str]]] = {}
    for e, spec in chosen.values():
        by.setdefault(e.path, []).append((e, spec))
    return by


def _fmt(r, indent):
    from .cli import format_result

    return format_result(r, indent)


def write_changes(by_path, assume_yes=False, out=print, ask=input):
    new = {}
    for path, edits in by_path.items():
        old = open(path, "rb").read()
        updated = apply_edits(old, edits)
        try:
            ast.parse(updated.decode("utf-8"))
        except SyntaxError as e:  # never write a file we broke
            out(f"refusing to change {path}: result wouldn't parse ({e})")
            continue
        new[path] = (old, updated)
    if not new:
        return 0
    for path, (old, updated) in new.items():
        out("".join(difflib.unified_diff(old.decode().splitlines(True), updated.decode().splitlines(True),
                                         f"a/{path}", f"b/{path}")))
    n = sum(len(by_path[p]) for p in new)
    if not assume_yes:
        try:
            if ask(f"\nWrite {n} change(s) to {len(new)} file(s)? [y/N] ").strip().lower() != "y":
                out("nothing written")
                return 0
        except EOFError:
            out("nothing written")
            return 0
    for path, (_, updated) in new.items():
        with open(path, "wb") as f:
            f.write(updated)
    out(f"wrote {n} change(s) to {len(new)} file(s)")
    return n


# --------------------------------------------------------------------------- CLI
def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="pincheck scan",
        description="Find pipmaster ensure_packages/install_if_missing calls in Python code, vet the packages "
                    "(OSV vulns, malware, release cooldown) and propose pinned versions.",
    )
    ap.add_argument("paths", nargs="*", default=["."], help="files or directories (default: .)")
    ap.add_argument("--hours", type=int, default=48, help="minimum release age in hours (default 48; 0 disables)")
    ap.add_argument("--ignore", action="append", default=[], metavar="ID", help="advisory ID to ignore (repeatable)")
    ap.add_argument("--exclude", action="append", default=[], metavar="DIR", help="extra directory name to skip")
    ap.add_argument("--strict", action="store_true", help="unpinned packages count as failures")
    ap.add_argument("-i", "--interactive", action="store_true", help="review each proposed fix and edit the code")
    ap.add_argument("--apply", action="store_true", help="apply every proposed fix without asking (prints the diff)")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    args = ap.parse_args(argv)

    items, unres, bad, nfiles = scan_paths(args.paths, args.exclude)
    checkable = [i for i in items if i.req]
    if not items and not unres:
        print(f"scanned {nfiles} Python file(s): no pipmaster ensure_packages calls found")
        return 0

    try:
        uniq = list(dict.fromkeys(i.req for i in checkable))
        res_by_req = {}
        if uniq:
            results, code = check(uniq, hours=args.hours, ignore=args.ignore, strict=args.strict)
            res_by_req = dict(zip(uniq, results))
        else:
            code = 0
    except Exception as e:
        print(f"error: {e}", file=sys.stderr)
        return 3
    findings = [(i, res_by_req[i.req]) for i in checkable]

    if args.json:
        print(json.dumps({
            "files_scanned": nfiles,
            "findings": [{"file": i.path, "line": i.line, "call": i.call, "raw": i.raw, "via": i.via,
                          "editable": i.edit is not None, "result": r.to_dict()} for i, r in findings],
            "unverifiable": [{"file": i.path, "line": i.line, "raw": i.raw, "reason": i.unverifiable}
                             for i in items if i.unverifiable],
            "unresolved": [u.__dict__ for u in unres],
            "unparseable_files": [{"file": f, "error": e} for f, e in bad],
        }, indent=2))
        return code

    print(f"scanned {nfiles} Python file(s): {len(items)} package reference(s) in pipmaster calls\n")
    by_loc: Dict[tuple, list] = {}
    for it, r in findings:
        by_loc.setdefault((it.path, it.line, it.call), []).append((it, r))
    for it in items:
        if it.unverifiable:
            by_loc.setdefault((it.path, it.line, it.call), []).append((it, None))
    for (path, line, call), rows in sorted(by_loc.items()):
        print(f"{path}:{line}  {call}")
        for it, r in rows:
            if r is None:
                print(f"  ? {it.raw}: {it.unverifiable}")
                continue
            via = f"  (from {it.via})" if it.via else ""
            print(f"  {it.raw}{via}")
            print("\n".join(_fmt(r, "    ")))
    for u in unres:
        print(f"\n{u.path}:{u.line}  {u.call}: can't analyse statically ({u.reason}) -> verify by hand")
    for f, e in bad:
        print(f"\nskipped unparseable file {f}: {e}")
    if args.strict and (unres or any(i.unverifiable for i in items)):
        code = max(code, 2)

    fixable = [(i, r) for i, r in findings if (r.suggest or r.raise_floor)]
    if args.interactive or args.apply:
        if args.interactive and not sys.stdin.isatty():
            print("\nerror: -i needs a terminal (use --apply to accept all fixes)", file=sys.stderr)
            return 3
        by_path, manual = interactive(fixable, apply_all=args.apply)
        for it, r in manual:
            print(f"\nmanual edit needed at {it.path}:{it.line}: {it.raw} -> {r.suggest or r.raise_floor} (literal can't be auto-edited)")
        if by_path:
            print()
            write_changes(by_path, assume_yes=args.apply)
        else:
            print("\nno changes chosen")
    elif fixable:
        print(f"\n{len(fixable)} fix(es) proposed. Re-run with -i to review and apply them, or --apply to accept all.")
    return code
