"""Condition coverage: every in-line decision in ``xgfalclient`` taken both ways.

Branch coverage sees a line as one decision. It cannot tell whether the
right-hand side of ``a or b`` was ever reached, which arm of ``x if c else y``
ran, or whether a comprehension's ``if`` ever threw anything away. With
``XGFAL_CONDCOV=1`` in the environment, the test run rewrites every module of
the package as it is imported, wrapping each such decision in a probe, and
fails unless every probe saw both a true and a false value:

* each operand of ``and``/``or`` that decides whether evaluation goes on -
  every operand but the last, and the last too when the whole expression is
  itself a condition (an ``if``, ``while``, ``not``, ternary or filter);
* the test of a conditional expression;
* each ``if`` of a comprehension.

``if``/``while`` statements, loops and ``match`` are branch coverage's job and
are left alone. Run it on its own, not under ``--cov``: the rewritten code is
not the code coverage.py maps back to lines.
"""

from __future__ import annotations

import ast
import importlib.abc
import importlib.machinery
import os
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from types import CodeType
from typing import Any

import pytest

PACKAGE = "xgfalclient"
PROBE = "__condcov__"
ENABLED = bool(os.environ.get("XGFAL_CONDCOV"))
OUTCOMES = ((1, "true"), (0, "false"))


@dataclass(frozen=True)
class Site:
    line: int
    col: int
    kind: str
    text: str


class Instrumenter(ast.NodeTransformer):
    """Wraps every decision in ``__condcov__(site, value)``; ``sites`` lists them in order."""

    def __init__(self, source: str) -> None:
        self.source = source
        self.sites: list[Site] = []

    def probe(self, node: ast.expr, kind: str) -> ast.expr:
        text = ast.get_source_segment(self.source, node) or ast.dump(node)
        self.sites.append(Site(node.lineno, node.col_offset, kind, " ".join(text.split())))
        call = ast.Call(
            func=ast.Name(id=PROBE, ctx=ast.Load()),
            args=[ast.Constant(len(self.sites) - 1), node],
            keywords=[],
        )
        return ast.copy_location(call, node)

    def condition(self, node: ast.expr, kind: str) -> ast.expr:
        """A test whose outcome picks a path: its operands if it is a BoolOp, else itself."""
        if isinstance(node, ast.BoolOp):
            return self.boolop(node, tested=True)
        node = self.visit(node)
        return node if isinstance(node, ast.Constant) else self.probe(node, kind)

    def boolop(self, node: ast.BoolOp, tested: bool) -> ast.expr:
        values = []
        for index, value in enumerate(node.values):
            decides = tested or index < len(node.values) - 1
            if isinstance(value, ast.BoolOp):
                value = self.boolop(value, decides)
            else:
                value = self.visit(value)
            if decides and not isinstance(value, ast.Constant):
                value = self.probe(value, "operand")
            values.append(value)
        node.values = values
        return node

    # -- where a BoolOp is itself a condition ---------------------------------------

    def _test(self, node: Any) -> Any:
        if isinstance(node.test, ast.BoolOp):
            node.test = self.boolop(node.test, tested=True)
        else:
            node.test = self.visit(node.test)
        for field in ("body", "orelse"):
            setattr(node, field, [self.visit(child) for child in getattr(node, field)])
        return node

    visit_If = _test
    visit_While = _test

    def visit_UnaryOp(self, node: ast.UnaryOp) -> ast.expr:
        if isinstance(node.op, ast.Not) and isinstance(node.operand, ast.BoolOp):
            node.operand = self.boolop(node.operand, tested=True)
            return node
        return self.generic_visit(node)  # type: ignore[return-value]

    def visit_BoolOp(self, node: ast.BoolOp) -> ast.expr:
        return self.boolop(node, tested=False)

    def visit_IfExp(self, node: ast.IfExp) -> ast.expr:
        node.test = self.condition(node.test, "ternary")
        node.body = self.visit(node.body)
        node.orelse = self.visit(node.orelse)
        return node

    def visit_comprehension(self, node: ast.comprehension) -> ast.comprehension:
        node.target = self.visit(node.target)
        node.iter = self.visit(node.iter)
        node.ifs = [self.condition(test, "filter") for test in node.ifs]
        return node


def instrument(source: str, filename: str) -> tuple[ast.Module, list[Site]]:
    tree = ast.parse(source, filename)
    instrumenter = Instrumenter(source)
    tree = ast.fix_missing_locations(instrumenter.visit(tree))
    return tree, instrumenter.sites


# -- the import hook ------------------------------------------------------------------

#: Relative path of each instrumented module -> the set of ``site * 2 + outcome`` seen.
HITS: dict[str, set[int]] = {}


def probe_for(module: str) -> Any:
    """The probe a rewritten module calls; it binds it to itself on import."""
    seen = HITS.setdefault(module, set())

    def probe(site: int, value: Any) -> Any:
        seen.add(site * 2 + (1 if value else 0))
        return value

    return probe


class _Loader(importlib.machinery.SourceFileLoader):
    """Compiles from the rewritten tree, and never writes it to ``__pycache__``.

    The module binds its own probe (rather than the loader planting one) so
    that code run without ``exec_module``, as ``runpy`` does, still works.
    """

    def get_code(self, fullname: str) -> CodeType:
        path = self.get_filename(fullname)
        source = self.get_data(path).decode("utf-8")
        tree, _ = instrument(source, path)
        bind = ast.parse(f"{PROBE} = __import__('condcov').probe_for({_relative(path)!r})").body
        start = _after_preamble(tree.body)
        tree.body[start:start] = bind
        return compile(ast.fix_missing_locations(tree), path, "exec", dont_inherit=True)


def _after_preamble(body: list[ast.stmt]) -> int:
    """Where statements may go: after the docstring and any ``__future__`` imports."""
    start = 0
    for index, statement in enumerate(body):
        docstring = index == 0 and isinstance(statement, ast.Expr)
        future = isinstance(statement, ast.ImportFrom) and statement.module == "__future__"
        if not (docstring or future):
            break
        start = index + 1
    return start


class _Finder(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname: str, path: Sequence[str] | None, target: Any = None) -> Any:
        if fullname != PACKAGE and not fullname.startswith(PACKAGE + "."):
            return None
        spec = importlib.machinery.PathFinder.find_spec(fullname, path)
        if spec is None or not isinstance(spec.loader, importlib.machinery.SourceFileLoader):
            return spec
        spec.loader = _Loader(fullname, spec.loader.path)
        return spec


def _root() -> Path:
    spec = importlib.machinery.PathFinder.find_spec(PACKAGE)
    assert spec is not None and spec.submodule_search_locations
    return Path(next(iter(spec.submodule_search_locations)))


def _relative(path: str) -> str:
    return Path(path).relative_to(_root().parent).as_posix()


def install() -> None:
    """Instrument ``xgfalclient``; must run before anything imports it."""
    already = [name for name in sys.modules if name.split(".")[0] == PACKAGE]
    if already:
        raise RuntimeError(f"condcov: {PACKAGE} was imported before instrumentation")
    sys.meta_path.insert(0, _Finder())


# -- reporting ------------------------------------------------------------------------


def missing(hits: dict[str, set[int]]) -> tuple[list[tuple[str, Site, str]], int]:
    """Every probe short of an outcome, over every module of the package; and the probe count."""
    root = _root()
    gaps = []
    total = 0
    for path in sorted(root.rglob("*.py")):
        relative = path.relative_to(root.parent).as_posix()
        _, sites = instrument(path.read_text("utf-8"), str(path))
        total += len(sites)
        seen = hits.get(relative, set())
        for index, site in enumerate(sites):
            lacking = [f"never {name}" for bit, name in OUTCOMES if index * 2 + bit not in seen]
            if lacking:
                gaps.append((relative, site, " or ".join(lacking)))
    return gaps, total


class Plugin:
    def __init__(self, config: pytest.Config) -> None:
        self.config = config
        self.hits: dict[str, set[int]] = {}

    def _merge(self, hits: dict[str, Sequence[int]]) -> None:
        for module, seen in hits.items():
            self.hits.setdefault(module, set()).update(seen)

    @pytest.hookimpl(optionalhook=True)
    def pytest_testnodedown(self, node: Any, error: Any) -> None:
        self._merge(getattr(node, "workeroutput", {}).get("condcov", {}))

    def pytest_sessionfinish(self, session: pytest.Session) -> None:
        workeroutput = getattr(self.config, "workeroutput", None)
        if workeroutput is not None:
            workeroutput["condcov"] = {module: sorted(seen) for module, seen in HITS.items()}
            return
        self._merge({module: sorted(seen) for module, seen in HITS.items()})
        gaps, total = missing(self.hits)
        reporter = self.config.pluginmanager.get_plugin("terminalreporter")
        if reporter is not None:
            reporter.write_sep("=", "condition coverage")
            for module, site, lacking in gaps:
                where = f"{module}:{site.line}:{site.col + 1}"
                reporter.write_line(f"{where}: {site.kind} {lacking}: {site.text}")
            reporter.write_line(f"{total - len(gaps)}/{total} decisions taken both ways")
        if gaps and session.exitstatus == 0:
            session.exitstatus = pytest.ExitCode.TESTS_FAILED
