"""The condition-coverage instrumenter: which decisions it probes, and that it changes nothing."""

from __future__ import annotations

from typing import Any

import pytest

from condcov import _after_preamble, instrument


def sites(source: str) -> list[tuple[str, str]]:
    return [(site.kind, site.text) for site in instrument(source, "<test>")[1]]


def run(source: str, **names: Any) -> tuple[dict[str, Any], set[int]]:
    """Execute instrumented ``source``; its namespace and the ``site * 2 + outcome`` seen."""
    tree, _ = instrument(source, "<test>")
    seen: set[int] = set()

    def probe(site: int, value: Any) -> Any:
        seen.add(site * 2 + (1 if value else 0))
        return value

    namespace = {"__condcov__": probe, **names}
    exec(compile(tree, "<test>", "exec"), namespace)
    return namespace, seen


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        # A value: the last operand decides nothing.
        ("x = a or b", [("operand", "a")]),
        ("x = a and b and c", [("operand", "a"), ("operand", "b")]),
        # A condition: every operand does.
        ("if a or b:\n    pass", [("operand", "a"), ("operand", "b")]),
        ("while a and b:\n    pass", [("operand", "a"), ("operand", "b")]),
        ("x = not (a or b)", [("operand", "a"), ("operand", "b")]),
        # Nested: the inner BoolOp is itself an operand that decides.
        (
            "x = (a or b) and c",
            [("operand", "a"), ("operand", "b"), ("operand", "a or b")],
        ),
        ("x = c and (a or b)", [("operand", "c"), ("operand", "a")]),
        # Ternaries and filters, plain and compound.
        ("x = 1 if c else 2", [("ternary", "c")]),
        ("x = 1 if a or b else 2", [("operand", "a"), ("operand", "b")]),
        ("x = [v for v in w if v > 0]", [("filter", "v > 0")]),
        # Constants cannot go both ways, so they are not probed.
        ("x = a or True or b", [("operand", "a")]),
        ("x = 1 if True else 2", []),
        # Statements branch coverage already sees.
        ("if c:\n    pass", []),
        ("assert c", []),
    ],
)
def test_sites(source: str, expected: list[tuple[str, str]]) -> None:
    assert sites(source) == expected


def test_short_circuit_is_preserved() -> None:
    def boom() -> bool:
        raise AssertionError("evaluated")

    namespace, seen = run("x = a or boom()\ny = b and boom()", a=1, b=0, boom=boom)
    assert (namespace["x"], namespace["y"]) == (1, 0)
    assert seen == {0 * 2 + 1, 1 * 2 + 0}


def test_values_pass_through_unchanged() -> None:
    namespace, seen = run(
        "x = [v for v in w if v % 2]\ny = 'odd' if x else 'none'\nz = p or q",
        w=[1, 2, 3],
        p="",
        q="fallback",
    )
    assert namespace["x"] == [1, 3]
    assert namespace["y"] == "odd"
    assert namespace["z"] == "fallback"
    assert seen == {0, 1, 3, 4}


def test_probe_goes_after_docstring_and_future_imports() -> None:
    tree, _ = instrument('"""Doc."""\nfrom __future__ import annotations\nimport os\n', "<t>")
    assert _after_preamble(tree.body) == 2
    tree, _ = instrument("import os\n", "<t>")
    assert _after_preamble(tree.body) == 0
