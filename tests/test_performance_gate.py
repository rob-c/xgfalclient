from __future__ import annotations

import pytest
from benchmarks.bench_vs_gfal2 import parse_args, selection, sign_test, verdict


def test_sign_test_is_one_sided() -> None:
    assert sign_test(5, 5) == 0.03125
    assert sign_test(4, 5) == 0.1875


def test_verdict_requires_effect_size_and_reliability() -> None:
    decisive = {"xgfalclient": [20.0] * 5, "gfal2": [10.0] * 5}
    outcome = verdict(decisive, minimum_ratio=1.1, alpha=0.05)
    assert outcome == {"passed": True, "ratio": 2.0, "wins": 5, "rounds": 5, "p": 0.03125}

    too_small = {"xgfalclient": [10.5] * 5, "gfal2": [10.0] * 5}
    assert verdict(too_small, minimum_ratio=1.1, alpha=0.05)["passed"] is False

    noisy = {"xgfalclient": [20.0, 20.0, 20.0, 5.0, 5.0], "gfal2": [10.0] * 5}
    assert verdict(noisy, minimum_ratio=1.1, alpha=0.05)["passed"] is False


@pytest.mark.parametrize(
    ("argument", "message"),
    [
        ("--repeat=0", "--repeat must be positive"),
        ("--min-ratio=1", "--min-ratio must be greater than 1"),
        ("--alpha=1", "--alpha must be between 0 and 1"),
    ],
)
def test_invalid_gate_parameters_are_rejected(
    argument: str, message: str, capsys: pytest.CaptureFixture[str]
) -> None:
    parser, args = parse_args(["--base=davs://example.test/bench", argument])
    with pytest.raises(SystemExit, match="2"):
        selection(parser, args)
    assert message in capsys.readouterr().err
