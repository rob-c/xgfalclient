"""Release metadata stays connected to the public runtime version."""

from pathlib import Path

import xgfalclient

ROOT = Path(__file__).parents[1]


def test_version_has_one_build_source_and_release_notes() -> None:
    project = (ROOT / "pyproject.toml").read_text()
    changelog = (ROOT / "CHANGELOG.md").read_text()

    assert 'dynamic = ["version"]' in project
    assert 'path = "src/xgfalclient/_version.py"' in project
    headings = [line for line in changelog.splitlines() if line.startswith("## [")]
    assert headings[0].startswith(f"## [{xgfalclient.VERSION}] - ")
    assert sum(line.startswith(f"## [{xgfalclient.VERSION}]") for line in headings) == 1
    assert f"[{xgfalclient.VERSION}]: https://github.com/rob-c/xgfalclient/compare/" in changelog
    assert "## [0.2.0] - 2026-10-01" in headings
    assert xgfalclient.__version__ == xgfalclient.VERSION
    assert xgfalclient.VERSION.count(".") == 2


def test_generated_documentation_is_excluded_from_source_distributions() -> None:
    assert "site/" in (ROOT / ".gitignore").read_text().splitlines()
