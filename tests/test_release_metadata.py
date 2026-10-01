"""Release metadata stays connected to the public runtime version."""

from pathlib import Path

import xgfalclient

ROOT = Path(__file__).parents[1]


def test_version_has_one_build_source_and_release_notes() -> None:
    project = (ROOT / "pyproject.toml").read_text()
    changelog = (ROOT / "CHANGELOG.md").read_text()

    assert 'dynamic = ["version"]' in project
    assert 'path = "src/xgfalclient/_version.py"' in project
    assert f"## [{xgfalclient.VERSION}]" in changelog
    assert xgfalclient.__version__ == xgfalclient.VERSION
    assert xgfalclient.VERSION.count(".") == 2
