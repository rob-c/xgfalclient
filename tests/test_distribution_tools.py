"""The facade delegates distribution validation to the shared-core workflow."""

from pathlib import Path

ROOT = Path(__file__).parents[1]


def test_distribution_workflow_checks_this_candidate_with_the_shared_core():
    workflow = (ROOT / ".github/workflows/platforms.yml").read_text()
    assert "uses: rob-c/xrdclient/.github/workflows/platforms.yml@main" in workflow
    assert "xgfalclient-ref: ${{ github.sha }}" in workflow
    assert "xrdclient-ref: ${{ inputs.xrdclient-ref || 'main' }}" in workflow


def test_nix_package_uses_the_same_implementation():
    recipe = (ROOT / "packaging/default.nix").read_text()
    assert 'xrdclientSrc + "/packaging/nix"' in recipe
    assert "xgfalclientSrc = ../.;" in recipe
