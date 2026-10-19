"""xgfalclient's distribution checks are xrd-devtools' shared ones, run on this candidate."""

from pathlib import Path

ROOT = Path(__file__).parents[1]
DEVTOOLS = "rob-c/xrd-devtools/.github"


def test_distribution_workflow_checks_this_candidate_with_the_shared_matrix() -> None:
    workflow = (ROOT / ".github/workflows/platforms.yml").read_text()
    assert f"uses: {DEVTOOLS}/workflows/platforms.yml@main" in workflow
    assert "xgfalclient-ref: ${{ github.sha }}" in workflow
    assert "xrdclient-ref: ${{ inputs.xrdclient-ref || 'main' }}" in workflow


def test_ci_runs_the_shared_gates_and_every_job_uses_the_one_candidates_action() -> None:
    ci = (ROOT / ".github/workflows/ci.yml").read_text()
    for workflow in ("static", "tests", "chain"):
        assert f"uses: {DEVTOOLS}/workflows/{workflow}.yml@main" in ci
    assert ci.count("\n    runs-on:") == ci.count(f"uses: {DEVTOOLS}/actions/candidates@main")


def test_nix_package_uses_the_same_implementation() -> None:
    recipe = (ROOT / "packaging/default.nix").read_text()
    assert 'devtoolsSrc + "/packaging/nix"' in recipe
    assert "xgfalclientSrc = ../.;" in recipe


def test_publish_checks_xrdclient_and_the_libraries_are_on_pypi_first() -> None:
    """The shared publish action runs the PyPI pre-flight before it stages the artifacts."""
    publish = (ROOT / ".github/workflows/publish.yml").read_text()
    build = publish[publish.index(f"uses: {DEVTOOLS}/actions/publish@main") :]
    assert "package: xgfalclient\n" in build and "preflight: true\n" in build
    assert publish.index("preflight: true") < publish.index("pypa/gh-action-pypi-publish")
    # The compatibility packages ride in the same wheel and must survive installing it.
    assert "import gfal2, gfal2_util" in build
