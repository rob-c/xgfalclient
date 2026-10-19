"""What a cold start imports: the choices xgfalclient makes about its own imports.

``import gfal2`` and every ``gfal-*`` command used to pay about half a second
before doing anything, almost all of it for modules they never used: the core
copy module imported xrdclient's copy pipeline (and with it the whole of an
eager xrdclient), and the HTTP plugin imported botocore for ``s3://`` and the
X.509 stack for delegation whatever the URL. Each scenario here runs in a
fresh interpreter - this process has long since imported everything - and
lists what it loaded.

Two kinds of assertion, kept apart:

* xgfalclient's own choices - no HTTP plugin for a ``--help`` or a
  ``file://`` URL, no botocore for ``davs://``, no xrdclient or library
  module at all for ``import gfal2`` - hold whatever the libraries do, and
  must pass.
* What the ``gfal-*`` commands cost beyond that: since 0.4.0 they import
  xrdcore's small report module (:mod:`xrdcore.report`, formerly
  ``xrdclient.cli._output``) and nothing of xrdclient, xrdsec or xrdhttp -
  no client, session or copy engine, no X.509 stack - until a URL needs a
  plugin that uses them.
"""

from __future__ import annotations

import json
import subprocess
import sys
from functools import cache
from pathlib import Path

import pytest

#: Prints, as JSON, every module the scenario passed in ``argv[1]`` loaded.
_PROBE = """
import contextlib, io, json, sys
scenario = sys.argv[1]
if scenario == "gfal2":
    import gfal2
elif scenario == "cli":
    import xgfalclient.cli
elif scenario.startswith("gfal-"):
    from xgfalclient import cli
    sys.argv = [scenario, *sys.argv[2:]]
    with contextlib.redirect_stdout(io.StringIO()), contextlib.suppress(SystemExit):
        getattr(cli, scenario[len("gfal-"):])()
elif scenario == "davs":
    import xgfalclient
    with xgfalclient.creat_context() as context, contextlib.suppress(Exception):
        context.stat("davs://127.0.0.1:1/f")
sys.stderr.write(json.dumps(sorted(sys.modules)))
"""

#: The HTTP plugin and the expensive libraries only it needs.
HTTP_STACK = ("xgfalclient.plugins.http", "urllib3", "botocore")
#: The XRootD plugin (and the xrdclient client it drives).
XROOTD_PLUGIN = ("xgfalclient.plugins.xrootd",)
#: The client and the libraries a command must not pay for before a URL needs them.
CLIENT_AND_LIBRARIES = ("xrdclient", "xrdsec", "xrdhttp")
#: What a context's credential search may load (it runs when a context is
#: made, as gfal2's does): the search itself, but never TLS or X.509.
CREDENTIAL_SEARCH = ("xrdsec", "xrdsec._version", "xrdsec.credentials", "xrdsec.discovery")
X509_STACK = ("cryptography.x509",)


@cache
def _loaded(scenario: str, *args: str) -> frozenset[str]:
    """The modules a fresh interpreter has after running ``scenario``."""
    # Without -I: the test run's PYTHONPATH must reach the child, so that it
    # imports the tree under test rather than whatever else is installed.
    done = subprocess.run(
        [sys.executable, "-c", _PROBE, scenario, *args],
        capture_output=True,
        text=True,
        timeout=120,
        check=True,
    )
    return frozenset(json.loads(done.stderr.strip().splitlines()[-1]))


def _imported(modules: frozenset[str], prefixes: tuple[str, ...]) -> list[str]:
    """The members of ``modules`` that are, or are inside, any of ``prefixes``."""
    return sorted(m for m in modules if any(m == p or m.startswith(p + ".") for p in prefixes))


@pytest.fixture(scope="module")
def stat_target(tmp_path_factory: pytest.TempPathFactory) -> str:
    target = tmp_path_factory.mktemp("import-cost") / "f"
    target.write_bytes(b"x")
    return target.as_uri()


def test_import_gfal2_imports_no_xrdclient_no_library_and_no_plugin() -> None:
    modules = _loaded("gfal2")
    assert _imported(modules, (*CLIENT_AND_LIBRARIES, "xrdcore")) == []
    assert _imported(modules, (*HTTP_STACK, *XROOTD_PLUGIN, *X509_STACK)) == []
    assert _imported(modules, ("xgfalclient.plugins.file",)) == []


@pytest.mark.parametrize("scenario", ["cli", "gfal-ls --help", "gfal-stat"])
def test_commands_import_no_protocol_plugin_they_do_not_use(
    scenario: str, stat_target: str
) -> None:
    modules = _commands(scenario, stat_target)
    assert _imported(modules, (*HTTP_STACK, *XROOTD_PLUGIN)) == []


@pytest.mark.parametrize("scenario", ["cli", "gfal-ls --help", "gfal-stat"])
def test_commands_import_only_the_report_module(scenario: str, stat_target: str) -> None:
    modules = _commands(scenario, stat_target)
    loaded = _imported(modules, (*CLIENT_AND_LIBRARIES, *X509_STACK, "ssl"))
    assert [name for name in loaded if name not in CREDENTIAL_SEARCH] == []
    assert "xrdcore.report" in modules
    # The core streamed copy imports the shared pipeline only when a copy streams.
    assert "xrdcore.pipeline" not in modules


def _commands(scenario: str, stat_target: str) -> frozenset[str]:
    if scenario == "gfal-stat":
        return _loaded("gfal-stat", stat_target)
    return _loaded(*scenario.split())


def test_a_webdav_url_imports_neither_s3_nor_gcs_nor_delegation() -> None:
    modules = _loaded("davs")
    assert "xgfalclient.plugins.http.plugin" in modules  # the scenario did reach it
    lazy = ("_s3", "_gcloud", "_delegation")
    assert _imported(modules, ("botocore", *(f"xgfalclient.plugins.http.{m}" for m in lazy))) == []
    assert _imported(modules, XROOTD_PLUGIN) == []


def test_the_http_plugins_object_store_schemes_agree_with_their_modules() -> None:
    from xgfalclient.plugins.http import _gcloud, _s3, plugin
    from xgfalclient.url import parse

    for scheme in plugin.HTTPPlugin.schemes:
        base = scheme.partition("+")[0]
        assert (base in plugin.S3_SCHEMES) == _s3.is_s3(parse(f"{scheme}://h/b/k"))
        assert (base in plugin.GCLOUD_SCHEMES) == _gcloud.is_gcloud(scheme)


def test_probe_is_this_tree() -> None:
    """The child imports the xgfalclient under test, not some other installation."""
    import xgfalclient

    here = Path(xgfalclient.__file__).resolve()
    child = subprocess.run(
        [sys.executable, "-c", "import xgfalclient; print(xgfalclient.__file__)"],
        capture_output=True,
        text=True,
        timeout=60,
        check=True,
    )
    assert Path(child.stdout.strip()).resolve() == here
