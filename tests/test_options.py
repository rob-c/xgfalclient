"""The key-file configuration: gfal2's defaults, accessors and GLib error codes."""

from __future__ import annotations

import errno
import logging
import os
from pathlib import Path

import pytest

import xgfalclient
from xgfalclient import GError
from xgfalclient import options as options_module
from xgfalclient.options import (
    GROUP_NOT_FOUND,
    INVALID_VALUE,
    KEY_NOT_FOUND,
    PARSE_ERROR,
    Options,
    parse_ini,
)


@pytest.fixture
def options() -> Options:
    return Options()


def test_stock_defaults(options: Options) -> None:
    assert options.get_integer("CORE", "NAMESPACE_TIMEOUT") == 300
    assert options.get_string("CORE", "NAMESPACE_TIMEOUT") == "300"
    assert options.get_boolean("HTTP PLUGIN", "INSECURE") is False
    assert options.get_string("HTTP PLUGIN", "DEFAULT_COPY_MODE") == "3rd pull"
    assert options.get_string_list("SRM PLUGIN", "TURL_PROTOCOLS") == [
        "gsiftp",
        "rfio",
        "gsidcap",
        "dcap",
        "kdcap",
    ]
    assert "GRIDFTP PLUGIN" in options.groups()
    assert "DCAU" in options.keys("GRIDFTP PLUGIN")


def test_missing_group_and_key_codes(options: Options) -> None:
    with pytest.raises(GError) as caught:
        options.get_string("NOPE", "NOPE")
    assert caught.value.code == GROUP_NOT_FOUND
    assert caught.value.message == "Key file does not have group “NOPE”"
    with pytest.raises(GError) as caught:
        options.get_string("CORE", "NOPE")
    assert caught.value.code == KEY_NOT_FOUND
    assert caught.value.message == "Key file does not have key “NOPE” in group “CORE”"
    with pytest.raises(GError):
        options.keys("NOPE")


def test_invalid_values(options: Options) -> None:
    with pytest.raises(GError) as caught:
        options.get_integer("HTTP PLUGIN", "DEFAULT_COPY_MODE")
    assert caught.value.code == INVALID_VALUE
    assert "in group “HTTP PLUGIN”" in caught.value.message
    with pytest.raises(GError) as caught:
        options.get_boolean("HTTP PLUGIN", "DEFAULT_COPY_MODE")
    assert caught.value.code == INVALID_VALUE
    assert caught.value.message == (
        "Key file contains key “DEFAULT_COPY_MODE” which has a value that cannot be interpreted."
    )


@pytest.mark.parametrize(
    ("raw", "value"), [("true", True), ("1", True), ("false \t", False), ("0", False)]
)
def test_booleans(options: Options, raw: str, value: bool) -> None:
    options.set_string("X", "B", raw)
    assert options.get_boolean("X", "B") is value


@pytest.mark.parametrize("raw", ["TRUE", "False", " true", "yes", ""])
def test_booleans_are_case_sensitive_as_in_glib(options: Options, raw: str) -> None:
    options.set_string("X", "B", raw)
    with pytest.raises(GError) as caught:
        options.get_boolean("X", "B")
    assert caught.value.code == INVALID_VALUE


@pytest.mark.parametrize(
    ("raw", "value"), [("12", 12), ("+12", 12), (" -7", -7), ("2147483647", 2**31 - 1)]
)
def test_integers(options: Options, raw: str, value: int) -> None:
    options.set_string("X", "I", raw)
    assert options.get_integer("X", "I") == value


@pytest.mark.parametrize(
    "raw", [" 12 ", "1_000", "0x10", "99999999999", "-2147483649", "١٢", "", "12\n"]
)
def test_integers_follow_glib_strictly(options: Options, raw: str) -> None:
    options.set_string("X", "I", raw)
    with pytest.raises(GError) as caught:
        options.get_integer("X", "I")
    assert caught.value.code == INVALID_VALUE


def test_setters_round_trip_as_glib_does(options: Options) -> None:
    options.set_boolean("X", "B", True)
    assert options.get_string("X", "B") == "true"
    options.set_boolean("X", "B", False)
    assert options.get_string("X", "B") == "false"
    options.set_integer("X", "I", 7)
    assert options.get_string("X", "I") == "7"
    options.set_string_list("X", "L", ["a", "b"])
    assert options.get_string("X", "L") == "a;b;"
    assert options.get_string_list("X", "L") == ["a", "b"]
    options.set_string("X", "S", "a;b, c")
    assert options.get_string_list("X", "S") == ["a", "b, c"]
    options.set_string("X", "E", "")
    assert options.get_string_list("X", "E") == []


def test_remove(options: Options) -> None:
    assert options.remove("CORE", "NAMESPACE_TIMEOUT") is True
    assert not options.has("CORE", "NAMESPACE_TIMEOUT")
    with pytest.raises(GError) as caught:
        options.remove("CORE", "NAMESPACE_TIMEOUT")
    assert caught.value.code == KEY_NOT_FOUND


def test_defaulted_reads_never_raise(options: Options) -> None:
    assert options.string("NOPE", "K", "d") == "d"
    assert options.integer("NOPE", "K", 3) == 3
    assert options.boolean("NOPE", "K", True) is True
    assert options.string_list("NOPE", "K", ["x"]) == ["x"]
    assert options.string_list("NOPE", "K") == []
    assert options.string("CORE", "NAMESPACE_TIMEOUT") == "300"
    assert options.integer("CORE", "NAMESPACE_TIMEOUT") == 300
    assert options.boolean("HTTP PLUGIN", "KEEP_ALIVE") is True
    assert options.string_list("SRM PLUGIN", "TURL_3RD_PARTY_PROTOCOLS")[0] == "gsiftp"


def test_timeout_prefers_the_plugin_group(options: Options) -> None:
    assert options.timeout("HTTP PLUGIN") == 300
    options.set_integer("HTTP PLUGIN", "OPERATION_TIMEOUT", 12)
    assert options.timeout("HTTP PLUGIN") == 12
    options.set_integer("CORE", "NAMESPACE_TIMEOUT", 9)
    assert options.timeout("SRM PLUGIN") == 9


def test_parse_ini_grammar() -> None:
    text = "# comment\n\n[A]\nk = v ; w\n[ B ]\nx=\n[C]\n"
    assert parse_ini(text) == {"A": {"k": "v ; w"}, "B": {"x": ""}, "C": {}}
    for bad in ("[A]\nnot a key\n", "[A]\n=v\n", "[A]\n[unclosed\n"):
        with pytest.raises(GError) as caught:
            parse_ini(bad, "f.conf")
        line = bad.split("\n")[1]
        assert caught.value.args == (
            f"Key file contains line “{line}” which is not a key-value pair, group, or comment",
            PARSE_ERROR,
        )
    with pytest.raises(GError) as caught:
        parse_ini("k=v\n[A]\n")
    assert caught.value.args == ("Key file does not start with a group", GROUP_NOT_FOUND)


def test_load_file_and_errors(tmp_path: Path, options: Options) -> None:
    conf = tmp_path / "extra.conf"
    conf.write_text("[HTTP PLUGIN]\nINSECURE=true\n[NEW]\nK=1\n")
    options.load_file(str(conf))
    assert options.get_boolean("HTTP PLUGIN", "INSECURE") is True
    assert options.get_integer("NEW", "K") == 1
    missing = tmp_path / "missing.conf"
    with pytest.raises(GError) as caught:
        options.load_file(str(missing))
    assert caught.value.args == (
        f"Error while loading configuration file {missing}: No such file or directory",
        4,  # G_FILE_ERROR_NOENT
    )
    for irregular in (tmp_path, Path(os.devnull)):
        with pytest.raises(GError) as caught:
            options.load_file(str(irregular))
        assert caught.value.args == (
            f"Error while loading configuration file {irregular}: Not a regular file",
            PARSE_ERROR,
        )
    bad = tmp_path / "bad.conf"
    bad.write_text("[OK]\nK=1\n[G]\ngarbage\n")
    with pytest.raises(GError) as caught:
        options.load_file(str(bad))
    assert caught.value.code == PARSE_ERROR
    assert caught.value.message.startswith(f"Error while loading configuration file {bad}: Key")
    assert "OK" not in options.groups()  # all or nothing


def test_a_group_without_keys_is_not_created(tmp_path: Path, options: Options) -> None:
    conf = tmp_path / "x509.conf"
    conf.write_text("[X509]\n# CERT=/path\n")
    options.load_file(str(conf))
    with pytest.raises(GError) as caught:
        options.get_string("X509", "CERT")
    assert caught.value.code == GROUP_NOT_FOUND


@pytest.mark.parametrize(
    ("error", "expected"),
    [
        (OSError("no errno here"), ("no errno here", 24)),
        (OSError(errno.EACCES, "denied"), ("Permission denied", 2)),
        (OSError(errno.ECONNRESET, "odd"), (os.strerror(errno.ECONNRESET), 24)),
    ],
)
def test_load_file_open_failures(
    monkeypatch: pytest.MonkeyPatch, options: Options, error: OSError, expected: tuple[str, int]
) -> None:
    def refuse(*args: object, **kwargs: object) -> None:
        raise error

    monkeypatch.setattr(options_module, "open", refuse, raising=False)
    with pytest.raises(GError) as caught:
        options.load_file("/anywhere.conf")
    message, code = expected
    assert caught.value.args == (
        f"Error while loading configuration file /anywhere.conf: {message}",
        code,
    )


def test_system_files_follow_gfal_config_dir(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    (tmp_path / "b.conf").write_text("[CORE]\nNAMESPACE_TIMEOUT=5\n")
    (tmp_path / "a.conf").write_text("[CORE]\nNAMESPACE_TIMEOUT=4\n")
    (tmp_path / "ignored.txt").write_text("[CORE]\nNAMESPACE_TIMEOUT=1\n")
    (tmp_path / "x.conf.conf").write_text("[CORE]\nNAMESPACE_TIMEOUT=1\n")
    env = {"GFAL_CONFIG_DIR": str(tmp_path)}
    # gfal2 reads them in the directory's order, not sorted.
    order = [name for name in os.listdir(tmp_path) if name in ("a.conf", "b.conf")]
    assert Options.system_files(env) == [f"{tmp_path}/{name}" for name in order]
    monkeypatch.setattr(options_module, "DEFAULT_CONFIG_DIR", str(tmp_path) + "/")
    assert Options.system_files({}) == [f"{tmp_path}//{name}" for name in order]
    assert Options.system_files({"GFAL_CONFIG_DIR": str(tmp_path / "missing")}) == []
    # Announced in gfal2's words.
    xgfalclient.set_verbose(xgfalclient.verbose_level.debug)
    try:
        with caplog.at_level(logging.DEBUG, logger="gfal2"):
            Options.system_files(env, announce=True)
            Options.system_files({}, announce=True)
            monkeypatch.setenv("GFAL_CONFIG_DIR", str(tmp_path))
            Options()
    finally:
        xgfalclient.set_verbose(xgfalclient.verbose_level.verbose)
    assert [r.getMessage() for r in caplog.records] == [
        f" GFAL_CONFIG_DIR env var found, try to load configuration from {tmp_path}",
        " no GFAL_CONFIG_DIR env var found, try to load configuration from default "
        f"directory {tmp_path}/",
        f" GFAL_CONFIG_DIR env var found, try to load configuration from {tmp_path}",
        *(f" try to load configuration file {tmp_path}/{name} ..." for name in order),
    ]


@pytest.mark.parametrize(
    ("name", "wanted"),
    [("a.conf", True), (".conf", True), ("a.conf.conf", False), ("a.confx", False), ("a", False)],
)
def test_config_names_as_gfal2_matches_them(name: str, wanted: bool) -> None:
    assert options_module.is_config_name(name) is wanted


def test_system_configuration_is_layered(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    (tmp_path / "core.conf").write_text("[CORE]\nNAMESPACE_TIMEOUT=77\n")
    monkeypatch.setenv("GFAL_CONFIG_DIR", str(tmp_path))
    assert Options().get_integer("CORE", "NAMESPACE_TIMEOUT") == 77
    assert Options(load_system=False).get_integer("CORE", "NAMESPACE_TIMEOUT") == 300


def test_snapshot_is_a_copy(options: Options) -> None:
    snapshot = options.snapshot()
    snapshot["CORE"]["NAMESPACE_TIMEOUT"] = "1"
    assert options.get_integer("CORE", "NAMESPACE_TIMEOUT") == 300
