"""The key-file configuration: gfal2's defaults, accessors and GLib error codes."""

from __future__ import annotations

from pathlib import Path

import pytest

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
    ("raw", "value"), [("true", True), ("1", True), ("FALSE", False), ("0", False)]
)
def test_booleans(options: Options, raw: str, value: bool) -> None:
    options.set_string("X", "B", raw)
    assert options.get_boolean("X", "B") is value


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
    text = "# comment\n\n[A]\nk = v ; w\n[ B ]\nx=\n"
    assert parse_ini(text) == {"A": {"k": "v ; w"}, "B": {"x": ""}}
    for bad in ("k=v\n", "[A]\nnot a key\n", "[A]\n=v\n", "[A]\n[unclosed\n"):
        with pytest.raises(GError) as caught:
            parse_ini(bad, "f.conf")
        assert caught.value.code == PARSE_ERROR
        assert "f.conf" in caught.value.message


def test_load_file_and_errors(tmp_path: Path, options: Options) -> None:
    conf = tmp_path / "extra.conf"
    conf.write_text("[HTTP PLUGIN]\nINSECURE=true\n[NEW]\nK=1\n")
    options.load_file(str(conf))
    assert options.get_boolean("HTTP PLUGIN", "INSECURE") is True
    assert options.get_integer("NEW", "K") == 1
    with pytest.raises(GError) as caught:
        options.load_file(str(tmp_path / "missing.conf"))
    assert caught.value.code == 2
    assert "missing.conf" in caught.value.message


def test_load_file_error_without_errno(monkeypatch: pytest.MonkeyPatch, options: Options) -> None:
    def refuse(*args: object, **kwargs: object) -> None:
        raise OSError("no errno here")

    monkeypatch.setattr(options_module, "open", refuse, raising=False)
    with pytest.raises(GError) as caught:
        options.load_file("/anywhere.conf")
    assert caught.value.code == 0


def test_system_files_follow_gfal_config_dir(tmp_path: Path) -> None:
    (tmp_path / "b.conf").write_text("[CORE]\nNAMESPACE_TIMEOUT=5\n")
    (tmp_path / "a.conf").write_text("[CORE]\nNAMESPACE_TIMEOUT=4\n")
    (tmp_path / "ignored.txt").write_text("[CORE]\nNAMESPACE_TIMEOUT=1\n")
    env = {"GFAL_CONFIG_DIR": str(tmp_path)}
    assert [Path(p).name for p in Options.system_files(env)] == ["a.conf", "b.conf"]
    assert Options.system_files({}) == Options.system_files({"GFAL_CONFIG_DIR": "/etc/gfal2.d"})


def test_system_configuration_is_layered(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    (tmp_path / "core.conf").write_text("[CORE]\nNAMESPACE_TIMEOUT=77\n")
    monkeypatch.setenv("GFAL_CONFIG_DIR", str(tmp_path))
    assert Options().get_integer("CORE", "NAMESPACE_TIMEOUT") == 77
    assert Options(load_system=False).get_integer("CORE", "NAMESPACE_TIMEOUT") == 300


def test_snapshot_is_a_copy(options: Options) -> None:
    snapshot = options.snapshot()
    snapshot["CORE"]["NAMESPACE_TIMEOUT"] = "1"
    assert options.get_integer("CORE", "NAMESPACE_TIMEOUT") == 300
