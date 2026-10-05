"""Every shipped entry point has machine output, without service-specific imports."""

from __future__ import annotations

import base64
import errno
import io
import json
import sys
from xml.etree import ElementTree as ET

import pytest
from xrdclient.cli import _output as output

from gfal2_util.shell import Gfal2Shell
from xgfalclient import cli, transfer
from xgfalclient.cli import _base, _tape
from xgfalclient.cli.__main__ import main as module_main
from xgfalclient.context import Gfal2Context
from xgfalclient.plugins.mock import MockPlugin


def xml_value(node):
    kind = node.attrib["type"]
    if kind == "object":
        return {field.attrib["name"]: xml_value(field) for field in node}
    if kind == "array":
        return [xml_value(item) for item in node]
    if kind == "null":
        return None
    if kind == "string":
        text = node.text or ""
        if "encoding" in node.attrib:
            return base64.b64decode(text).decode("utf-8", "surrogatepass")
        return text
    return json.loads(node.text)


def decode(text, fmt):
    if fmt == "json":
        return json.loads(text)
    root = ET.fromstring(text)
    return {
        "schema": root.attrib["schema"],
        "version": int(root.attrib["version"]),
        "tool": xml_value(root.find("tool")),
        "command": xml_value(root.find("command")),
        "records": [xml_value(node) for node in root.find("records")],
        "summary": xml_value(root.find("summary")),
    }


def invoke(command, args, fmt, capsys):
    code = getattr(cli, command.replace("-", "_"))(["--output-format", fmt, *args])
    captured = capsys.readouterr()
    assert captured.err == ""
    report = decode(captured.out, fmt)
    assert report["schema"] == output.SCHEMA and report["version"] == 1
    assert report["summary"]["exit_code"] == code
    return code, report


@pytest.mark.parametrize("fmt", ["json", "xml"])
@pytest.mark.parametrize("command", sorted(cli.COMMANDS))
@pytest.mark.parametrize("flag", ["--help", "--version"])
def test_all_commands_help_and_version(fmt, command, flag, capsys):
    code, report = invoke(command, [flag], fmt, capsys)
    assert code == 0 and report["summary"]["ok"]
    assert report["records"]
    if flag == "--version":
        assert any(row["kind"] == "version" for row in report["records"])


@pytest.mark.parametrize("fmt", ["json", "xml"])
@pytest.mark.parametrize("command", ["gfal2_version", "gfal_srm_ifce_version"])
def test_version_only_tools(fmt, command, capsys):
    code, report = invoke(command, [], fmt, capsys)
    assert code == 0 and report["records"][0]["kind"] == "version"


@pytest.mark.parametrize("fmt", ["json", "xml"])
@pytest.mark.parametrize("command", ["stat", "copy", "chmod", "legacy-register"])
def test_usage_errors_are_structured(fmt, command, capsys):
    code, report = invoke(command, [], fmt, capsys)
    assert code == 2
    error = next(row for row in report["records"] if row["kind"] == "error")
    assert error["code"] == 2 and error["error_type"] == "ValueError"
    assert "required" in error["message"]


@pytest.mark.parametrize("fmt", ["json", "xml"])
def test_partial_mkdir_batch_retains_success_and_numeric_failure(fmt, tmp_path, capsys):
    first, second = tmp_path / "first", tmp_path / "second"
    second.mkdir()
    code, report = invoke("mkdir", [first.as_uri(), second.as_uri()], fmt, capsys)
    assert code == errno.EEXIST and first.is_dir()
    assert report["records"][0]["url"] == first.as_uri()
    assert report["records"][0]["status"] == "succeeded"
    error = next(row for row in report["records"] if row["kind"] == "error")
    assert error["url"] == second.as_uri() and error["code"] == errno.EEXIST
    assert "already exists" in error["message"]


@pytest.mark.parametrize("fmt", ["json", "xml"])
@pytest.mark.parametrize("command", ["cat", "copy"])
def test_binary_stdout_is_encoded_not_mixed_with_report(fmt, command, tmp_path, capsys):
    path = tmp_path / "blob"
    body = b"\0\xff\r\n" * (1 << 19)
    path.write_bytes(body)
    args = [path.as_uri()] + (["-"] if command == "copy" else [])
    code, report = invoke(command, args, fmt, capsys)
    assert code == 0
    chunks = [row for row in report["records"] if row["kind"] == "content"]
    assert b"".join(base64.b64decode(row["value"]["data"]) for row in chunks) == body
    assert any(row.get("status") == "succeeded" for row in report["records"])


@pytest.mark.parametrize("fmt", ["json", "xml"])
def test_listing_is_typed_and_filename_escaping_is_lossless(fmt, tmp_path, capsys):
    name = "a\n<&>\té"
    (tmp_path / name).write_bytes(b"ab")
    code, report = invoke("ls", [tmp_path.as_uri()], fmt, capsys)
    assert code == 0
    row = next(row for row in report["records"] if row["kind"] == "result")
    assert row["name"] == name and row["value"]["st_size"] == 2
    assert row["url"] == tmp_path.as_uri()


@pytest.mark.parametrize("fmt", ["json", "xml"])
def test_mutators_and_results(fmt, tmp_path, capsys, monkeypatch):
    source, target = tmp_path / "source", tmp_path / "target"
    source.write_bytes(b"abc")
    for command, args in [
        ("stat", [source.as_uri()]),
        ("sum", [source.as_uri(), "MD5"]),
        ("chmod", ["600", source.as_uri()]),
        ("rename", [source.as_uri(), target.as_uri()]),
        ("rm", [target.as_uri()]),
    ]:
        code, report = invoke(command, args, fmt, capsys)
        assert code == 0 and any(row["kind"] == "result" for row in report["records"])
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(b"saved")))
    code, report = invoke("save", [source.as_uri()], fmt, capsys)
    assert code == 0 and report["records"][0]["bytes_read"] == 5
    assert source.read_bytes() == b"saved"
    code, report = invoke("xattr", ["mock://h/f?user.status=ONLINE", "user.status"], fmt, capsys)
    assert code == 0 and report["records"][0]["value"] == "ONLINE"
    monkeypatch.setattr(
        MockPlugin, "token_retrieve", lambda *args: "requested-token", raising=False
    )
    code, report = invoke("token", ["mock://h/f"], fmt, capsys)
    assert code == 0 and any(row.get("value") == "requested-token" for row in report["records"])


@pytest.mark.parametrize("fmt", ["json", "xml"])
def test_copy_acknowledgement_and_progress(fmt, tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(transfer, "MONITOR_INTERVAL", 0)
    monkeypatch.setattr(transfer, "STREAM_MONITOR_INTERVAL", 0)
    source, target = tmp_path / "source", tmp_path / "target"
    source.write_bytes(b"a" * (2 << 20))
    code, report = invoke("copy", [source.as_uri(), target.as_uri()], fmt, capsys)
    assert code == 0 and target.read_bytes() == source.read_bytes()
    result = next(row for row in report["records"] if row["kind"] == "result")
    assert result["source"] == source.as_uri() and result["target"] == target.as_uri()
    assert result["expected_bytes"] == 2 << 20 and result["status"] == "succeeded"
    assert any(row["kind"] == "progress" for row in report["records"])
    assert any(row["kind"] == "event" for row in report["records"])
    event = next(row for row in report["records"] if row["kind"] == "event")
    assert event["source"] == source.as_uri() and event["target"] == target.as_uri()


@pytest.mark.parametrize("fmt", ["json", "xml"])
def test_dry_run_never_claims_transfer_success(fmt, tmp_path, capsys):
    source, target = tmp_path / "source", tmp_path / "target"
    source.write_bytes(b"a")
    code, report = invoke("copy", ["--dry-run", source.as_uri(), target.as_uri()], fmt, capsys)
    assert code == 0 and not target.exists()
    row = next(row for row in report["records"] if row["kind"] == "result")
    assert row["status"] == "planned" and row["bytes_transferred"] == 0


@pytest.mark.parametrize("fmt", ["json", "xml"])
def test_staging_handles_and_mixed_batch_states(fmt, tmp_path, capsys, monkeypatch):
    listing = tmp_path / "urls"
    urls = ["mock://h/good", "mock://h/bad?staging_errno=22"]
    listing.write_text("\n".join(urls))
    code, report = invoke("bringonline", ["--from-file", str(listing)], fmt, capsys)
    assert code == 0 and not report["summary"]["ok"]
    assert next(row for row in report["records"] if row["kind"] == "request")["request_id"]
    states = [row for row in report["records"] if row["kind"] == "result"]
    assert [(row["url"], row["status"]) for row in states] == [
        (urls[0], "queued"),
        (urls[1], "failed"),
    ]
    monkeypatch.setattr(_tape, "sleep", lambda seconds: None)
    monkeypatch.setattr(Gfal2Context, "bring_online_poll", lambda *args: [None])
    code, report = invoke("bringonline", ["--polling-timeout", "1", "mock://h/ready"], fmt, capsys)
    assert code == 0 and any(row["kind"] == "wait" for row in report["records"])
    assert any(row.get("status") == "ready" for row in report["records"])
    code, report = invoke("archivepoll", ["mock://h/queued?archiving_time=100"], fmt, capsys)
    assert code == 0 and any(row.get("status") == "queued" for row in report["records"])
    code, report = invoke("evict", ["mock://h/f", "opaque-handle"], fmt, capsys)
    assert code == 0 and report["records"][0]["request_id"] == "opaque-handle"


@pytest.mark.parametrize("fmt", ["json", "xml"])
def test_report_failure_can_coexist_with_compatibility_exit_zero(fmt, capsys, monkeypatch):
    monkeypatch.setattr(MockPlugin, "listxattr", lambda *args: ["user.nope"], raising=False)
    code, report = invoke("xattr", ["mock://h/f"], fmt, capsys)
    assert code == 0 and not report["summary"]["ok"]
    assert report["records"][0]["code"] == errno.ENODATA


@pytest.mark.parametrize("fmt", ["json", "xml"])
def test_module_and_compatibility_shell(fmt, tmp_path, capsys):
    path = tmp_path / "a"
    path.write_bytes(b"hi")
    assert module_main(["stat", "--output-format", fmt, path.as_uri()]) == 0
    assert decode(capsys.readouterr().out, fmt)["summary"]["ok"]
    assert module_main(["unknown", "--output-format", fmt]) == 2
    assert decode(capsys.readouterr().out, fmt)["summary"]["exit_code"] == 2
    assert Gfal2Shell().main(["gfal-stat", "--output-format", fmt, path.as_uri()]) == 0
    assert decode(capsys.readouterr().out, fmt)["summary"]["ok"]


def test_shortcuts_and_timeout_close_late_worker_output(tmp_path, capsys, monkeypatch):
    path = tmp_path / "a"
    path.write_bytes(b"hi")
    assert cli.stat(["--json", path.as_uri()]) == 0
    assert json.loads(capsys.readouterr().out)["summary"]["ok"]
    assert cli.stat(["--xml", path.as_uri()]) == 0
    assert decode(capsys.readouterr().out, "xml")["summary"]["ok"]
    # A worker that exceeds the wait budget retains its closed ContextVar report;
    # shared diagnostic helpers must never leak late text into restored stdout.
    import threading

    done, release = threading.Event(), threading.Event()
    original = Gfal2Context.stat

    def delayed(self, url):
        release.wait(5)
        _base.out("late worker message")
        done.set()
        return original(self, url)

    monkeypatch.setattr(Gfal2Context, "stat", delayed)
    monkeypatch.setattr(_base, "TIMEOUT_GRACE", 0)
    code, report = invoke("stat", ["--timeout", "1", path.as_uri()], "json", capsys)
    release.set()
    assert done.wait(5)
    assert code == errno.ETIMEDOUT and not report["summary"]["ok"]
    assert any(row.get("code") == errno.ETIMEDOUT for row in report["records"])
    assert capsys.readouterr().out == ""


@pytest.mark.parametrize("fmt", ["json", "xml"])
def test_early_configuration_and_input_validation(fmt, capsys):
    code, report = invoke("stat", ["-D", "bad", "mock://h/f"], fmt, capsys)
    assert code == 1 and report["summary"]["error_count"] == 1
    code, report = invoke("token", ["--validity=-1", "mock://h/f"], fmt, capsys)
    assert code == 1 and "validity" in report["records"][0]["message"]
    code, report = invoke("bringonline", [], fmt, capsys)
    assert code == 1 and "URL" in report["records"][0]["message"]


def test_shared_error_is_deduplicated_across_copy_and_executor(tmp_path, capsys):
    source, target = tmp_path / "source", tmp_path / "target"
    source.write_bytes(b"a")
    target.write_bytes(b"b")
    code, report = invoke("copy", [source.as_uri(), target.as_uri()], "json", capsys)
    assert code == errno.EEXIST and report["summary"]["error_count"] == 1


@pytest.mark.parametrize("fmt", ["json", "xml"])
def test_recursive_copy_does_not_acknowledge_failed_children(fmt, tmp_path, capsys, monkeypatch):
    source, target = tmp_path / "source", tmp_path / "target"
    source.mkdir()
    (source / "a").write_bytes(b"a")
    (source / "b").write_bytes(b"b")
    original = Gfal2Context.filecopy

    def copy(self, params, src, dst):
        if src.endswith("/b"):
            from xgfalclient import GError

            raise GError("write failed", errno.EIO)
        return original(self, params, src, dst)

    monkeypatch.setattr(Gfal2Context, "filecopy", copy)
    code, report = invoke("copy", ["-r", source.as_uri(), target.as_uri()], fmt, capsys)
    assert code == 0 and not report["summary"]["ok"]
    rows = [
        row
        for row in report["records"]
        if row["kind"] == "result" and row.get("operation") == "copy"
    ]
    assert any(row["source"].endswith("/a") and row["status"] == "succeeded" for row in rows)
    assert not any(row["source"].endswith("/b") and row["status"] == "succeeded" for row in rows)


def test_plain_metadata_conversion_is_skipped(capsys):
    from xgfalclient.types import Stat

    assert _base.stat_record(Stat()) is None

    def action():
        assert _base.stat_record(None) is None
        return 0

    assert output.run_cli("test", ["--json"], action) == 0
    assert json.loads(capsys.readouterr().out)["summary"]["ok"]
