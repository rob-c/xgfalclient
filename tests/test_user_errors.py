"""Plain display wording without changing compatibility error payloads."""

from __future__ import annotations

import errno
import os
import pickle

import pytest

from xgfalclient.errors import _USER_ERRORS, GError, from_oserror, gerror


@pytest.mark.parametrize("code", sorted(_USER_ERRORS))
@pytest.mark.parametrize("kind", ["empty", "system", "file_plugin", "scoped"])
def test_common_errors_have_a_clear_display_and_unchanged_payload(code, kind):
    messages = {
        "empty": "",
        "system": os.strerror(code),
        "file_plugin": "errno reported by local system call " + os.strerror(code),
        "scoped": "[gfal2_stat][file] " + os.strerror(code),
    }
    original = messages[kind]
    error = GError(original, code)
    assert error.message == original
    assert error.args == (original, code)
    assert error.code == code
    assert str(error) == error.user_message
    assert "." in error.user_message
    assert len(error.user_message) < 150
    assert "errno reported" not in str(error)
    assert "[gfal2_stat]" not in str(error)
    recovered = pickle.loads(pickle.dumps(error))
    assert (recovered.message, recovered.code, recovered.args) == (original, code, error.args)
    assert str(recovered) == str(error)


def test_existing_actionable_details_are_not_replaced_by_generic_advice():
    error = gerror(errno.EACCES, "Your bearer token has expired. Get a new token.", "http")
    assert error.user_message == "Your bearer token has expired. Get a new token."
    assert error.message.startswith("[http]")


def test_unknown_error_numbers_are_retained_without_guessing_the_cause():
    error = GError(os.strerror(9876), 9876)
    assert error.code == 9876
    assert error.user_message == "The request failed. Check the command and service configuration."


def test_local_missing_file_is_not_a_jargon_message():
    error = from_oserror(FileNotFoundError(errno.ENOENT, "gone", "/tmp/data.root"))
    assert error.code == errno.ENOENT
    assert error.user_message == "File or folder not found. Check the path and try again."
