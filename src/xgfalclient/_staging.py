"""Gfal2Context's tape, QoS and token calls, as a mixin.

gfal2 grew three families of calls that are not namespace operations:

* **tape** - ``bring_online``, ``bring_online_poll``, ``release``,
  ``abort_bring_online`` and ``archive_poll``, each in a single-URL form
  (an ``int`` status, raising on failure) and a list form (one ``GError``
  or ``None`` per URL, raising only for an empty list or mismatched
  metadata). The list forms go to the plugin of the *first* URL, as in
  gfal2, and a failure to find it becomes every file's error;
* **QoS** - ``check_file_qos`` and friends, passed straight to the plugin;
* **tokens** - ``token_retrieve``, whose overloads are untangled here.

They live in :class:`StagingMixin` so that :mod:`xgfalclient.context` reads
as the context - plugins, dispatch, cancellation, the namespace - while
:class:`~xgfalclient.context.Gfal2Context` still *has* every one of these
methods (it inherits them; ``help()``, IDEs and ``dir()`` show them as its
own), and the freed-context check ``context.py`` wraps around every
bindings method applies to them unchanged. The mixin uses only three
context methods, declared below for the type checker: ``plugin``,
``_guard`` and ``_dispatch``.
"""

from __future__ import annotations

import errno
from collections.abc import Callable, Sequence
from typing import TYPE_CHECKING, Any, TypeVar

from .errors import GError
from .plugin import StagingResult

if TYPE_CHECKING:
    from .plugin import Plugin

__all__ = ["StagingMixin"]

#: The result type of the plugin method :meth:`StagingMixin._guard` runs.
_T = TypeVar("_T")


class StagingMixin:
    """The tape, QoS and token methods of :class:`~xgfalclient.context.Gfal2Context`.

    Plugins always receive lists, even for the single-URL forms, so a plugin
    implements one method per call (``Plugin.bring_online(urls, ...)``) and
    the shaping into the bindings' two return conventions happens here.
    """

    if TYPE_CHECKING:
        # Provided by Gfal2Context; see its definitions.
        def plugin(self, url: str, operation: str) -> Plugin:
            """See :meth:`Gfal2Context.plugin`."""
            ...

        def _guard(self, method: Callable[..., _T], *args: Any) -> _T:
            """See :meth:`Gfal2Context._guard`."""
            ...

        def _dispatch(self, operation: str, url: str, *args: Any) -> Any:
            """See :meth:`Gfal2Context._dispatch`."""
            ...

    # -- tape -----------------------------------------------------------------------

    def bring_online(self, path: str | Sequence[str], *args: Any) -> tuple[Any, str]:
        """``(path(s), [metadata(s)], pintime, timeout, async)``, as gfal2 overloads it.

        ``gfal2_bring_online`` / ``gfal2_bring_online_list`` (and the ``_v2``
        forms with metadata, for the tape REST API's per-file ``targetedMetadata``).
        ``pintime`` and ``timeout`` are seconds; with ``async`` the request is
        queued and the token returned at once, to be polled with
        :meth:`bring_online_poll`. Answers ``(status, token)``: for one URL
        the status is ``1`` (online) or ``0`` (queued); for a list, one
        ``None``/``GError`` per URL.
        """
        if len(args) == 4:
            metadata_arg, pintime, timeout, is_async = args
        elif len(args) == 3:
            metadata_arg = None
            pintime, timeout, is_async = args
        else:
            raise TypeError("bring_online(path(s), [metadata], pintime, timeout, async)")
        call = (int(pintime), int(timeout), bool(is_async))
        if isinstance(path, str):
            metadata = [metadata_arg if metadata_arg is not None else ""]
            plugin = self.plugin(path, "bring_online")
            results, token = self._guard(plugin.bring_online, [path], metadata, *call)
            return _single_status(results[0]), token
        paths = _non_empty(path)
        metadata = list(metadata_arg) if metadata_arg is not None else [""] * len(paths)
        if len(metadata) != len(paths):
            raise GError("List of urls and list of metadata with different sizes", errno.EINVAL)
        found = self._bulk("bring_online", paths, metadata, *call)
        if isinstance(found, GError):
            return [found] * len(paths), ""
        results, token = found
        return [_list_error(r, u, None) for r, u in zip(results, paths, strict=False)], token

    def bring_online_poll(self, path: str | Sequence[str], token: str) -> Any:
        """``gfal2_bring_online_poll`` / ``_list``: ``1``/``0`` for one URL, errors for a list.

        A file not yet online is ``0`` in the single form and an ``EAGAIN``
        ``GError`` ("File ... is not yet online") in the list form, as in gfal2.
        """
        if isinstance(path, str):
            return _single_status(self._one("bring_online_poll", path, token), pending=True)
        return self._bulk_list("bring_online_poll", path, "online", token)

    def release(self, path: str | Sequence[str], token: str = "") -> Any:
        """``gfal2_release_file`` / ``_list``: drop the pin a bring-online took.

        The token may be empty, for protocols that can release by file.
        """
        if isinstance(path, str):
            return _single_done(self._one("release", path, token))
        return self._bulk_list("release", path, None, token)

    def abort_bring_online(self, path: str | Sequence[str], token: str) -> Any:
        """``gfal2_abort_files``: cancel the staging request ``token`` for these files."""
        if isinstance(path, str):
            return _single_done(self._one("abort_bring_online", path, token))
        return self._bulk_list("abort_bring_online", path, None, token)

    def archive_poll(self, path: str | Sequence[str]) -> Any:
        """``gfal2_archive_poll`` / ``_list``: is the file safely on tape yet?

        ``1``/``0`` for one URL; for a list, ``EAGAIN`` ("is not yet
        archived") per file still waiting. FTS polls this after an upload
        to a tape endpoint before declaring the transfer done.
        """
        if isinstance(path, str):
            return _single_status(self._one("archive_poll", path), pending=True)
        return self._bulk_list("archive_poll", path, "archived")

    def _one(self, operation: str, path: str, *args: Any) -> Any:
        """A list-shaped plugin call made for one URL: its only result."""
        plugin = self.plugin(path, operation)
        return self._guard(getattr(plugin, operation), [path], *args)[0]

    def _bulk(self, operation: str, paths: list[str], *args: Any) -> Any:
        """Run a list-form call on the first URL's plugin, or the ``GError`` every file gets.

        gfal2 sends the whole list to the plugin of the first URL, and turns a
        failure to find one (or of the call as a whole) into the same error
        for each file rather than raising.
        """
        try:
            plugin = self.plugin(paths[0], operation)
            return self._guard(getattr(plugin, operation), paths, *args)
        except GError as exc:
            return exc

    def _bulk_list(
        self, operation: str, path: Sequence[str], pending: str | None, *args: Any
    ) -> list[GError | None]:
        """A list form end to end: one ``None``/``GError`` per URL, in order.

        ``pending`` words the ``EAGAIN`` for a file whose result is "not
        yet" (``online``, ``archived``); None for calls where a false result
        cannot happen.
        """
        paths = _non_empty(path)
        found = self._bulk(operation, paths, *args)
        if isinstance(found, GError):
            return [found] * len(paths)
        return [_list_error(r, u, pending) for r, u in zip(found, paths, strict=False)]

    # -- QoS ----------------------------------------------------------------------

    # The QoS calls are gfal2's CDMI ones (``gfal2_qos_*``), implemented by
    # the HTTP plugin for endpoints that speak CDMI; nothing is added here.

    def check_file_qos(self, path: str) -> str:
        """``gfal2_check_file_qos``: the object's current QoS class URI."""
        return self._guard(self.plugin(path, "check_file_qos").check_file_qos, path)

    def check_available_qos_transitions(self, path: str) -> list[str]:
        """``gfal2_check_available_qos_transitions``: the classes ``path`` could move to."""
        plugin = self.plugin(path, "check_available_qos_transitions")
        return self._guard(plugin.check_available_qos_transitions, path)

    def check_target_qos(self, path: str) -> str:
        """``gfal2_check_target_qos``: the class a transition in progress is heading for."""
        return self._guard(self.plugin(path, "check_target_qos").check_target_qos, path)

    def change_object_qos(self, path: str, target: str) -> int:
        """``gfal2_change_object_qos``: start moving ``path`` to class ``target``."""
        self._dispatch("change_object_qos", path, target)
        return 0

    def qos_check_classes(self, path: str, kind: str) -> list[str]:
        """``gfal2_qos_check_classes``: the endpoint's classes of ``kind`` (``dataobject``...)."""
        return self._guard(self.plugin(path, "qos_check_classes").qos_check_classes, path, kind)

    # -- tokens ---------------------------------------------------------------------

    def token_retrieve(self, path: str, issuer: str, validity: int, *access: Any) -> str:
        """``(url, issuer, validity, write_access | activities)`` or
        ``(url, issuer, validity, write_access, activities)``, as gfal2 overloads it.

        Given activities, the plugin asks for those; ``write_access`` only
        picks a default set, and is ``False`` for the activities-only form.

        ``gfal2_token_retrieve`` (and ``_with_activities``): a macaroon or
        SciToken from the storage endpoint (``issuer`` empty means the
        endpoint's own), valid for ``validity`` minutes.
        """
        if len(access) == 2:
            write_access, activities = bool(access[0]), list(access[1])
        elif len(access) == 1 and isinstance(access[0], (list, tuple)):
            write_access, activities = False, list(access[0])
            if not activities:
                raise GError("Empty list of activities", errno.EINVAL)
        elif len(access) == 1:
            write_access, activities = bool(access[0]), []
        else:
            raise TypeError("token_retrieve(url, issuer, validity, write_access[, activities])")
        plugin = self.plugin(path, "token_retrieve")
        return self._guard(
            plugin.token_retrieve, path, issuer, int(validity), write_access, activities
        )


def _single_status(result: StagingResult, pending: bool = False) -> int:
    """``1`` done, ``0`` not yet; a poll's ``EAGAIN`` is "not yet" too, as in the bindings."""
    if isinstance(result, GError):
        if pending and result.code == errno.EAGAIN:
            return 0
        raise result
    return 1 if result else 0


def _list_error(result: StagingResult, url: str, pending: str | None) -> GError | None:
    """``None`` for done; the error, or ``EAGAIN`` worded as gfal2 does, otherwise."""
    if isinstance(result, GError):
        return result
    if not result and pending is not None:
        return GError(f"File {url} is not yet {pending}", errno.EAGAIN)
    return None


def _single_done(result: GError | None) -> int:
    """The single-URL ``release``/``abort`` convention: ``0``, or raise the URL's error."""
    if result is not None:
        raise result
    return 0


def _non_empty(paths: Sequence[str]) -> list[str]:
    """A list-form argument as a list; gfal2 refuses an empty one."""
    found = list(paths)
    if not found:
        raise GError("Empty list of files", errno.EINVAL)
    return found
