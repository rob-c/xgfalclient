"""``gfal-rm``: one ``url<TAB>STATUS`` line per file, as gfal2-util 1.9.1 prints them.

The exit status is the errno of the first failure, even when later files
are removed; a failure other than "missing" stops the command. Behaviour is
gfal2-util's (Apache-2.0, (c) CERN), reimplemented.

The status words (``DELETED``, ``MISSING``, ``FAILED``, ``RMDIR``, ``SKIP``,
``SKIP DIR``) are what scripts grep for, so they are fixed. ``gfal-rm``'s
:class:`~._base.Spec` starts its exit status at 0 rather than -1: an
unexpected exception still exits 0 there, as in gfal2-util.
"""

from __future__ import annotations

import errno
import stat
import sys

from ..errors import GError
from ._base import Command, Spec, arg, out, output, surl

__all__ = ["SPECS", "read_list"]


def read_list(path: str) -> list[str]:
    """The non-blank lines of a ``--from-file`` list, stripped.

    Used as given: unlike positional arguments, these are not passed
    through ``surl``, so a bare local path in the file is not turned into a
    ``file://`` URL (gfal2-util's behaviour).
    """
    with open(path) as handle:
        return [line.strip() for line in handle if line.strip()]


class _Remover:
    """One ``gfal-rm`` run; the exit status accumulates on ``cmd.return_code``."""

    def __init__(self, cmd: Command) -> None:
        """Bind to the invocation (options and context)."""
        self.cmd = cmd
        self.params = cmd.params
        self.context = cmd.context

    def propagate(self, code: int) -> None:
        """Make ``code`` the exit status unless an earlier failure already set one."""
        if self.cmd.return_code == 0:
            self.cmd.return_code = code

    def failed(self, url: str, exc: GError) -> None:
        """``MISSING`` is reported and survived; anything else stops the command."""
        self.propagate(exc.code)
        output.error(exc, url=url)
        if exc.code == errno.ENOENT:
            out(f"{url}\tMISSING\n")
            return
        out(f"{url}\tFAILED\n")
        raise exc

    def remove(self, url: str) -> None:
        """Remove one URL: stat it, recurse into a directory, else ``unlink``.

        ``--just-delete`` skips the ``stat`` - a pre-signed HTTP URL is
        valid for ``DELETE`` only, so a ``HEAD``/``PROPFIND`` would be
        refused - and therefore cannot recurse.
        """
        output.identify("rm", url=url)
        if not self.params.just_delete:
            try:
                info = self.context.stat(url)
            except GError as exc:
                self.failed(url, exc)
                return
            if stat.S_ISDIR(info.st_mode):
                self.remove_directory(url)
                return
        if self.params.dry_run:
            output.record(status="planned")
            out(f"{url}\tSKIP\n")
            return
        try:
            self.context.unlink(url)
        except GError as exc:
            self.failed(url, exc)
            return
        out(f"{url}\tDELETED\n")
        output.record(status="succeeded")

    def remove_directory(self, url: str) -> None:
        """``-r``: children depth-first, then the directory; without ``-r``, ``EISDIR``.

        Children are listed once up front (``listdir``), so entries created
        during the removal are not seen and the final ``rmdir`` fails with
        the server's ``ENOTEMPTY``, as with gfal2-util.
        """
        if not self.params.recursive:
            raise GError(f"Can not remove {url}, is a directory", errno.EISDIR)
        base = url if url.endswith("/") else url + "/"
        for name in self.context.listdir(url):
            if name not in (".", ".."):
                self.remove(base + name)
        output.identify("rmdir", url=url)
        if self.params.dry_run:
            output.record(status="planned")
            out(f"{url}\tSKIP DIR\n")
            return
        try:
            self.context.rmdir(url)
        except GError as exc:
            self.failed(url, exc)
            return
        out(f"{url}\tRMDIR\n")
        output.record(status="succeeded")

    def bulk(self, urls: list[str]) -> None:
        """``--bulk``: one list ``unlink`` (a single SRM ``srmRm``, say), one line per URL.

        Unlike the one-by-one path, a failure here does not stop the rest:
        the list call has already tried every file. No ``stat`` is done, so
        directories are not recognised (``--bulk`` refuses ``-r``).
        """
        if self.params.dry_run:
            for url in urls:
                output.record(operation="rm", url=url, status="planned")
            out("\tBULK DELETION\n")
            return
        results = self.context.unlink(urls)
        assert isinstance(results, list)
        for url, error in zip(urls, results, strict=False):
            if error is None:
                output.record(operation="rm", url=url, status="succeeded")
                out(f"{url}\tDELETED\n")
            else:
                output.error(error, operation="rm", url=url)
                out(f"{url}\tFAILED: {error}\n")
                self.propagate(error.code)


def rm(cmd: Command) -> int | None:
    """``gfal-rm [-r] [--bulk] [--dry-run] URL... | --from-file LIST``.

    Conflicting or missing arguments are reported on stderr with
    ``EINVAL`` as the status, gfal2-util's messages and all, rather than
    through argparse's usage error.
    """
    params = cmd.params
    if params.from_file and params.file:
        sys.stderr.write("--from-file and positional arguments can not be used at the same time\n")
        return errno.EINVAL
    if params.bulk and params.recursive:
        sys.stderr.write("--bulk and --recursive can not be used at the same time\n")
        return errno.EINVAL
    if params.file:
        urls = list(params.file)
    elif params.from_file:
        urls = read_list(params.from_file)
    else:
        sys.stderr.write("Missing surl\n")
        return errno.EINVAL
    remover = _Remover(cmd)
    if params.bulk:
        remover.bulk(urls)
    else:
        for url in urls:
            remover.remove(url)
    return cmd.return_code


SPECS = {
    "rm": Spec(
        "rm",
        "Removes files or directories",
        [
            arg(
                "-r",
                "-R",
                "--recursive",
                action="store_true",
                help="remove directories and their contents recursively",
            ),
            arg(
                "--dry-run",
                action="store_true",
                help="do not perform any actual change, just print what would happen",
            ),
            arg(
                "--just-delete",
                action="store_true",
                help="do not perform any check on the file, this is needed for HTTP signed URLs",
            ),
            arg("--from-file", type=str, default=None, help="read surls from a file"),
            arg("--bulk", action="store_true", default=False, help="use bulk deletion"),
            arg(
                "file",
                action="store",
                nargs="*",
                type=surl,
                help="uri(s) of the file(s) to be deleted",
            ),
        ],
        rm,
        return_code=0,
    ),
}
