"""``gfal-rm``: one ``url<TAB>STATUS`` line per file, as gfal2-util 1.9.1 prints them.

The exit status is the errno of the first failure, even when later files
are removed; a failure other than "missing" stops the command. Behaviour is
gfal2-util's (Apache-2.0, (c) CERN), reimplemented.
"""

from __future__ import annotations

import errno
import stat
import sys

from ..errors import GError
from ._base import Command, Spec, arg, out, surl

__all__ = ["SPECS", "read_list"]


def read_list(path: str) -> list[str]:
    """The non-blank lines of a ``--from-file`` list, stripped."""
    with open(path) as handle:
        return [line.strip() for line in handle if line.strip()]


class _Remover:
    def __init__(self, cmd: Command) -> None:
        self.cmd = cmd
        self.params = cmd.params
        self.context = cmd.context

    def propagate(self, code: int) -> None:
        if self.cmd.return_code == 0:
            self.cmd.return_code = code

    def failed(self, url: str, exc: GError) -> None:
        """``MISSING`` is reported and survived; anything else stops the command."""
        self.propagate(exc.code)
        if exc.code == errno.ENOENT:
            out(f"{url}\tMISSING\n")
            return
        out(f"{url}\tFAILED\n")
        raise exc

    def remove(self, url: str) -> None:
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
            out(f"{url}\tSKIP\n")
            return
        try:
            self.context.unlink(url)
        except GError as exc:
            self.failed(url, exc)
            return
        out(f"{url}\tDELETED\n")

    def remove_directory(self, url: str) -> None:
        if not self.params.recursive:
            raise GError(f"Can not remove {url}, is a directory", errno.EISDIR)
        base = url if url.endswith("/") else url + "/"
        for name in self.context.listdir(url):
            if name not in (".", ".."):
                self.remove(base + name)
        if self.params.dry_run:
            out(f"{url}\tSKIP DIR\n")
            return
        try:
            self.context.rmdir(url)
        except GError as exc:
            self.failed(url, exc)
            return
        out(f"{url}\tRMDIR\n")

    def bulk(self, urls: list[str]) -> None:
        if self.params.dry_run:
            out("\tBULK DELETION\n")
            return
        results = self.context.unlink(urls)
        assert isinstance(results, list)
        for url, error in zip(urls, results):
            if error is None:
                out(f"{url}\tDELETED\n")
            else:
                out(f"{url}\tFAILED: {error}\n")
                self.propagate(error.code)


def rm(cmd: Command) -> int | None:
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
