"""gfal2-util 1.9.1's Python package, for code that imports it.

Wrappers and pilots run ``gfal-*`` commands in-process or add their own::

    from gfal2_util.shell import Gfal2Shell
    sys.exit(Gfal2Shell().main(["gfal-ls", "-l", url]))

    from gfal2_util import base

    class CommandHello(base.CommandBase):
        @base.arg("file", type=base.surl, help="file's uri")
        def execute_hello(self):
            '''Say hello'''
            print(self.context.stat(self.params.file).st_size)

The modules and public names are gfal2-util's (``base``, ``shell``,
``commands``, ``ls``, ``copy``, ``rm``, ``tape``, ``legacy``, ``utils``,
``progress``, ``gfal2_utils_parameters``); the commands behind them are
:mod:`xgfalclient.cli`'s, so they behave exactly as the installed
``gfal-*`` scripts do.

Each module here is a thin adapter: it re-exports names or builds
gfal2-util-shaped classes around the :class:`xgfalclient.cli._base.Spec`
objects, so there is one implementation of every command. Signatures of
the public names must stay gfal2-util's; anything new belongs in
:mod:`xgfalclient.cli`.
"""
