"""The docker image the interop harnesses run this checkout's code in.

The gfal2 reference stack lives in the external ``gfal-ref:latest`` image
(AlmaLinux 9, gfal2 2.23.5), whose ``python3`` is 3.9 - the only interpreter
python3-gfal2 is built for there. xgfalclient and xrdclient need 3.11, so the
harnesses run gfal2's side on the system ``python3`` and this package's side
on AppStream ``python3.11``, in an image derived from the reference one with
that interpreter and the runtime dependencies added. xrdclient and the
libraries it and xgfalclient are built on (xrdcore, xrdsec, xrdhttp) come
from the host's own imports, bind-mounted, so the container runs exactly the
code the host test run does (the pinned releases are not in the image for
3.11): each harness mounts xrdclient where it always has, and adds
:func:`library_mounts`, which mounts each library under :data:`LIBRARY_ROOT`
and puts them on the container's ``PYTHONPATH`` (:data:`LIBRARY_PATH`, which a
harness that sets ``PYTHONPATH`` itself appends).

The derived image is tagged after the recipe's hash: a changed recipe builds
a new one, an unchanged one is docker's cache. The first build needs network
access for ``dnf`` and ``pip``; see "Reference behaviour" in
``docs/DEVELOPING.md`` for what to put in an image built by hand.
"""

from __future__ import annotations

import functools
import hashlib
import subprocess
from pathlib import Path

#: The external reference image: gfal2, its plugins and bindings, gfal2-util.
BASE_IMAGE = "gfal-ref:latest"
#: The interpreter that runs xgfalclient and xrdclient inside the image.
XGFAL_PYTHON = "python3.11"
#: The interpreter gfal2's Python bindings are built for.
GFAL2_PYTHON = "python3"
#: Runtime dependencies of the libraries (xrdsec: asn1crypto, cryptography;
#: xrdhttp: botocore), xrdclient and xgfalclient (bcrypt, cryptography), less
#: the bind-mounted packages themselves.
PACKAGES = ("cryptography>=45", "botocore>=1.35", "bcrypt>=4", "asn1crypto>=1.5.1")
#: The shared libraries, in dependency order, each mounted from its ``src``.
LIBRARIES = ("xrdcore", "xrdsec", "xrdhttp")
#: Where :func:`library_mounts` puts them in a container.
LIBRARY_ROOT = "/libs"
#: Their directories as a ``PYTHONPATH`` fragment inside a container.
LIBRARY_PATH = ":".join(f"{LIBRARY_ROOT}/{name}" for name in LIBRARIES)


def dockerfile(base: str = BASE_IMAGE, extras: tuple[str, ...] = ()) -> str:
    """The derived image's recipe: ``base`` plus python3.11 and the dependencies."""
    packages = " ".join(f'"{requirement}"' for requirement in (*PACKAGES, *extras))
    return (
        f"FROM {base}\n"
        "RUN dnf -y install python3.11 python3.11-pip && dnf clean all \\\n"
        f"    && {XGFAL_PYTHON} -m pip install --no-cache-dir {packages}\n"
    )


def image_tag(base: str, recipe: str) -> str:
    """``<base name>-py311:<recipe hash>``, so a changed recipe is a new image."""
    name = base.rsplit(":", 1)[0] if ":" in base.rsplit("/", 1)[-1] else base
    digest = hashlib.sha256(recipe.encode()).hexdigest()[:12]
    return f"{name}-py311:{digest}"


@functools.cache
def xgfal_image(base: str = BASE_IMAGE, extras: tuple[str, ...] = ()) -> str:
    """Build (once per process) the image that can run this checkout; its tag.

    ``extras`` are further requirements for one harness (paramiko for sftp's
    optional tier). The build always runs: docker's cache makes an unchanged
    recipe cheap, and keys on the base image, so a rebuilt base is picked up.
    """
    recipe = dockerfile(base, extras)
    tag = image_tag(base, recipe)
    done = subprocess.run(
        ["docker", "build", "-q", "-t", tag, "-"],
        input=recipe,
        capture_output=True,
        text=True,
        timeout=3600,
        check=False,
    )
    if done.returncode:
        raise RuntimeError(
            f"cannot derive {tag} from {base} (needs network for dnf and pip the first "
            f"time; see docs/DEVELOPING.md):\n{done.stderr.strip()[-2000:]}"
        )
    return tag


def xrdclient_src() -> Path:
    """The directory holding the ``xrdclient`` package this process imports."""
    import xrdclient

    return Path(xrdclient.__file__).resolve().parent.parent


def library_src(name: str) -> Path:
    """The directory holding the library package ``name`` this process imports."""
    import importlib

    module = importlib.import_module(name)
    assert module.__file__ is not None
    return Path(module.__file__).resolve().parent.parent


def library_mounts() -> list[str]:
    """``docker run`` arguments that mount every library and put them on ``PYTHONPATH``.

    Each library's ``src`` is mounted read-only at ``/libs/<name>``. A
    harness whose container command sets ``PYTHONPATH`` itself must append
    :data:`LIBRARY_PATH` to it; one that edits ``sys.path`` inherits this.
    """
    mounts = [f"{library_src(name)}:{LIBRARY_ROOT}/{name}:ro" for name in LIBRARIES]
    return [
        *(part for mount in mounts for part in ("-v", mount)),
        "-e",
        f"PYTHONPATH={LIBRARY_PATH}",
    ]
