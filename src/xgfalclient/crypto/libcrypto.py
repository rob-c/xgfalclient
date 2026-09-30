"""The fast cipher backend: ``ctypes`` into the libcrypto Python's ``ssl`` uses.

Every CPython that has :mod:`ssl` has an OpenSSL (or LibreSSL) libcrypto
loaded, with AES-NI and vectorised ChaCha20 in it. Borrowing that library
through :mod:`ctypes` gives the SSH transport C-speed bulk encryption with no
dependency to install. Only the symmetric primitives are taken - EVP
ciphers (AES-CTR, AES-GCM, ChaCha20) and the Poly1305 MAC - because they
are what runs per packet; handshake arithmetic stays in Python, where it is
a few milliseconds.

The library is opened as a :class:`ctypes.PyDLL`, so calls keep the GIL.
A packet's cipher work is microseconds; dropping the GIL around each call
cost far more, because the transport's reader thread then had to win it
back from the consumer thread several times per packet.

Finding the library is the delicate part, so it is done conservatively:

1. the ``_ssl`` extension module itself - ``dlsym`` on its handle searches
   the libraries it links against, so this is exactly the libcrypto Python
   uses (Linux and macOS alike);
2. the running executable, for a Python with OpenSSL linked in statically;
3. ``ctypes.util.find_library("crypto")`` - except macOS's
   ``/usr/lib/libcrypto*``, a stub that aborts the process when loaded.

A candidate is accepted only if it has every symbol the backend calls
(AES-GCM and Poly1305 are optional extras, reported by :attr:`LibCrypto.has_gcm`
and :attr:`LibCrypto.has_poly1305`). :func:`load` returns ``None`` when none
qualifies, and the pure-Python backend in :mod:`.ciphers` takes over.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import sys
import threading
from typing import Any, Callable

__all__ = ["LibCrypto", "load", "candidates"]

_REQUIRED = (
    "EVP_CIPHER_CTX_new",
    "EVP_CIPHER_CTX_free",
    "EVP_CipherInit_ex",
    "EVP_CipherUpdate",
    "EVP_aes_128_ctr",
    "EVP_aes_192_ctr",
    "EVP_aes_256_ctr",
    "EVP_chacha20",
)
#: AES-GCM for ``aes{128,256}-gcm@openssh.com``; optional, like Poly1305.
_GCM = ("EVP_aes_128_gcm", "EVP_aes_256_gcm", "EVP_CIPHER_CTX_ctrl", "EVP_CipherFinal_ex")
_CTRL_GCM_GET_TAG = 0x10
_CTRL_GCM_SET_TAG = 0x11
_MAC = ("EVP_MAC_fetch", "EVP_MAC_CTX_new", "EVP_MAC_init", "EVP_MAC_update", "EVP_MAC_final")


def candidates() -> list[str | None]:
    """Paths to try, best first (``None`` means the running executable)."""
    found: list[str | None] = []
    try:
        import _ssl

        found.append(_ssl.__file__)
    except (ImportError, AttributeError):  # no ssl at all, or built into the executable
        pass
    found.append(None)
    library = ctypes.util.find_library("crypto")
    if library and not (sys.platform == "darwin" and library.startswith("/usr/lib/")):
        found.append(library)
    return found


def _open(path: str | None) -> Any:
    # PyDLL, not CDLL: the calls keep the GIL. Each is microseconds of work on
    # one packet, and releasing the GIL around it would mean re-acquiring it
    # afterwards - a wait behind whatever other thread holds it, per call.
    try:
        return ctypes.PyDLL(path)
    except OSError:
        return None


class _Cipher:
    """One ``EVP_CIPHER_CTX``, encrypting in place into a fresh ``bytearray``."""

    def __init__(self, lib: LibCrypto, cipher: Any, key: bytes, iv: bytes) -> None:
        self._lib = lib
        self._ctx = lib.c.EVP_CIPHER_CTX_new()
        if not self._ctx or not lib.c.EVP_CipherInit_ex(self._ctx, cipher, None, key, iv, 1):
            raise RuntimeError("EVP_CipherInit_ex failed")
        self._out = ctypes.c_int()

    def reset(self, iv: bytes) -> None:
        """Restart the keystream at ``iv`` with the same key."""
        if not self._lib.c.EVP_CipherInit_ex(self._ctx, None, None, None, iv, -1):
            raise RuntimeError("EVP_CipherInit_ex failed")

    def update(self, data: bytes | bytearray | memoryview) -> bytearray:
        buffer = bytearray(data)
        length = len(buffer)
        if length:
            pointer = (ctypes.c_char * length).from_buffer(buffer)
            if not self._lib.c.EVP_CipherUpdate(
                self._ctx, pointer, ctypes.byref(self._out), pointer, length
            ):
                raise RuntimeError("EVP_CipherUpdate failed")
        return buffer

    def __del__(self) -> None:
        ctx, self._ctx = getattr(self, "_ctx", None), None
        if ctx:
            self._lib.c.EVP_CIPHER_CTX_free(ctx)


class _Gcm:
    """One direction of AES-GCM, sealing or opening packets in place.

    The key schedule is set once; each packet restarts the context with its
    12-byte nonce, authenticates ``aad`` and transforms
    ``buffer[start:start + length]`` where it lies, with the 16-byte tag
    right after it. One call per step, so a packet costs a handful of
    ``ctypes`` round trips whatever its size.
    """

    def __init__(self, lib: LibCrypto, cipher: Any, key: bytes, encrypt: bool) -> None:
        self._c = lib.c
        self._encrypt = 1 if encrypt else 0
        self._ctx = lib.c.EVP_CIPHER_CTX_new()
        if not self._ctx or not lib.c.EVP_CipherInit_ex(
            self._ctx, cipher, None, key, None, self._encrypt
        ):
            raise RuntimeError("EVP_CipherInit_ex failed")
        self._out = ctypes.c_int()

    def apply(self, nonce: bytes, aad: bytes, buffer: bytearray, start: int, length: int) -> bool:
        """Seal or open ``buffer[start:start+length]`` in place, the tag right after it.

        Encrypting writes the tag and returns ``True``. Decrypting checks the
        tag and returns ``False`` when it is wrong - the region then holds
        unauthenticated output, which the caller must discard unread.
        """
        c, ctx, out = self._c, self._ctx, ctypes.byref(self._out)
        pinned = (ctypes.c_char * len(buffer)).from_buffer(buffer)  # held until we return
        data = ctypes.addressof(pinned) + start
        tag = data + length
        ready = (
            c.EVP_CipherInit_ex(ctx, None, None, None, nonce, self._encrypt)
            and c.EVP_CipherUpdate(ctx, None, out, aad, len(aad))
            and (self._encrypt or c.EVP_CIPHER_CTX_ctrl(ctx, _CTRL_GCM_SET_TAG, 16, tag))
            and (not length or c.EVP_CipherUpdate(ctx, data, out, data, length))
        )
        if not ready:
            raise RuntimeError("AES-GCM failed")
        if not c.EVP_CipherFinal_ex(ctx, tag, out):
            return False
        if self._encrypt and not c.EVP_CIPHER_CTX_ctrl(ctx, _CTRL_GCM_GET_TAG, 16, tag):
            raise RuntimeError("AES-GCM get tag failed")
        return True

    def __del__(self) -> None:
        ctx, self._ctx = getattr(self, "_ctx", None), None
        if ctx:
            self._c.EVP_CIPHER_CTX_free(ctx)


class LibCrypto:
    """A loaded libcrypto with the prototypes the backend uses declared."""

    def __init__(self, handle: Any, path: str | None) -> None:
        self.c = handle
        self.path = path
        c = handle
        c.EVP_CIPHER_CTX_new.restype = ctypes.c_void_p
        c.EVP_CIPHER_CTX_new.argtypes = []
        c.EVP_CIPHER_CTX_free.argtypes = [ctypes.c_void_p]
        c.EVP_CIPHER_CTX_free.restype = None
        c.EVP_CipherInit_ex.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_char_p,
            ctypes.c_char_p,
            ctypes.c_int,
        ]
        c.EVP_CipherInit_ex.restype = ctypes.c_int
        c.EVP_CipherUpdate.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_int),
            ctypes.c_void_p,
            ctypes.c_int,
        ]
        c.EVP_CipherUpdate.restype = ctypes.c_int
        for name in ("EVP_aes_128_ctr", "EVP_aes_192_ctr", "EVP_aes_256_ctr", "EVP_chacha20"):
            getattr(c, name).restype = ctypes.c_void_p
            getattr(c, name).argtypes = []
        self.version = self._version()
        self.has_gcm = all(hasattr(c, name) for name in _GCM)
        if self.has_gcm:
            for name in ("EVP_aes_128_gcm", "EVP_aes_256_gcm"):
                getattr(c, name).restype = ctypes.c_void_p
                getattr(c, name).argtypes = []
            c.EVP_CIPHER_CTX_ctrl.argtypes = [
                ctypes.c_void_p,
                ctypes.c_int,
                ctypes.c_int,
                ctypes.c_void_p,
            ]
            c.EVP_CIPHER_CTX_ctrl.restype = ctypes.c_int
            c.EVP_CipherFinal_ex.argtypes = [
                ctypes.c_void_p,
                ctypes.c_void_p,
                ctypes.POINTER(ctypes.c_int),
            ]
            c.EVP_CipherFinal_ex.restype = ctypes.c_int
        self._mac: Any = None
        if all(hasattr(c, name) for name in _MAC):
            c.EVP_MAC_fetch.restype = ctypes.c_void_p
            c.EVP_MAC_fetch.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]
            c.EVP_MAC_CTX_new.restype = ctypes.c_void_p
            c.EVP_MAC_CTX_new.argtypes = [ctypes.c_void_p]
            c.EVP_MAC_init.restype = ctypes.c_int
            c.EVP_MAC_init.argtypes = [
                ctypes.c_void_p,
                ctypes.c_char_p,
                ctypes.c_size_t,
                ctypes.c_void_p,
            ]
            c.EVP_MAC_update.restype = ctypes.c_int
            c.EVP_MAC_update.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_size_t]
            c.EVP_MAC_final.restype = ctypes.c_int
            c.EVP_MAC_final.argtypes = [
                ctypes.c_void_p,
                ctypes.c_char_p,
                ctypes.POINTER(ctypes.c_size_t),
                ctypes.c_size_t,
            ]
            self._mac = c.EVP_MAC_fetch(None, b"POLY1305", None) or None
        self._local = threading.local()
        # Apple's LibreSSL (what the Xcode Python's ``_ssl`` links) exports the
        # symbols but fails AES-GCM outright and derives a different ChaCha20
        # keystream from the same IV, so every primitive is proven against a
        # known answer before it is offered, and the pure-Python code takes
        # over for whichever fails.
        self.has_chacha = _passes(self._chacha_known_answer)
        self.has_gcm = self.has_gcm and _passes(self._gcm_known_answer)

    def _ctr_known_answer(self) -> None:
        # NIST SP 800-38A F.5.1, first block.
        key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
        iv = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
        out = self.aes_ctr(key, iv).update(bytes.fromhex("6bc1bee22e409f96e93d7e117393172a"))
        if bytes(out) != bytes.fromhex("874d6191b620e3261bef6864990db6ce"):
            raise RuntimeError("AES-CTR known answer failed")

    def _chacha_known_answer(self) -> None:
        # RFC 8439 2.4.2, first 16 bytes of the keystream at counter 1.
        cipher = self.chacha20(bytes(range(32)))
        cipher.reset(b"\x01\x00\x00\x00" + bytes.fromhex("000000000000004a00000000"))
        out = cipher.update(b"Ladies and Gentl")
        if bytes(out) != bytes.fromhex("6e2e359a2568f98041ba0728dd0d6981"):
            raise RuntimeError("ChaCha20 known answer failed")

    def _gcm_known_answer(self) -> None:
        # NIST GCM test case 2: zero key, zero IV, one zero block, no AAD.
        buffer = bytearray(32)
        sealed = bytes.fromhex("0388dace60b6a392f328c2b971b2fe78ab6e47d42cec13bdf53a67b21257bddf")
        if not self.aes_gcm(bytes(16), True).apply(bytes(12), b"", buffer, 0, 16):
            raise RuntimeError("AES-GCM seal failed")
        if bytes(buffer) != sealed:
            raise RuntimeError("AES-GCM known answer failed")
        if not self.aes_gcm(bytes(16), False).apply(bytes(12), b"", buffer, 0, 16):
            raise RuntimeError("AES-GCM open failed")
        if bytes(buffer[:16]) != bytes(16):
            raise RuntimeError("AES-GCM round trip failed")

    def _version(self) -> str:
        function = getattr(self.c, "OpenSSL_version", None)
        if function is None:
            return "libcrypto"
        function.restype = ctypes.c_char_p
        function.argtypes = [ctypes.c_int]
        return str(function(0).decode("ascii", "replace"))

    @property
    def has_poly1305(self) -> bool:
        return self._mac is not None

    def aes_ctr(self, key: bytes, iv: bytes) -> _Cipher:
        cipher = {16: "EVP_aes_128_ctr", 24: "EVP_aes_192_ctr", 32: "EVP_aes_256_ctr"}.get(len(key))
        if cipher is None or len(iv) != 16:
            raise ValueError("AES-CTR takes a 16, 24 or 32-byte key and a 16-byte IV")
        return _Cipher(self, getattr(self.c, cipher)(), key, iv)

    def aes_gcm(self, key: bytes, encrypt: bool) -> _Gcm:
        """An AES-GCM context for one direction (12-byte nonces, 16-byte tags)."""
        cipher = {16: "EVP_aes_128_gcm", 32: "EVP_aes_256_gcm"}.get(len(key))
        if cipher is None:
            raise ValueError("AES-GCM takes a 16 or 32-byte key")
        if not self.has_gcm:
            raise RuntimeError("this libcrypto has no AES-GCM")
        return _Gcm(self, getattr(self.c, cipher)(), key, encrypt)

    def chacha20(self, key: bytes) -> _Cipher:
        """A ChaCha20 context; :meth:`_Cipher.reset` sets the 16-byte counter+nonce."""
        if len(key) != 32:
            raise ValueError("ChaCha20 takes a 32-byte key")
        return _Cipher(self, self.c.EVP_chacha20(), key, bytes(16))

    def poly1305(self, key: bytes, data: bytes | bytearray | memoryview) -> bytes:
        """The Poly1305 tag; the MAC context is per thread and re-keyed per call."""
        if self._mac is None:
            raise RuntimeError("this libcrypto has no EVP_MAC Poly1305")
        c = self.c
        ctx = getattr(self._local, "ctx", None)
        if ctx is None:
            ctx = self._local.ctx = c.EVP_MAC_CTX_new(self._mac)
        payload = bytes(data)
        out = ctypes.create_string_buffer(16)
        size = ctypes.c_size_t()
        if not (
            c.EVP_MAC_init(ctx, key, len(key), None)
            and c.EVP_MAC_update(ctx, payload, len(payload))
            and c.EVP_MAC_final(ctx, out, ctypes.byref(size), 16)
        ):
            raise RuntimeError("EVP_MAC Poly1305 failed")
        return out.raw


def _passes(check: Callable[[], None]) -> bool:
    try:
        check()
    except (RuntimeError, ValueError, OSError):
        return False
    return True


_lock = threading.Lock()
_loaded: list[LibCrypto | None] = []


def _find() -> LibCrypto | None:
    for path in candidates():
        handle = _open(path)
        if handle is not None and all(hasattr(handle, name) for name in _REQUIRED):
            lib = LibCrypto(handle, path)
            if _passes(lib._ctr_known_answer):
                return lib
    return None


def load() -> LibCrypto | None:
    """The process-wide libcrypto, found once; ``None`` if there is none usable."""
    with _lock:
        if not _loaded:
            _loaded.append(_find())
        return _loaded[0]
