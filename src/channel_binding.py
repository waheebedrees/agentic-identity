from __future__ import annotations
import ctypes
import ctypes.util
import logging
import os
import ssl
import sys

log = logging.getLogger(__name__)

RFC9266_LABEL = b"EXPORTER-Channel-Binding"
RFC9266_CONTEXT = b""
RFC9266_LENGTH = 32


class ChannelBindingError(Exception):
    """No mechanism could produce a binding, or the binding failed."""

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}")
        self.code, self.detail = code, detail



def _load_openssl_windows():
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetModuleHandleW.argtypes = [ctypes.c_wchar_p]
    kernel32.GetModuleHandleW.restype = ctypes.c_void_p
    for name in ("libssl-3", "libssl-3-x64", "libssl-1_1", "libssl-1_1-x64"):
        h = kernel32.GetModuleHandleW(name)
        if h:
            return ctypes.CDLL(name, handle=h)
    raise RuntimeError("could not locate libssl in this process")


def _load_openssl_posix():
    # dlopen is idempotent for the same soname, so opening libssl here
    # returns the very handle that Python's _ssl module already loaded.
    candidates = []

    found = ctypes.util.find_library("ssl")
    if found:
        candidates.append(found)

    if sys.platform == "darwin":
        candidates += [
            "libssl.3.dylib",
            "libssl.1.1.dylib",
            "libssl.dylib",
        ]
    else:
        candidates += [
            "libssl.so.3",
            "libssl.so.1.1",
            "libssl.so",
        ]

    last_err: Exception | None = None
    for name in candidates:
        try:
            return ctypes.CDLL(name)
        except OSError as e:
            last_err = e
    raise RuntimeError(f"could not locate libssl: {last_err}")


def _load_openssl():
    if os.name == "nt":
        return _load_openssl_windows()
    return _load_openssl_posix()


# SSL* extraction from ssl.SSLSocket

# CPython's Modules/_ssl.c declares:
#
#     typedef struct {
#         PyObject_HEAD
#         PyObject *Socket;   /* weakref to the Python socket */
#         SSL *ssl;
#         ...
#     } PySSLSocket;
#
# So the SSL* sits at offset sizeof(PyObject) + sizeof(void*).

def _ssl_pointer(ssl_obj) -> int:
    inner = ssl_obj._sslobj
    head = object.__basicsize__                  # 16 on 64-bit CPython
    ptr_size = ctypes.sizeof(ctypes.c_void_p)
    ptr = ctypes.c_void_p.from_address(id(inner) + head + ptr_size).value
    if not ptr:
        raise RuntimeError("null SSL*")
    return ptr


# FFI prototypes
 

_SSL = _load_openssl()

_SSL.SSL_export_keying_material.argtypes = [
    ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t,
    ctypes.c_char_p, ctypes.c_size_t,
    ctypes.c_char_p, ctypes.c_size_t,
    ctypes.c_int,
]
_SSL.SSL_export_keying_material.restype = ctypes.c_int

_SSL.SSL_get_version.argtypes = [ctypes.c_void_p]
_SSL.SSL_get_version.restype = ctypes.c_char_p


def native_export_keying_material(
    ssl_obj,
    length: int = RFC9266_LENGTH,
    label: bytes | str = RFC9266_LABEL,
    context: bytes | str | None = RFC9266_CONTEXT,
) -> bytes:
    if isinstance(label, str):
        label = label.encode("ASCII")
    if isinstance(context, str):
        context = context.encode("ASCII")

    ptr = _ssl_pointer(ssl_obj)
    out = ctypes.create_string_buffer(length)
    use_ctx = 1 if context is not None else 0
    ctx = context or b""

    rc = _SSL.SSL_export_keying_material(
        ptr, out, length,
        label, len(label),
        ctx, len(ctx),
        use_ctx,
    )
    if rc != 1:
        raise RuntimeError(f"SSL_export_keying_material returned {rc}")
    return out.raw




