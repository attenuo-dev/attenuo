"""``tls_ca_cert``, ``tls_client_cert`` and ``tls_client_key``: the CA a client trusts for the
attenuo server's certificate, and the TLS client certificate it presents to the server (RFC 8705
``self_signed_tls_client_auth``). The rules are the ``attenuo`` CLI's ``--tls-*`` options':

- With ``tls_ca_cert``, the certificates in that file are the only roots the client trusts: the
  certifi roots httpx uses by default (and ``SSL_CERT_FILE``) are not trusted next to them.
  Hostname checks stay on; nothing here can turn verification off.
- ``tls_client_cert`` and ``tls_client_key`` go together and need an ``https://`` server URL.
  The certificate is presented on connections to the origin (scheme, host and port) of the
  server URL only: a request to any other origin goes through a second ``httpx`` client that
  has the CA but no certificate (:class:`HttpClient`, the one place that chooses). No client
  follows a redirect (SR-112), so the certificate is never carried to a ``Location`` either.
- Each file is read once, when the client is made. Anything but a regular file (a FIFO, a
  directory) is refused before it is read, and so is a file over the size limit. An error names
  the option and the path, never the file's content. A CA or certificate file that holds a
  private key is refused. ``repr`` shows paths only.

The standard library loads a client certificate from paths only (``SSLContext.load_cert_chain``),
so the two client files are read twice: once here, to check them, and once by OpenSSL.
"""

from __future__ import annotations

import base64
import binascii
import os
import re
import ssl
import stat
import warnings
from typing import Any, Union

import certifi
import httpx

#: The largest CA bundle read (a system bundle is a few hundred KiB).
MAX_CA_BYTES = 4 << 20
#: The largest client certificate or key file read.
MAX_CLIENT_BYTES = 1 << 20

#: A file path: ``str`` or ``os.PathLike``.
PathArg = Union[str, "os.PathLike[str]"]

CA = "tls_ca_cert"
CERT = "tls_client_cert"
KEY = "tls_client_key"

_BEGIN = re.compile(rb"^[ \t]*-----BEGIN ([^\r\n]*?)-----[ \t]*\r?$", re.M)
_SUPPORTED_KEYS = (b"PRIVATE KEY", b"EC PRIVATE KEY", b"RSA PRIVATE KEY")


class _NoPassword(Exception):
    """Raised by the password callback: an encrypted key is never prompted for."""


def _no_password() -> bytes:
    raise _NoPassword


def _path(option: str, value: PathArg) -> str:
    if not isinstance(value, (str, os.PathLike)):
        raise TypeError(f"{option} must be a path (str or os.PathLike)")
    p = os.fspath(value)
    if not isinstance(p, str):
        raise TypeError(f"{option} must be a str path")
    if p == "":
        raise ValueError(f"{option} is an empty path")
    return p


def _read(option: str, path: str, max_bytes: int) -> bytearray:
    """At most ``max_bytes`` of ``path``. Opened without blocking (``O_NONBLOCK``, which a regular
    file ignores), and anything but a regular file is refused, as checked on the open handle."""
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_BINARY", 0)
    try:
        fd = os.open(path, flags)
    except OSError as e:
        raise ValueError(f"cannot read {option} {path}: {e.strerror or type(e).__name__}") from None
    try:
        try:
            st = os.fstat(fd)
        except OSError as e:
            raise ValueError(f"cannot read {option} {path}: {e.strerror}") from None
        if not stat.S_ISREG(st.st_mode):
            raise ValueError(f"{option} {path} is not a regular file")
        if st.st_size > max_bytes:
            raise ValueError(f"{option} {path} is larger than {max_bytes} bytes")
        buf = bytearray()
        failed: str | None = None
        while len(buf) <= max_bytes:
            try:
                chunk = os.read(fd, min(1 << 16, max_bytes + 1 - len(buf)))
            except OSError as e:
                failed = e.strerror or type(e).__name__
                break
            if not chunk:
                break
            buf += chunk
        if failed is not None:
            _wipe(buf)
            raise ValueError(f"cannot read {option} {path}: {failed}")
    finally:
        os.close(fd)
    if len(buf) > max_bytes:
        _wipe(buf)
        raise ValueError(f"{option} {path} is larger than {max_bytes} bytes")
    if not buf.strip():
        raise ValueError(f"{option} {path} is empty")
    return buf


def _wipe(buf: bytearray) -> None:
    """Overwrite ``buf`` in place (best effort: Python may hold other copies)."""
    buf[:] = bytes(len(buf))


def _labels(data: bytearray) -> list[bytes]:
    """The labels of the PEM ``BEGIN`` lines (``CERTIFICATE``, ``PRIVATE KEY``, ...). Only
    compared, never shown: they come from the file."""
    return [m.group(1).strip() for m in _BEGIN.finditer(data)]


def _has_private_key(data: bytearray) -> bool:
    return any(label.endswith(b"PRIVATE KEY") for label in _labels(data))


def _certificates(option: str, path: str, data: bytearray) -> list[bytes] | None:
    """The DER of each ``CERTIFICATE`` block, ``None`` when a block cannot be read. Other blocks
    are skipped."""
    out: list[bytes] = []
    text = bytes(data)
    pos = 0
    while True:
        m = _BEGIN.search(text, pos)
        if m is None:
            return out
        label = m.group(1).strip()
        end = text.find(b"-----END " + label + b"-----", m.end())
        if end < 0:
            return None
        if label == b"CERTIFICATE":
            body = b"".join(text[m.end() : end].split())
            try:
                out.append(base64.b64decode(body, validate=True))
            except (binascii.Error, ValueError):
                return None
            if not out[-1]:
                return None
        pos = end


def _ca(path: str) -> str:
    """The ``tls_ca_cert`` bundle as PEM text of its certificates only."""
    data = _read(CA, path, MAX_CA_BYTES)
    if _has_private_key(data):
        _wipe(data)
        raise ValueError(f"{CA} {path} holds a private key; it must hold only the CA certificates")
    ders = _certificates(CA, path, data)
    if ders is None:
        raise ValueError(f"{CA} {path} is not a readable PEM file")
    if not ders:
        raise ValueError(f"{CA} {path} holds no PEM certificate")
    return "".join(ssl.DER_cert_to_PEM_cert(d) for d in ders)


def _check_client(cert: str, key: str) -> None:
    """Check the ``tls_client_cert`` file (certificates only, the client's first) and the
    ``tls_client_key`` file (exactly one unencrypted private key, nothing else)."""
    data = _read(CERT, cert, MAX_CLIENT_BYTES)
    if _has_private_key(data):
        _wipe(data)
        raise ValueError(
            f"{CERT} {cert} holds a private key; give the key in {KEY} and only the "
            "certificate here"
        )
    ders = _certificates(CERT, cert, data)
    labels = _labels(data)
    if ders is None or not ders or any(label != b"CERTIFICATE" for label in labels):
        raise ValueError(
            f"{CERT} {cert} must hold the client certificate in PEM (`BEGIN CERTIFICATE`) and "
            "nothing else"
        )
    data = _read(KEY, key, MAX_CLIENT_BYTES)
    try:
        labels = _labels(data)
        encrypted = b"ENCRYPTED" in data and (
            any(label.startswith(b"ENCRYPTED") for label in labels)
            or re.search(rb"^Proc-Type:[ \t]*4,[ \t]*ENCRYPTED", data, re.M) is not None
        )
        if encrypted:
            raise ValueError(
                f"{KEY} {key} is an encrypted private key; it must be unencrypted (for example "
                "`openssl pkey -in <key> -out <plain key>`, then chmod 600)"
            )
        if any(lb.endswith(b"PRIVATE KEY") and lb not in _SUPPORTED_KEYS for lb in labels):
            raise ValueError(
                f"{KEY} {key} holds a kind of private key that cannot be read; it needs PEM "
                "`BEGIN PRIVATE KEY` (PKCS#8), `BEGIN EC PRIVATE KEY` or `BEGIN RSA PRIVATE KEY`"
            )
        ends = len(re.findall(rb"-----END ", data))
        if len(labels) != 1 or labels[0] not in _SUPPORTED_KEYS or ends != 1:
            raise ValueError(
                f"{KEY} {key} must hold exactly one unencrypted private key in PEM (`BEGIN "
                "PRIVATE KEY`, `BEGIN EC PRIVATE KEY` or `BEGIN RSA PRIVATE KEY`) and nothing else"
            )
    finally:
        _wipe(data)


def _context(cadata: str | None) -> ssl.SSLContext:
    """A client context with the standard library's strict defaults (certificate and hostname
    checks on, TLS 1.2 or newer): trusting ``cadata`` only, or without it the roots httpx
    trusts by default (``SSL_CERT_FILE``, else ``SSL_CERT_DIR``, else certifi's bundle)."""
    if cadata is not None:
        return ssl.create_default_context(cadata=cadata)
    if os.environ.get("SSL_CERT_FILE"):
        return ssl.create_default_context(cafile=os.environ["SSL_CERT_FILE"])
    if os.environ.get("SSL_CERT_DIR"):
        return ssl.create_default_context(capath=os.environ["SSL_CERT_DIR"])
    return ssl.create_default_context(cafile=certifi.where())


def origin(url: httpx.URL | str) -> tuple[str, str, int | None]:
    """The origin of ``url``: scheme, host and port, the default port filled in."""
    u = httpx.URL(url)
    scheme = u.scheme.lower()
    port = u.port if u.port is not None else {"http": 80, "https": 443}.get(scheme)
    return scheme, u.host.lower(), port


class TlsSettings:
    """The ``tls_*`` options of one client, read and checked: an ``ssl.SSLContext`` for the
    server's origin (with the client certificate when one is given) and one for every other
    origin (never with it)."""

    __slots__ = ("_other", "_server", "ca_cert", "client_cert", "client_key", "origin")

    def __init__(
        self,
        server_url: str,
        ca_cert: PathArg | None,
        client_cert: PathArg | None = None,
        client_key: PathArg | None = None,
    ) -> None:
        # The pairing is checked before any file is read.
        if client_cert is not None and client_key is None:
            raise ValueError(f"{CERT} needs {KEY}: the private key of the certificate")
        if client_key is not None and client_cert is None:
            raise ValueError(f"{KEY} needs {CERT}: the certificate of the key")
        self.ca_cert = None if ca_cert is None else _path(CA, ca_cert)
        self.client_cert = None if client_cert is None else _path(CERT, client_cert)
        self.client_key = None if client_key is None else _path(KEY, client_key)
        https = server_url.lower().startswith("https://")
        if self.client_cert is not None and not https:
            raise ValueError(
                f"{CERT} and {KEY} need an https:// server URL; a client certificate cannot be "
                "sent over plain HTTP"
            )
        self.origin = origin(server_url)
        cadata = None if self.ca_cert is None else _ca(self.ca_cert)
        try:
            other: ssl.SSLContext | None = _context(cadata)
        except (ssl.SSLError, OSError, ValueError):
            other = None
        if other is None:
            if self.ca_cert is None:
                raise ValueError(
                    "cannot load the default CA certificates (SSL_CERT_FILE, SSL_CERT_DIR)"
                )
            raise ValueError(f"{CA} {self.ca_cert}: a certificate in it cannot be used as a CA")
        self._other = other
        self._server = other
        if self.client_cert is not None and self.client_key is not None:
            _check_client(self.client_cert, self.client_key)
            server = _context(cadata)
            loaded = False
            try:
                server.load_cert_chain(self.client_cert, self.client_key, password=_no_password)
                loaded = True
            except (ssl.SSLError, OSError, _NoPassword, ValueError):
                pass
            # Raised outside the handler, so no OpenSSL error is chained to it.
            if not loaded:
                raise ValueError(
                    f"{KEY} {self.client_key} is not the private key of the certificate in "
                    f"{CERT} {self.client_cert}, or they cannot be used as a client certificate"
                )
            self._server = server
        if self.ca_cert is not None and not https:
            warnings.warn(
                f"{CA} is set, but the server URL is not https://, so it is not used",
                UserWarning,
                stacklevel=4,
            )

    @property
    def has_client_cert(self) -> bool:
        return self.client_cert is not None

    @property
    def server_context(self) -> ssl.SSLContext:
        """The context for the server's origin: with the client certificate when one is set."""
        return self._server

    @property
    def other_context(self) -> ssl.SSLContext:
        """The context for every other origin: the same trust, never a client certificate."""
        return self._other

    def is_server_origin(self, url: httpx.URL | str) -> bool:
        return origin(url) == self.origin

    def __repr__(self) -> str:
        cert = None if self.client_cert is None else (self.client_cert, self.client_key)
        return f"TlsSettings(ca_cert={self.ca_cert!r}, client_cert={cert!r})"


def settings(
    server_url: str,
    ca_cert: PathArg | None,
    client_cert: PathArg | None = None,
    client_key: PathArg | None = None,
    transport: Any = None,
) -> TlsSettings | None:
    """The :class:`TlsSettings` of a client, ``None`` when no option is given."""
    if ca_cert is None and client_cert is None and client_key is None:
        return None
    if transport is not None:
        # A transport brings its own TLS setup; the options would silently not apply.
        raise ValueError("pass either transport or the tls_* options, not both")
    return TlsSettings(server_url, ca_cert, client_cert, client_key)
