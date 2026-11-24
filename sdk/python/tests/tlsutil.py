"""Certificates made at test time, and a local TLS server that records the client certificate
it was shown. Nothing here touches the network beyond 127.0.0.1."""

from __future__ import annotations

import datetime as dt
import hashlib
import http.server
import ipaddress
import json
import ssl
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

PEM = serialization.Encoding.PEM


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _key_pem(key: ec.EllipticCurvePrivateKey) -> bytes:
    return key.private_bytes(PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


def _dates(b: x509.CertificateBuilder) -> x509.CertificateBuilder:
    now = dt.datetime.now(dt.timezone.utc)
    return b.not_valid_before(now - dt.timedelta(days=1)).not_valid_after(
        now + dt.timedelta(days=30)
    )


class Ca:
    """A CA that signs server and client certificates: a root, or an intermediate under
    ``issuer``."""

    key: ec.EllipticCurvePrivateKey
    cert: x509.Certificate

    def __init__(self, name: str, issuer: Ca | None = None) -> None:
        self.key = ec.generate_private_key(ec.SECP256R1())
        pub = self.key.public_key()
        b = (
            _dates(x509.CertificateBuilder())
            .subject_name(_name(name))
            .issuer_name(issuer.cert.subject if issuer else _name(name))
            .public_key(pub)
            .serial_number(x509.random_serial_number())
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(pub), critical=False)
        )
        if issuer is not None:
            b = b.add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer.key.public_key()), False
            )
        self.cert = b.sign(issuer.key if issuer else self.key, hashes.SHA256())
        self.pem = self.cert.public_bytes(PEM)

    def client(self, uri: str) -> tuple[bytes, bytes]:
        """A client certificate (``CA:FALSE``, ``clientAuth``) whose SAN is ``uri``, and its
        key, as PEM."""
        key = ec.generate_private_key(ec.SECP256R1())
        b = (
            _dates(x509.CertificateBuilder())
            .subject_name(_name(uri.rsplit("/", 1)[-1]))
            .issuer_name(self.cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.SubjectAlternativeName([x509.UniformResourceIdentifier(uri)]), False
            )
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), False)
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(self.key.public_key()), False
            )
        )
        return b.sign(self.key, hashes.SHA256()).public_bytes(PEM), _key_pem(key)

    def leaf(self, names: list[str]) -> tuple[bytes, bytes]:
        """A server certificate for ``names`` (IP addresses or DNS names) and its key, as PEM."""
        key = ec.generate_private_key(ec.SECP256R1())
        sans: list[x509.GeneralName] = []
        for n in names:
            try:
                sans.append(x509.IPAddress(ipaddress.ip_address(n)))
            except ValueError:
                sans.append(x509.DNSName(n))
        b = (
            _dates(x509.CertificateBuilder())
            .subject_name(_name(names[0]))
            .issuer_name(self.cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.SubjectAlternativeName(sans), critical=False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False)
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(self.key.public_key()), False
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
            )
        )
        cert = b.sign(self.key, hashes.SHA256())
        return cert.public_bytes(PEM), _key_pem(key)


class ClientCert:
    """A self-signed client certificate (``CA:FALSE``, ``clientAuth``), as attenuo pins them."""

    def __init__(self, name: str) -> None:
        self.key = ec.generate_private_key(ec.SECP256R1())
        pub = self.key.public_key()
        b = (
            _dates(x509.CertificateBuilder())
            .subject_name(_name(name))
            .issuer_name(_name(name))
            .public_key(pub)
            .serial_number(x509.random_serial_number())
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(pub), critical=False)
        )
        self.cert = b.sign(self.key, hashes.SHA256())
        self.pem = self.cert.public_bytes(PEM)
        self.key_pem = _key_pem(self.key)
        self.der = self.cert.public_bytes(serialization.Encoding.DER)
        #: What ``tls_client_cert_sha256`` pins: lower-case hex SHA-256 of the DER.
        self.sha256 = hashlib.sha256(self.der).hexdigest()

    def write(self, d: Path, name: str) -> tuple[Path, Path]:
        c, k = d / f"{name}.crt", d / f"{name}.key"
        c.write_bytes(self.pem)
        k.write_bytes(self.key_pem)
        k.chmod(0o600)
        return c, k


class _Handler(http.server.BaseHTTPRequestHandler):
    server: TlsServer

    def _answer(self) -> None:
        sock: Any = self.connection
        n = int(self.headers.get("content-length") or 0)
        body = self.rfile.read(n) if n else b""
        self.server.seen.append(
            {
                "path": self.path,
                "peer_cert": sock.getpeercert(binary_form=True),
                "body": body,
            }
        )
        status, payload = self.server.answer
        data = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    do_GET = _answer
    do_POST = _answer

    def log_message(self, format: str, *args: Any) -> None:
        pass


class TlsServer(http.server.ThreadingHTTPServer):
    """An HTTPS server on 127.0.0.1 (a port the kernel picks, kept bound) that asks every client
    for a certificate (``CERT_OPTIONAL``, trusting ``client_ca``) and records what it saw."""

    daemon_threads = True

    def __init__(self, cert: bytes, key: bytes, d: Path, client_ca: bytes | None) -> None:
        super().__init__(("127.0.0.1", 0), _Handler)
        self.seen: list[dict[str, Any]] = []
        self.answer: tuple[int, Any] = (200, {"ok": True})
        crt, k = d / f"srv{id(self)}.crt", d / f"srv{id(self)}.key"
        crt.write_bytes(cert)
        k.write_bytes(key)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(crt, k)
        if client_ca is not None:
            ctx.verify_mode = ssl.CERT_OPTIONAL
            ctx.load_verify_locations(cadata=client_ca.decode())
        self.socket = ctx.wrap_socket(self.socket, server_side=True)

    @property
    def url(self) -> str:
        return f"https://127.0.0.1:{self.server_address[1]}"

    def handle_error(self, request: Any, client_address: Any) -> None:
        pass


@contextmanager
def tls_server(
    ca: Ca, d: Path, names: list[str] | None = None, client_ca: bytes | None = None
) -> Iterator[TlsServer]:
    cert, key = ca.leaf(names or ["127.0.0.1"])
    srv = TlsServer(cert, key, d, client_ca)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        yield srv
    finally:
        srv.shutdown()
        srv.server_close()
        t.join()
