"""``tls_ca_cert``, ``tls_client_cert`` and ``tls_client_key`` over real TLS on 127.0.0.1.

Each test makes its certificates and starts its own HTTPS servers on ports the kernel picks
(kept bound), so nothing reaches the network and no test waits on a timer."""

from __future__ import annotations

import contextlib
import json
import os
import socket
import sys
import threading
import warnings
from pathlib import Path

import httpx
import pytest
from cryptography.hazmat.primitives import serialization

from attenuo import (
    AdminClient,
    ApiError,
    AsyncAdminClient,
    AsyncClient,
    Capability,
    Client,
    TransportError,
)
from attenuo import _wire as w
from attenuo._tls import MAX_CA_BYTES, TlsSettings

from .helpers import Signer
from .tlsutil import Ca, ClientCert, tls_server

# A delegation token (the servers below never check it).
PARENT = Signer().mint()


@pytest.fixture
def ca() -> Ca:
    return Ca("test-ca")


@pytest.fixture
def client_cert() -> ClientCert:
    return ClientCert("planner")


def write(p: Path, data: bytes | str) -> Path:
    p.write_bytes(data.encode() if isinstance(data, str) else data)
    return p


def key_chunks(cc: ClientCert) -> list[str]:
    body = "".join(
        line for line in cc.key_pem.decode().splitlines() if not line.startswith("-----")
    )
    return [body[i : i + 12] for i in range(0, len(body) - 12, 12)]


def no_key_bytes(text: str, cc: ClientCert) -> None:
    for chunk in key_chunks(cc):
        assert chunk not in text, text


# -- trust --


def test_the_given_ca_is_trusted_and_nothing_else(tmp_path: Path, ca: Ca) -> None:
    ca_file = write(tmp_path / "ca.pem", ca.pem)
    other = Ca("other-ca")
    with tls_server(ca, tmp_path) as good, tls_server(other, tmp_path) as bad:
        with Client(good.url, tls_ca_cert=ca_file) as c:
            c._http.get("/healthz").raise_for_status()
        with Client(bad.url, tls_ca_cert=ca_file) as c, pytest.raises(TransportError) as e:
            c._http.get("/healthz")
        assert "CERTIFICATE_VERIFY_FAILED" in str(e.value)
    # Only the one CA is in the trust store: no system or certifi roots next to it.
    s = TlsSettings(good.url, ca_file)
    assert len(s.server_context.get_ca_certs()) == 1
    assert len(s.other_context.get_ca_certs()) == 1


def test_ssl_cert_file_is_not_trusted_next_to_the_ca(
    tmp_path: Path, ca: Ca, monkeypatch: pytest.MonkeyPatch
) -> None:
    """httpx trusts ``SSL_CERT_FILE`` by default; with ``tls_ca_cert`` it must not."""
    other = Ca("other-ca")
    monkeypatch.setenv("SSL_CERT_FILE", str(write(tmp_path / "other.pem", other.pem)))
    ca_file = write(tmp_path / "ca.pem", ca.pem)
    with tls_server(other, tmp_path) as srv:
        # Without the option, the environment's CA is trusted (httpx's own behaviour)...
        with Client(srv.url) as c:
            c._http.get("/healthz").raise_for_status()
        # ...with it, only the option's CA is.
        with Client(srv.url, tls_ca_cert=ca_file) as c, pytest.raises(TransportError):
            c._http.get("/healthz")
        # A client certificate alone keeps httpx's default roots, the environment's included.
        crt, key = ClientCert("planner").write(tmp_path, "planner")
        with Client(srv.url, tls_client_cert=crt, tls_client_key=key) as c:
            c._http.get("/healthz").raise_for_status()


def test_a_hostname_mismatch_is_refused(tmp_path: Path, ca: Ca) -> None:
    ca_file = write(tmp_path / "ca.pem", ca.pem)
    with tls_server(ca, tmp_path, names=["other.test"]) as srv:
        with Client(srv.url, tls_ca_cert=ca_file) as c, pytest.raises(TransportError) as e:
            c._http.get("/healthz")
        assert "CERTIFICATE_VERIFY_FAILED" in str(e.value)
    s = TlsSettings(srv.url, ca_file)
    assert s.server_context.check_hostname and s.other_context.check_hostname


def test_the_admin_client_takes_the_ca(tmp_path: Path, ca: Ca) -> None:
    ca_file = write(tmp_path / "ca.pem", ca.pem)
    with tls_server(ca, tmp_path) as srv:
        srv.answer = (200, {"subject": "urn:attenuo:admin", "kind": "token"})
        with AdminClient(srv.url, "t", tls_ca_cert=ca_file) as admin:
            admin._http.get("/admin/whoami").raise_for_status()
        other = write(tmp_path / "o.pem", Ca("o").pem)
        with AdminClient(srv.url, "t", tls_ca_cert=other) as a, pytest.raises(TransportError):
            a._http.get("/admin/whoami")


# -- the client certificate, per origin --


def test_the_certificate_goes_to_the_server_origin_only(
    tmp_path: Path, ca: Ca, client_cert: ClientCert
) -> None:
    ca_file = write(tmp_path / "ca.pem", ca.pem)
    crt, key = client_cert.write(tmp_path, "planner")
    # Both servers ask for a client certificate and would accept this one.
    with (
        tls_server(ca, tmp_path, client_ca=client_cert.pem) as server,
        tls_server(ca, tmp_path, client_ca=client_cert.pem) as elsewhere,
    ):
        with Client(server.url, tls_ca_cert=ca_file, tls_client_cert=crt, tls_client_key=key) as c:
            c._http.get("/healthz").raise_for_status()
            # Another origin (another port), named by a full URL: the same client sends no
            # certificate there, whatever the path.
            c._http.get(f"{elsewhere.url}/healthz").raise_for_status()
            c._http.get(f"{elsewhere.url}/token").raise_for_status()
        assert server.seen[0]["peer_cert"] == client_cert.der
        assert [s["peer_cert"] for s in elsewhere.seen] == [None, None]


async def test_the_async_client_keeps_the_certificate_to_the_server_origin(
    tmp_path: Path, ca: Ca, client_cert: ClientCert
) -> None:
    ca_file = write(tmp_path / "ca.pem", ca.pem)
    crt, key = client_cert.write(tmp_path, "planner")
    with (
        tls_server(ca, tmp_path, client_ca=client_cert.pem) as server,
        tls_server(ca, tmp_path, client_ca=client_cert.pem) as elsewhere,
    ):
        async with AsyncClient(
            server.url, tls_ca_cert=ca_file, tls_client_cert=crt, tls_client_key=key
        ) as c:
            (await c._http.get("/healthz")).raise_for_status()
            (await c._http.get(f"{elsewhere.url}/healthz")).raise_for_status()
        assert server.seen[0]["peer_cert"] == client_cert.der
        assert elsewhere.seen[0]["peer_cert"] is None


def test_the_other_origin_still_trusts_only_the_ca(
    tmp_path: Path, ca: Ca, client_cert: ClientCert
) -> None:
    ca_file = write(tmp_path / "ca.pem", ca.pem)
    crt, key = client_cert.write(tmp_path, "planner")
    with (
        tls_server(ca, tmp_path) as server,
        tls_server(Ca("x"), tmp_path) as elsewhere,
        Client(server.url, tls_ca_cert=ca_file, tls_client_cert=crt, tls_client_key=key) as c,
        pytest.raises(TransportError),
    ):
        c._http.get(f"{elsewhere.url}/healthz")


def test_origins_compare_scheme_host_and_port() -> None:
    from attenuo._tls import origin

    assert origin("https://A.test/x") == origin("https://a.test:443/y")
    assert origin("https://a.test") != origin("https://a.test:8443")
    assert origin("https://a.test") != origin("http://a.test")
    assert origin("https://a.test") != origin("https://b.test")
    assert origin("https://127.0.0.1:8443/pfx") == ("https", "127.0.0.1", 8443)


def test_a_redirect_is_not_followed_with_the_certificate(
    tmp_path: Path, ca: Ca, client_cert: ClientCert
) -> None:
    ca_file = write(tmp_path / "ca.pem", ca.pem)
    crt, key = client_cert.write(tmp_path, "planner")
    with (
        tls_server(ca, tmp_path, client_ca=client_cert.pem) as server,
        tls_server(ca, tmp_path, client_ca=client_cert.pem) as elsewhere,
    ):
        server.answer = (307, {})
        with Client(server.url, tls_ca_cert=ca_file, tls_client_cert=crt, tls_client_key=key) as c:
            with pytest.raises(ApiError) as e:
                c.exchange(PARENT, "planner", [Capability("github", "read_file")])
            assert e.value.error == "redirect_not_followed"
        assert elsewhere.seen == []


# -- token exchange with the certificate --


def test_exchange_with_the_certificate_sends_client_id_and_no_secret(
    tmp_path: Path, ca: Ca, client_cert: ClientCert
) -> None:
    ca_file = write(tmp_path / "ca.pem", ca.pem)
    crt, key = client_cert.write(tmp_path, "planner")
    with tls_server(ca, tmp_path, client_ca=client_cert.pem) as server:
        server.answer = (401, {"error": "client_authentication_failed"})
        with Client(server.url, tls_ca_cert=ca_file, tls_client_cert=crt, tls_client_key=key) as c:
            with pytest.raises(ApiError):
                c.exchange(PARENT, "planner", [Capability("github", "read_file")])
            with pytest.raises(ApiError):
                c.exchange(PARENT, "planner", "github:*", client_id="planner-2")
            with pytest.raises(ApiError):
                c.exchange(PARENT, "planner", "github:*", client_secret="s3")
            with pytest.raises(ApiError):
                c.exchange(PARENT, "planner", "github:*", actor_token="a.b.c")
    bodies = [json.loads(s["body"]) for s in server.seen]
    assert all(s["peer_cert"] == client_cert.der for s in server.seen)
    assert bodies[0]["client_id"] == "planner" and "client_secret" not in bodies[0]
    assert bodies[1]["client_id"] == "planner-2" and "client_secret" not in bodies[1]
    # A secret is sent as before; next to an actor token no client_id is sent.
    assert bodies[2]["client_id"] == "planner" and bodies[2]["client_secret"] == "s3"
    assert "client_id" not in bodies[3] and bodies[3]["actor_token"] == "a.b.c"


def test_exchange_body_by_certificate() -> None:
    caps = [Capability("github", "read_file")]
    b = w.exchange_body(PARENT, "planner", caps, None, None, None, None, client_cert=True)
    assert b["client_id"] == "planner" and "client_secret" not in b
    assert b["subject_token_type"] == w.TYPE_JWT
    # Hop 0 (an IdP token, not a delegation token): the certificate authenticates, so the
    # subject is an ID token as with a secret.
    b = w.exchange_body("not-a-jwt", "planner", caps, None, None, None, None, client_cert=True)
    assert b["subject_token_type"] == w.TYPE_ID_TOKEN
    b = w.exchange_body(PARENT, "p", caps, None, None, None, None, client_assertion="a.b.c")
    assert "client_secret" not in b
    # Without a certificate nothing changes: a client_id alone is an error, none is sent.
    b = w.exchange_body(PARENT, "planner", caps, None, None, None, None)
    assert "client_id" not in b
    with pytest.raises(ValueError, match="client_id goes with"):
        w.exchange_body(PARENT, "planner", caps, None, "planner", None, None)
    with pytest.raises(ValueError, match="client_id goes with"):
        w.exchange_body(
            PARENT, "planner", caps, None, "x", None, None, actor_token="a.b.c", client_cert=True
        )


# -- refusals at construction --


def test_cert_and_key_go_together(tmp_path: Path) -> None:
    missing = tmp_path / "missing.pem"
    with pytest.raises(ValueError, match=r"^tls_client_cert needs tls_client_key"):
        Client("https://a.test", tls_client_cert=missing)
    with pytest.raises(ValueError, match=r"^tls_client_key needs tls_client_cert"):
        AsyncClient("https://a.test", tls_client_key=missing)


def test_a_client_certificate_needs_https(tmp_path: Path, client_cert: ClientCert) -> None:
    crt, key = client_cert.write(tmp_path, "planner")
    for url in ("http://a.test", "http://127.0.0.1:8080"):
        with pytest.raises(ValueError, match="need an https:// server URL"):
            Client(url, tls_client_cert=crt, tls_client_key=key)
        with pytest.raises(ValueError, match="need an https:// server URL"):
            AsyncClient(url, tls_client_cert=crt, tls_client_key=key)


def test_a_ca_with_an_http_server_warns(tmp_path: Path, ca: Ca) -> None:
    ca_file = write(tmp_path / "ca.pem", ca.pem)
    with pytest.warns(UserWarning, match="tls_ca_cert is set, but the server URL is not https"):
        Client("http://a.test", tls_ca_cert=ca_file).close()
    with pytest.warns(UserWarning, match="tls_ca_cert"):
        AdminClient("http://a.test", "t", tls_ca_cert=ca_file).close()
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        Client("https://a.test", tls_ca_cert=ca_file).close()


def test_a_transport_and_tls_options_are_refused(tmp_path: Path, ca: Ca) -> None:
    ca_file = write(tmp_path / "ca.pem", ca.pem)
    mock = httpx.MockTransport(lambda r: httpx.Response(200))
    with pytest.raises(ValueError, match="transport or the tls_"):
        Client("https://a.test", transport=mock, tls_ca_cert=ca_file)
    with pytest.raises(ValueError, match="transport or the tls_"):
        AdminClient("https://a.test", "t", transport=mock, tls_ca_cert=ca_file)


def test_a_private_key_in_the_ca_or_certificate_file_is_refused(
    tmp_path: Path, ca: Ca, client_cert: ClientCert
) -> None:
    _, key = client_cert.write(tmp_path, "planner")
    both = write(tmp_path / "both.pem", client_cert.pem + client_cert.key_pem)
    for f in (both, key):
        with pytest.raises(ValueError, match="holds a private key") as e:
            Client("https://a.test", tls_ca_cert=f)
        no_key_bytes(str(e.value), client_cert)
    with pytest.raises(ValueError, match="holds a private key"):
        Client("https://a.test", tls_client_cert=both, tls_client_key=key)
    for label in ("ENCRYPTED PRIVATE KEY", "OPENSSH PRIVATE KEY", "DSA PRIVATE KEY"):
        odd = write(
            tmp_path / "odd.pem",
            ca.pem + f"-----BEGIN {label}-----\nU0VDUkVU\n-----END {label}-----\n".encode(),
        )
        with pytest.raises(ValueError, match="holds a private key"):
            Client("https://a.test", tls_ca_cert=odd)


def test_the_key_file_holds_one_unencrypted_key(
    tmp_path: Path, ca: Ca, client_cert: ClientCert
) -> None:
    crt, _ = client_cert.write(tmp_path, "planner")
    other = ClientCert("other")
    two = write(tmp_path / "two.pem", client_cert.key_pem + other.key_pem)
    both = write(tmp_path / "both.pem", client_cert.pem + client_cert.key_pem)
    for bad in (two, both, crt):
        with pytest.raises(ValueError, match="exactly one unencrypted private key"):
            Client("https://a.test", tls_client_cert=crt, tls_client_key=bad)
    enc = serialization.BestAvailableEncryption(b"pw")
    for fmt in (serialization.PrivateFormat.PKCS8, serialization.PrivateFormat.TraditionalOpenSSL):
        f = write(
            tmp_path / "enc.pem",
            client_cert.key.private_bytes(serialization.Encoding.PEM, fmt, enc),
        )
        # Refused before OpenSSL could ask for a password on the terminal.
        with pytest.raises(ValueError, match="is an encrypted private key"):
            Client("https://a.test", tls_client_cert=crt, tls_client_key=f)
    ossh = write(
        tmp_path / "ossh.pem",
        "-----BEGIN OPENSSH PRIVATE KEY-----\nU0VDUkVU\n-----END OPENSSH PRIVATE KEY-----\n",
    )
    with pytest.raises(ValueError, match="kind of private key") as e:
        Client("https://a.test", tls_client_cert=crt, tls_client_key=ossh)
    assert "U0VDUkVU" not in str(e.value)
    # A key that is not the certificate's.
    _, other_key = other.write(tmp_path, "other")
    with pytest.raises(ValueError, match="is not the private key of the certificate") as e:
        Client("https://a.test", tls_client_cert=crt, tls_client_key=other_key)
    assert e.value.__cause__ is None and e.value.__context__ is None
    no_key_bytes(str(e.value), other)


def test_unreadable_empty_and_unparsable_files(tmp_path: Path, client_cert: ClientCert) -> None:
    crt, key = client_cert.write(tmp_path, "planner")
    missing = tmp_path / "missing.pem"
    empty = write(tmp_path / "empty.pem", " \n\n")
    secret = "-----BEGIN CERTIFICATE-----\nS3CR3T!!!***\n-----END CERTIFICATE-----\n"
    broken = write(tmp_path / "broken.pem", secret)
    text = write(tmp_path / "text.pem", "hello SECRETSECRET\n")
    with pytest.raises(ValueError, match=r"^cannot read tls_ca_cert .*missing.pem"):
        Client("https://a.test", tls_ca_cert=missing)
    with pytest.raises(ValueError, match=r"^tls_ca_cert .* is empty$"):
        Client("https://a.test", tls_ca_cert=empty)
    with pytest.raises(ValueError, match=r"^cannot read tls_client_key "):
        Client("https://a.test", tls_client_cert=crt, tls_client_key=missing)
    with pytest.raises(ValueError, match=r"^tls_client_key .* is empty$"):
        Client("https://a.test", tls_client_cert=crt, tls_client_key=empty)
    for bad in (broken, text):
        for kwargs in (
            {"tls_ca_cert": bad},
            {"tls_client_cert": bad, "tls_client_key": key},
            {"tls_client_cert": crt, "tls_client_key": bad},
        ):
            with pytest.raises(ValueError) as e:
                Client("https://a.test", **kwargs)  # type: ignore[arg-type]
            msg = str(e.value)
            assert "S3CR3T" not in msg and "SECRET" not in msg, msg
            assert msg.startswith(("tls_", "cannot read tls_")), msg
    with pytest.raises(ValueError, match="tls_ca_cert is an empty path"):
        Client("https://a.test", tls_ca_cert="")


def test_a_large_file_is_refused(tmp_path: Path) -> None:
    big = tmp_path / "big.pem"
    with big.open("wb") as f:
        f.truncate(MAX_CA_BYTES + 1)
    with pytest.raises(ValueError, match="is larger than"):
        Client("https://a.test", tls_ca_cert=big)


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX FIFOs")
def test_a_fifo_or_a_directory_is_refused_without_blocking(
    tmp_path: Path, client_cert: ClientCert
) -> None:
    crt, _ = client_cert.write(tmp_path, "planner")
    fifo = tmp_path / "fifo.pem"
    os.mkfifo(fifo)
    # Nothing ever writes to the FIFO: a blocking open would hang the test.
    with pytest.raises(ValueError, match="is not a regular file"):
        Client("https://a.test", tls_ca_cert=fifo)
    with pytest.raises(ValueError, match=r"^tls_client_key .* is not a regular file"):
        Client("https://a.test", tls_client_cert=crt, tls_client_key=fifo)
    with pytest.raises(ValueError, match=r"^tls_client_cert .* is not a regular file"):
        Client("https://a.test", tls_client_cert=fifo, tls_client_key=fifo)
    with pytest.raises(ValueError, match=r"is not a regular file|cannot read"):
        AsyncAdminClient("https://a.test", "t", tls_ca_cert=tmp_path)


def test_repr_shows_paths_and_no_key(tmp_path: Path, ca: Ca, client_cert: ClientCert) -> None:
    ca_file = write(tmp_path / "ca.pem", ca.pem)
    crt, key = client_cert.write(tmp_path, "planner")
    with Client(
        "https://a.test", tls_ca_cert=ca_file, tls_client_cert=crt, tls_client_key=key
    ) as c:
        tls = c._http._tls
        assert tls is not None
        for text in (repr(tls), repr(c), repr(c._http), repr(vars(c))):
            no_key_bytes(text, client_cert)
        assert "planner.key" in repr(tls)


# -- review follow-ups --


@pytest.mark.skipif(not hasattr(os, "memfd_create"), reason="Linux memory files")
def test_the_checked_bytes_are_loaded_not_the_files_again(
    tmp_path: Path, ca: Ca, client_cert: ClientCert, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Between the checks and the load, the files are replaced by another pair (a key that
    must be refused, then a FIFO): the client loads what it checked."""
    from attenuo import _tls

    ca_file = write(tmp_path / "ca.pem", ca.pem)
    crt, key = client_cert.write(tmp_path, "planner")
    other = ClientCert("other")

    def swap() -> None:
        crt.write_bytes(other.pem)
        key.unlink()
        os.mkfifo(key)  # a load by path would block here

    monkeypatch.setattr(_tls, "_before_load", swap)
    with tls_server(ca, tmp_path, client_ca=client_cert.pem) as server:
        with Client(server.url, tls_ca_cert=ca_file, tls_client_cert=crt, tls_client_key=key) as c:
            c._http.get("/healthz").raise_for_status()
        assert server.seen[0]["peer_cert"] == client_cert.der


@pytest.mark.parametrize("ws", ["\f", "\v"])
def test_a_begin_line_with_other_white_space_hides_no_key(
    tmp_path: Path, ca: Ca, client_cert: ClientCert, ws: str
) -> None:
    hidden_key = client_cert.key_pem.decode().replace(
        "-----BEGIN PRIVATE KEY-----", f"-----BEGIN PRIVATE KEY-----{ws}"
    )
    hidden = write(tmp_path / "hidden.pem", client_cert.pem.decode() + hidden_key)
    _, key = client_cert.write(tmp_path, "planner")
    with pytest.raises(ValueError, match="holds a private key"):
        Client("https://a.test", tls_ca_cert=hidden)
    with pytest.raises(ValueError, match="holds a private key"):
        Client("https://a.test", tls_client_cert=hidden, tls_client_key=key)
    # Such a line in the key file is still read as the one key.
    spaced = write(tmp_path / "spaced.key", hidden_key)
    crt, _ = client_cert.write(tmp_path, "planner2")
    Client("https://a.test", tls_client_cert=crt, tls_client_key=spaced).close()


def test_a_begin_line_that_is_not_read_is_refused(tmp_path: Path, ca: Ca) -> None:
    odd = write(
        tmp_path / "odd.pem",
        ca.pem + b"-----BEGIN CERTIFICATE-----junk\nAAAA\n-----END CERTIFICATE-----\n",
    )
    with pytest.raises(ValueError, match="is not a readable PEM file"):
        Client("https://a.test", tls_ca_cert=odd)


def test_lone_cr_line_ends_and_non_ascii_space_are_refused(
    tmp_path: Path, ca: Ca, client_cert: ClientCert
) -> None:
    # The same rules as the TypeScript SDK: lines end in \n or \r\n, and only
    # ASCII white space may stand around a BEGIN line.
    _, key = client_cert.write(tmp_path, "planner")
    lone_cr = write(tmp_path / "cr.pem", client_cert.pem.replace(b"\n", b"\r"))
    nbsp = write(
        tmp_path / "nbsp.pem",
        client_cert.pem.replace(b"CERTIFICATE-----\n", b"CERTIFICATE-----\xc2\xa0\n", 1),
    )
    for bad in (lone_cr, nbsp):
        with pytest.raises(ValueError, match="is not a readable PEM file"):
            Client("https://a.test", tls_ca_cert=bad)
        with pytest.raises(ValueError, match="must hold the client certificate in PEM"):
            Client("https://a.test", tls_client_cert=bad, tls_client_key=key)
    for name, data in (
        ("cr-key.pem", client_cert.pem + client_cert.key_pem.replace(b"\n", b"\r")),
        (
            "nbsp-key.pem",
            client_cert.pem + client_cert.key_pem.replace(b"KEY-----\n", b"KEY-----\xc2\xa0\n", 1),
        ),
    ):
        hidden = write(tmp_path / name, data)
        with pytest.raises(ValueError, match="holds a private key"):
            Client("https://a.test", tls_ca_cert=hidden)
        with pytest.raises(ValueError, match="holds a private key"):
            Client("https://a.test", tls_client_cert=hidden, tls_client_key=key)


class ConnectProxy:
    """A local HTTP CONNECT proxy that records the targets it tunnels to."""

    def __init__(self) -> None:
        self.targets: list[str] = []
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen()
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.sock.getsockname()[1]}"

    def _serve(self) -> None:
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._tunnel, args=(conn,), daemon=True).start()

    def _tunnel(self, conn: socket.socket) -> None:
        head = b""
        while b"\r\n\r\n" not in head:
            chunk = conn.recv(4096)
            if not chunk:
                conn.close()
                return
            head += chunk
        target = head.split(b" ")[1].decode()
        self.targets.append(target)
        host, port = target.rsplit(":", 1)
        up = socket.create_connection((host, int(port)))
        conn.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")

        def pipe(a: socket.socket, b: socket.socket) -> None:
            try:
                while data := a.recv(65536):
                    b.sendall(data)
            except OSError:
                pass
            finally:
                for s in (a, b):
                    with contextlib.suppress(OSError):
                        s.shutdown(socket.SHUT_RDWR)

        threading.Thread(target=pipe, args=(up, conn), daemon=True).start()
        pipe(conn, up)

    def close(self) -> None:
        self.sock.close()


@pytest.mark.parametrize("var", ["HTTPS_PROXY", "ALL_PROXY"])
def test_through_a_connect_proxy_only_the_server_tunnel_carries_the_certificate(
    tmp_path: Path, ca: Ca, client_cert: ClientCert, monkeypatch: pytest.MonkeyPatch, var: str
) -> None:
    for name in ("HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy", "NO_PROXY", "no_proxy"):
        monkeypatch.delenv(name, raising=False)
    proxy = ConnectProxy()
    monkeypatch.setenv(var, proxy.url)
    ca_file = write(tmp_path / "ca.pem", ca.pem)
    crt, key = client_cert.write(tmp_path, "planner")
    try:
        with (
            tls_server(ca, tmp_path, client_ca=client_cert.pem) as server,
            tls_server(ca, tmp_path, client_ca=client_cert.pem) as elsewhere,
        ):
            with Client(
                server.url, tls_ca_cert=ca_file, tls_client_cert=crt, tls_client_key=key
            ) as c:
                c._http.get("/healthz").raise_for_status()
                c._http.get(f"{elsewhere.url}/healthz").raise_for_status()
            assert server.seen[0]["peer_cert"] == client_cert.der
            assert elsewhere.seen[0]["peer_cert"] is None
            # Both went through the proxy.
            ports = {t.rsplit(":", 1)[1] for t in proxy.targets}
            assert ports == {server.url.rsplit(":", 1)[1], elsewhere.url.rsplit(":", 1)[1]}
    finally:
        proxy.close()
