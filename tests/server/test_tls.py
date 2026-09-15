"""TLS 1.3 enforcement.

Zero-Trust §7.1 enforces TLS 1.3. The trap this guards against is that
``ssl.PROTOCOL_TLS_SERVER`` negotiates 1.2 quite happily, so a server that merely
"uses TLS" is not a TLS 1.3 server. The test performs real handshakes rather than
asserting on configuration, because the configuration is exactly the thing that looks
right while behaving wrong.
"""

from __future__ import annotations

import datetime
import socket
import ssl
import threading

import pytest

from mcp_server.security import build_tls_context

cryptography = pytest.importorskip("cryptography")

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402


@pytest.fixture(scope="module")
def certificate(tmp_path_factory: pytest.TempPathFactory) -> tuple[str, str]:
    """A throwaway self-signed certificate for handshake testing."""
    directory = tmp_path_factory.mktemp("tls")
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_path = directory / "cert.pem"
    key_path = directory / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return str(cert_path), str(key_path)


def _listen(context: ssl.SSLContext, connections: int) -> int:
    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 0))
    server.listen(connections)
    port = int(server.getsockname()[1])

    def serve() -> None:
        for _ in range(connections):
            try:
                conn, _ = server.accept()
                with context.wrap_socket(conn, server_side=True) as tls:
                    tls.recv(16)
            except OSError:
                continue
        server.close()

    threading.Thread(target=serve, daemon=True).start()
    return port


def _handshake(port: int, maximum_version: ssl.TLSVersion) -> str:
    client = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client.check_hostname = False
    client.verify_mode = ssl.CERT_NONE
    client.maximum_version = maximum_version
    with socket.create_connection(("127.0.0.1", port), timeout=5) as raw:
        with client.wrap_socket(raw, server_hostname="localhost") as tls:
            return tls.version() or ""


def test_context_declares_tls_13_as_the_minimum(certificate: tuple[str, str]) -> None:
    context = build_tls_context(certfile=certificate[0], keyfile=certificate[1])
    assert context.minimum_version is ssl.TLSVersion.TLSv1_3


def test_tls_13_client_connects(certificate: tuple[str, str]) -> None:
    context = build_tls_context(certfile=certificate[0], keyfile=certificate[1])
    port = _listen(context, 1)
    assert _handshake(port, ssl.TLSVersion.TLSv1_3) == "TLSv1.3"


def test_tls_12_client_is_refused(certificate: tuple[str, str]) -> None:
    """The load-bearing assertion: a 1.2-capable client must not be downgraded to."""
    context = build_tls_context(certfile=certificate[0], keyfile=certificate[1])
    port = _listen(context, 1)
    with pytest.raises(ssl.SSLError):
        _handshake(port, ssl.TLSVersion.TLSv1_2)


def test_compression_is_disabled(certificate: tuple[str, str]) -> None:
    """TLS compression enables CRIME."""
    context = build_tls_context(certfile=certificate[0], keyfile=certificate[1])
    assert context.options & ssl.OP_NO_COMPRESSION


def test_client_certificate_requires_a_ca(certificate: tuple[str, str]) -> None:
    """mTLS without a CA to verify against would verify nothing."""
    with pytest.raises(ValueError, match="client_ca_file"):
        build_tls_context(
            certfile=certificate[0], keyfile=certificate[1], require_client_cert=True
        )


def test_harden_uvicorn_config_refuses_a_plaintext_config() -> None:
    """Silently doing nothing would leave a caller believing they hardened a listener."""
    from mcp_server.security import harden_uvicorn_config

    class PlaintextConfig:
        ssl = None

    with pytest.raises(ValueError, match="no TLS context"):
        harden_uvicorn_config(PlaintextConfig())


def test_harden_uvicorn_config_raises_tls_floor(certificate: tuple[str, str]) -> None:
    class Config:
        def __init__(self) -> None:
            self.ssl = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

    from mcp_server.security import harden_uvicorn_config

    config = Config()
    assert config.ssl.minimum_version is not ssl.TLSVersion.TLSv1_3
    harden_uvicorn_config(config)
    assert config.ssl.minimum_version is ssl.TLSVersion.TLSv1_3
