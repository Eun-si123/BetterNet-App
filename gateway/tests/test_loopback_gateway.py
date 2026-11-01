"""Loopback TLS tests; no VPN, public listener, real gateway or Internet access."""

import socket
import ssl
import subprocess
import sys
import tempfile
import time
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from loopback_gateway import GatewayConfig, authorize, handle_client, read_request, relay

TOKEN = "TestOnlyOpaqueToken0123456789"


class GatewayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.cert = str(Path(cls.tmp.name) / "cert.pem")
        cls.key = str(Path(cls.tmp.name) / "key.pem")
        cls.origin_cert = str(Path(cls.tmp.name) / "origin-cert.pem")
        cls.origin_key = str(Path(cls.tmp.name) / "origin-key.pem")
        for cert, key, hostname in (
            (cls.cert, cls.key, "gateway.example"),
            (cls.origin_cert, cls.origin_key, "origin.example"),
        ):
            subprocess.run([
                "openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
                "-nodes", "-keyout", key, "-out", cert, "-days", "1",
                "-subj", f"/CN={hostname}", "-addext", f"subjectAltName=DNS:{hostname}",
            ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True, timeout=10)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def setUp(self):
        self.config = GatewayConfig(TOKEN, "127.0.0.1", "dns.example", "127.0.0.1")

    def request(self, authority="127.0.0.1:443", token=TOKEN):
        return (f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n"
                f"Proxy-Authorization: Bearer {token}\r\n\r\n").encode("ascii")

    def with_tls_gateway(self, request, on_dial):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.cert, self.key)
        client_context = ssl.create_default_context(cafile=self.cert)
        failures = []
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            listener.settimeout(4)

            def server():
                try:
                    conn, _ = listener.accept()
                    with conn:
                        conn.settimeout(3)
                        with context.wrap_socket(conn, server_side=True) as tls:
                            with patch("loopback_gateway.socket.create_connection", side_effect=on_dial):
                                handle_client(tls, self.config)
                except Exception as error:
                    failures.append(error)

            worker = threading.Thread(target=server, daemon=True)
            worker.start()
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as raw:
                raw.settimeout(3)
                raw.connect(listener.getsockname())
                with client_context.wrap_socket(raw, server_hostname="gateway.example") as tls:
                    tls.settimeout(3)
                    tls.sendall(request)
                    response = bytearray()
                    while not response.endswith(b"\r\n\r\n"):
                        part = tls.recv(1)
                        if not part:
                            break
                        response.extend(part)
                    yield tls, bytes(response)
            worker.join(4)
            self.assertFalse(worker.is_alive(), "Gateway did not stop after client disconnect")
            self.assertEqual([], failures)

    def test_authenticated_connect_relay_and_fixed_target(self):
        gateway_socket, upstream_peer = socket.socketpair()
        destinations = []
        try:
            def dial(address, timeout):
                destinations.append((address, timeout))
                return gateway_socket

            def echo():
                with upstream_peer:
                    data = upstream_peer.recv(100)
                    upstream_peer.sendall(data.upper())

            echo_thread = threading.Thread(target=echo, daemon=True)
            echo_thread.start()
            for tls, response in self.with_tls_gateway(self.request(), dial):
                self.assertEqual(b"HTTP/1.1 200 OK\r\n\r\n", response)
                tls.sendall(b"test")
                self.assertEqual(b"TEST", tls.recv(4))
            echo_thread.join(3)
            self.assertFalse(echo_thread.is_alive())
            self.assertEqual([(("127.0.0.1", 443), 3)], destinations)
        finally:
            gateway_socket.close()
            upstream_peer.close()

    def test_real_https_response_through_independently_verified_nested_tls(self):
        """A real TLS origin replies through the authenticated gateway; no Internet/VPN."""
        origin_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        origin_context.load_cert_chain(self.origin_cert, self.origin_key)
        client_context = ssl.create_default_context(cafile=self.origin_cert)
        failures = []
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            listener.settimeout(4)

            def origin():
                try:
                    conn, _ = listener.accept()
                    with conn:
                        conn.settimeout(3)
                        with origin_context.wrap_socket(conn, server_side=True) as tls:
                            request = bytearray()
                            while not request.endswith(b"\r\n\r\n"):
                                request.extend(tls.recv(1024))
                            if bytes(request) != b"GET /health HTTP/1.1\r\nHost: origin.example\r\n\r\n":
                                raise AssertionError("Unexpected HTTPS request")
                            tls.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
                except Exception as error:
                    failures.append(error)

            worker = threading.Thread(target=origin, daemon=True)
            worker.start()
            original_connect = socket.create_connection
            def dial(address, timeout):
                self.assertEqual(("127.0.0.1", 443), address)
                return original_connect(listener.getsockname(), timeout=timeout)

            for outer, response in self.with_tls_gateway(self.request(), dial):
                self.assertEqual(b"HTTP/1.1 200 OK\r\n\r\n", response)
                incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
                inner = client_context.wrap_bio(incoming, outgoing, server_side=False,
                                                server_hostname="origin.example")

                def exchange(operation):
                    while True:
                        try:
                            result = operation()
                        except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
                            result = None
                            needs_more = True
                        else:
                            needs_more = False
                        pending = outgoing.read()
                        if pending:
                            outer.sendall(pending)
                        if not needs_more:
                            return result
                        incoming.write(outer.recv(16384))

                exchange(inner.do_handshake)
                exchange(lambda: inner.write(b"GET /health HTTP/1.1\r\nHost: origin.example\r\n\r\n"))
                reply = bytearray()
                while not reply.endswith(b"\r\n\r\nOK"):
                    reply.extend(exchange(lambda: inner.read(16384)))
                self.assertEqual(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK", bytes(reply))
            worker.join(4)
            self.assertFalse(worker.is_alive(), "Origin did not finish")
            self.assertEqual([], failures)

    def test_client_write_half_close_still_delivers_upstream_response(self):
        """A TCP peer may finish sending while still expecting its reply."""
        gateway_client, client = socket.socketpair()
        gateway_upstream, origin = socket.socketpair()
        failures = []

        class SocketLikeTls:
            def __init__(self, sock):
                self.sock = sock
            def fileno(self):
                return self.sock.fileno()
            def pending(self):
                return 0
            def settimeout(self, timeout):
                self.sock.settimeout(timeout)
            def recv(self, size):
                return self.sock.recv(size)
            def sendall(self, data):
                return self.sock.sendall(data)

        def serve_origin():
            try:
                with origin:
                    origin.settimeout(2)
                    data = bytearray()
                    while True:
                        part = origin.recv(1024)
                        if not part:
                            break
                        data.extend(part)
                    self.assertEqual(b"request", bytes(data))
                    origin.sendall(b"response")
            except Exception as error:
                failures.append(error)

        def serve_relay():
            try:
                with gateway_client, gateway_upstream:
                    relay(SocketLikeTls(gateway_client), gateway_upstream)
            except Exception as error:
                failures.append(error)

        origin_thread = threading.Thread(target=serve_origin, daemon=True)
        relay_thread = threading.Thread(target=serve_relay, daemon=True)
        origin_thread.start()
        relay_thread.start()
        try:
            with client:
                client.settimeout(2)
                client.sendall(b"request")
                client.shutdown(socket.SHUT_WR)
                self.assertEqual(b"response", client.recv(1024))
        finally:
            gateway_client.close()
            gateway_upstream.close()
            origin.close()
            origin_thread.join(3)
            relay_thread.join(3)
        self.assertFalse(origin_thread.is_alive())
        self.assertFalse(relay_thread.is_alive())
        self.assertEqual([], failures)

    def test_bad_token_never_dials(self):
        def forbidden(*args, **kwargs):
            raise AssertionError("Unauthenticated client reached upstream")
        for _, response in self.with_tls_gateway(self.request(token="WrongOpaqueToken1234"), forbidden):
            self.assertTrue(response.startswith(b"HTTP/1.1 403"))

    def test_wrong_target_never_dials(self):
        def forbidden(*args, **kwargs):
            raise AssertionError("Unapproved target reached upstream")
        for _, response in self.with_tls_gateway(self.request(authority="127.0.0.2:443"), forbidden):
            self.assertTrue(response.startswith(b"HTTP/1.1 403"))

    def test_no_arbitrary_dns_or_injected_headers(self):
        self.assertIsNone(authorize(self.request(authority="other.example:853"), self.config))
        self.assertIsNone(authorize(self.request()[:-2] + b"Extra: x\r\n\r\n", self.config))
        self.assertEqual(("127.0.0.1", 853),
                         authorize(self.request(authority="dns.example:853"), self.config))
        ipv6 = GatewayConfig(TOKEN, "2001:db8::1", "dns.example", "2001:db8::2")
        self.assertEqual(("2001:db8::1", 443),
                         authorize(self.request(authority="[2001:db8::1]:443"), ipv6))

    def test_oversized_header_is_rejected_before_authorization(self):
        class FakeTls:
            def settimeout(self, value):
                pass
            def recv(self, count):
                return b"A"
        with self.assertRaisesRegex(ValueError, "too large"):
            read_request(FakeTls(), time.monotonic() + 2)

    def test_slow_header_has_whole_request_deadline(self):
        class FakeTls:
            def settimeout(self, value):
                pass
            def recv(self, count):
                raise socket.timeout()
        with self.assertRaises(TimeoutError):
            read_request(FakeTls(), time.monotonic() + 0.005)

    def test_bad_configuration_is_rejected(self):
        for token in ("short", "a" * 257, "a\r\nInjected: yes"):
            with self.assertRaises(ValueError):
                GatewayConfig(token, "127.0.0.1", "dns.example", "127.0.0.1")
        with self.assertRaises(ValueError):
            GatewayConfig(TOKEN, "not-an-ip", "dns.example", "127.0.0.1")
        with self.assertRaises(ValueError):
            GatewayConfig(TOKEN, "127.0.0.1", "bad_name", "127.0.0.1")


if __name__ == "__main__":
    unittest.main()
