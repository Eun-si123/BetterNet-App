"""Opt-in, loopback-only reference CONNECT gateway for isolated A1 testing.

No public bind, automatic deployment, DNS lookup, or general-purpose proxying.
A real deployment needs a separate security review and operator approval.
"""

import argparse
import hmac
import ipaddress
import os
import re
import select
import socket
import ssl
import time
from dataclasses import dataclass, field

MAX_HEADER = 1024
MAX_BYTES_PER_DIRECTION = 2 * 1024 * 1024
MAX_SESSION_SECONDS = 30
TOKEN_PATTERN = re.compile(r"[A-Za-z0-9_-]{16,256}\Z", re.ASCII)
HOST_PATTERN = re.compile(r"(?=.{1,253}\Z)[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+\Z", re.ASCII)


@dataclass(frozen=True)
class GatewayConfig:
    token: str = field(repr=False)
    https_ip: str
    dns_host: str
    dns_ip: str

    def __post_init__(self):
        if not TOKEN_PATTERN.fullmatch(self.token):
            raise ValueError("Invalid bearer token")
        if (not HOST_PATTERN.fullmatch(self.dns_host) or
                any(len(label) > 63 or label.startswith("-") or label.endswith("-")
                    for label in self.dns_host.split("."))):
            raise ValueError("Invalid DNS TLS hostname")
        ipaddress.ip_address(self.https_ip)
        ipaddress.ip_address(self.dns_ip)

    def allowed_target(self, authority: str):
        ip = ipaddress.ip_address(self.https_ip)
        https_authority = f"[{ip}]:443" if ip.version == 6 else f"{ip}:443"
        if authority == https_authority:
            return (str(ip), 443)
        if authority == f"{self.dns_host}:853":
            return (str(ipaddress.ip_address(self.dns_ip)), 853)
        return None


def read_request(tls: ssl.SSLSocket, deadline: float) -> bytes:
    data = bytearray()
    while len(data) < MAX_HEADER:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("CONNECT header deadline exceeded")
        tls.settimeout(min(remaining, 1.0))
        try:
            value = tls.recv(1)
        except socket.timeout:
            continue
        if not value:
            raise ValueError("Truncated CONNECT request")
        data.extend(value)
        if data.endswith(b"\r\n\r\n"):
            return bytes(data)
    raise ValueError("CONNECT header too large")


def authorize(request: bytes, config: GatewayConfig):
    try:
        lines = request.decode("ascii").split("\r\n")
    except UnicodeDecodeError:
        return None
    if len(lines) != 5 or lines[-2:] != ["", ""]:
        return None
    start, host, credential = lines[:3]
    if not start.startswith("CONNECT ") or not start.endswith(" HTTP/1.1"):
        return None
    authority = start[len("CONNECT "):-len(" HTTP/1.1")]
    if host != f"Host: {authority}" or not credential.startswith("Proxy-Authorization: Bearer "):
        return None
    supplied = credential[len("Proxy-Authorization: Bearer "):]
    if not TOKEN_PATTERN.fullmatch(supplied) or not hmac.compare_digest(supplied, config.token):
        return None
    return config.allowed_target(authority)


def relay(tls: ssl.SSLSocket, upstream: socket.socket):
    deadline = time.monotonic() + MAX_SESSION_SECONDS
    totals = {tls: 0, upstream: 0}
    client_read_open = True
    # One thread handles both directions; no unbounded queues or per-client workers.
    while time.monotonic() < deadline:
        readers = [upstream, tls] if client_read_open else [upstream]
        ready, _, _ = select.select(readers, [], [], 0.2)
        if client_read_open and tls.pending() and tls not in ready:
            ready.append(tls)
        for source in ready:
            destination = upstream if source is tls else tls
            source.settimeout(0.5)
            try:
                chunk = source.recv(min(4096, MAX_BYTES_PER_DIRECTION - totals[source] + 1))
            except socket.timeout:
                continue
            if not chunk:
                if source is upstream:
                    return
                # A client can finish its request without closing its read
                # direction. Preserve the upstream response instead of
                # discarding it at the first client-side EOF.
                client_read_open = False
                upstream.shutdown(socket.SHUT_WR)
                continue
            totals[source] += len(chunk)
            if totals[source] > MAX_BYTES_PER_DIRECTION:
                return
            destination.settimeout(0.5)
            destination.sendall(chunk)


def handle_client(tls: ssl.SSLSocket, config: GatewayConfig):
    tls.settimeout(3)
    request = read_request(tls, time.monotonic() + 3)
    target = authorize(request, config)
    if target is None:
        tls.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
        return
    # Never resolve client-provided names or connect before exact bearer+target approval.
    try:
        upstream = socket.create_connection(target, timeout=3)
    except OSError:
        tls.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
        return
    with upstream:
        tls.sendall(b"HTTP/1.1 200 OK\r\n\r\n")
        relay(tls, upstream)


def serve_loopback(config: GatewayConfig, cert: str, key: str, port: int):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(cert, key)
    # Hardcoded loopback: no CLI option may expose a public relay.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", port))
        listener.listen(1)
        print(f"Loopback test gateway on 127.0.0.1:{listener.getsockname()[1]}", flush=True)
        while True:
            peer, _ = listener.accept()
            with peer:
                peer.settimeout(3)  # Bound TLS handshake before wrap_socket.
                try:
                    with context.wrap_socket(peer, server_side=True) as tls:
                        handle_client(tls, config)
                except (OSError, ValueError, TimeoutError):
                    # Invalid peers are discarded; no tokens, requests or addresses logged.
                    continue


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cert", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--https-ip", required=True)
    parser.add_argument("--dns-host", required=True)
    parser.add_argument("--dns-ip", required=True)
    parser.add_argument("--port", type=int, default=0)
    args = parser.parse_args()
    if args.port not in range(65536):
        parser.error("Port outside 0..65535")
    token = os.environ.get("BETTERNET_TEST_GATEWAY_TOKEN", "")
    config = GatewayConfig(token, args.https_ip, args.dns_host, args.dns_ip)
    serve_loopback(config, args.cert, args.key, args.port)


if __name__ == "__main__":
    main()
