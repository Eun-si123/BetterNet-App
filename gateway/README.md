# Restricted loopback gateway (A1 reference, not deployed)

This **opt-in local test component** is an independent public implementation, not a copy of private research. It implements the same strict HTTP/1.1 CONNECT request shape as the dormant Android client. No production relay is provided, no credentials or certificates are bundled, and no Android app invokes it.

The listener is **hardcoded to `127.0.0.1`**, handles one TLS client at a time, requires a TLS server certificate and a 16–256 character base64url bearer token supplied via `BETTERNET_TEST_GATEWAY_TOKEN`, and authorizes only `HTTPS_IP:443` or `DNS_HOST:853` mapped to a preconfigured numeric `DNS_IP`. It never resolves a client-supplied hostname. Each CONNECT header is limited to 1 KiB, each relay direction to 2 MiB, and a relay to 30 seconds; handshake, header, connect and I/O waits are bounded. No client-supplied destination is used without exact bearer and authority checks. TLS certificate trust and hostname validation are the **client's** responsibility; never disable them.

For an operator-controlled, isolated Linux loopback test with an already prepared throwaway certificate/key and test-only token, run:

```sh
BETTERNET_TEST_GATEWAY_TOKEN='REPLACE_WITH_RANDOM_BASE64URL_TOKEN' \
python3 gateway/loopback_gateway.py \
  --cert /path/to/test-cert.pem --key /path/to/test-key.pem \
  --https-ip 127.0.0.1 --dns-host dns.example --dns-ip 127.0.0.1 --port 0
```

The example is intentionally local-only; port `0` chooses an ephemeral port. Do not publish, forward, tunnel or expose this listener, connect it to real endpoints, or use a production token without separate authorization, threat review, and deployment design. A loopback listener cannot be reached from an Android device on a different host. There is no graceful multi-session server management, Android VPN activation, real DNS/HTTPS success, or tc/netem evidence yet. This is a bounded integration reference, not an Internet acceleration or censorship-bypass service.

Verify without external traffic:

```sh
python3 -m unittest discover -s gateway/tests -v
```

The tests generate a disposable TLS certificate, connect to an ephemeral loopback TLS listener, and mock the upstream socket with a local socket pair. They check accepted bytes, rejected bearer/authority, and strict configuration. A separate integration test uses independently generated gateway and HTTPS-origin certificates to complete an actual nested TLS handshake and HTTP request/response through the loopback relay; it is not Android or Internet evidence. No remote DNS, external network or public listener is used.
