package io.betternet.next

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.net.SocketTimeoutException
import org.junit.Assert.*
import org.junit.Test

/** Offline HTTP framing/authorization tests: no Android VPN or network. */
class AuthenticatedHttpsProbeTest {
    private fun status(
        response: String, host: String = "test.example",
        verify: () -> Unit = {},
        nowNanos: () -> Long = System::nanoTime,
        timeoutMs: Int = 3_000,
    ): Pair<Int, String> {
        val sent = ByteArrayOutputStream()
        val result = readBoundedHttpsHeadStatus(
            host, ByteArrayInputStream(response.toByteArray()), sent,
            verify, { assertTrue(it in 1..10_000) }, timeoutMs, nowNanos,
        )
        return result to sent.toString("US-ASCII")
    }

    @Test fun sendsOnlyHeadAndAcceptsAuthenticErrorStatusWithoutRedirect() {
        for (code in listOf(200, 302, 403, 503)) {
            val (actual, sent) = status("HTTP/1.1 $code Test\r\nContent-Length: 999999\r\n")
            assertEquals(code, actual)
            assertEquals("HEAD / HTTP/1.1\r\nHost: test.example\r\nConnection: close\r\n\r\n", sent)
            assertFalse(sent.contains("Proxy-Authorization"))
        }
    }

    @Test fun rejectsMalformedUnboundedOrTruncatedStatus() {
        for (reply in listOf(
            "HTTP/1.1 200 OK\n",
            "HTTP/1.1 200 OK",
            "HTTP/1.1 200 OK\r",
            "HTTP/2 200 OK\r\n",
            "HTTP/1.1 999 Bad\r\n",
            "HTTP/1.1 200 " + "A".repeat(200) + "\r\n",
            "HTTP/1.1 200 \u0000\r\n",
        )) {
            try { status(reply); fail("Invalid HTTP status must fail") }
            catch (_: IOException) { }
        }
    }

    @Test fun invalidHostOrRevokedAuthorizationNeverWritesRequest() {
        val sent = ByteArrayOutputStream()
        for (host in listOf("test.example\r\nX-Injected: yes", "invalid host", "")) {
            try {
                readBoundedHttpsHeadStatus(host, ByteArrayInputStream(ByteArray(0)),
                    sent, {}, {}, 1_000)
                fail("Invalid host must not be sent")
            } catch (_: IllegalArgumentException) {
                assertEquals(0, sent.size())
            }
        }
        try {
            readBoundedHttpsHeadStatus("test.example", ByteArrayInputStream(ByteArray(0)),
                sent, { throw IllegalStateException("Revoked") }, {}, 1_000)
            fail("Revoked probe must not send")
        } catch (_: IllegalStateException) {
            assertEquals(0, sent.size())
        }
    }

    @Test fun wholeResponseDeadlinePreventsSlowPeerExtendingRead() {
        var clock = 0L
        try {
            status("HTTP/1.1 200 OK\r\n", nowNanos = { (clock++ * 1_000_000L) },
                timeoutMs = 2)
            fail("Per-byte reads must not extend the overall budget")
        } catch (_: SocketTimeoutException) { }
    }

    @Test fun revocationAfterFirstByteAbortsResponse() {
        var checks = 0
        try {
            status("HTTP/1.1 200 OK\r\n", verify = {
                if (++checks == 3) throw IllegalStateException("Scope changed")
            })
            fail("Stale probe result must not escape")
        } catch (_: IllegalStateException) {
            assertTrue(checks >= 3)
        }
    }
}
