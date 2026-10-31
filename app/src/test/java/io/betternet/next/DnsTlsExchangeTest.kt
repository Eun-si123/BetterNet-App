package io.betternet.next

import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import org.junit.Assert.*
import org.junit.Test

/** No network access: preflight errors must release the caller-supplied socket. */
class DnsTlsExchangeTest {
    private fun query() = byteArrayOf(
        0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1,
    )

    private fun socket(verifyHostname: Boolean): SSLSocket =
        (SSLContext.getDefault().socketFactory.createSocket() as SSLSocket).apply {
            useClientMode = true
            if (verifyHostname) {
                sslParameters = sslParameters.apply { endpointIdentificationAlgorithm = "HTTPS" }
            }
        }

    @Test fun invalidPreflightAlwaysClosesTlsSocket() {
        val valid = query()
        val cases = listOf(
            Triple("timeout", valid, 0),
            Triple("query length", ByteArray(16), 1_000),
            Triple("query flags", valid.clone().apply { this[2] = 0x81.toByte() }, 1_000),
            Triple("undeclared trailing data", valid + byteArrayOf(1), 1_000),
            Triple("unparsed additional record", valid.clone().apply { this[11] = 1 }, 1_000),
            Triple("identifying EDNS option",
                valid.clone().apply { this[11] = 1 } +
                    byteArrayOf(0, 0, 41, 4, 0xd0.toByte(), 0, 0, 0, 0, 0, 4, 0, 8, 0, 0),
                1_000),
        )
        for ((reason, bytes, timeout) in cases) {
            val tls = socket(verifyHostname = true)
            try {
                try {
                    exchangeOneDnsMessageOverTls(tls, bytes, timeout)
                    fail("$reason should be rejected")
                } catch (_: IllegalArgumentException) {
                    assertTrue("$reason must close TLS even before I/O", tls.isClosed)
                }
            } finally {
                tls.close()
            }
        }

        val tls = socket(verifyHostname = false)
        try {
            try {
                exchangeOneDnsMessageOverTls(tls, valid, 1_000)
                fail("Missing endpoint verification should be rejected")
            } catch (_: IllegalArgumentException) {
                assertTrue("Identity failure must close TLS", tls.isClosed)
            }
        } finally {
            tls.close()
        }
    }
}
