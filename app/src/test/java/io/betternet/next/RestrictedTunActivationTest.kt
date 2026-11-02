package io.betternet.next

import java.io.Closeable
import java.io.IOException
import org.junit.Assert.*
import org.junit.Test

/** Pure transaction tests: no Android service, VPN permission or TUN is opened. */
class RestrictedTunActivationTest {
    private class FakeDescriptor(private val events: MutableList<String>,
                                 private val closeFails: Boolean = false) : Closeable {
        override fun close() {
            events += "descriptor.close"
            if (closeFails) throw IOException("descriptor close failed")
        }
    }

    @Test fun successfulStartTransfersDescriptorOwnershipWithoutPrematureClose() {
        val events = mutableListOf<String>()
        val descriptor = FakeDescriptor(events)
        val worker = establishRestrictedTunTransaction(
            revalidate = { events += "revalidate" },
            establish = { events += "establish"; descriptor },
            attach = { assertSame(descriptor, it); events += "attach"; "worker" },
            start = { events += "start:$it" },
            rollback = { events += "rollback" },
        )
        assertEquals("worker", worker)
        assertEquals(listOf("revalidate", "establish", "attach", "start:worker"), events)
    }

    @Test fun revokedConsentBeforeEstablishNeverTouchesTun() {
        val events = mutableListOf<String>()
        try {
            establishRestrictedTunTransaction(
                revalidate = { events += "revalidate"; throw SecurityException("revoked") },
                establish = { events += "establish"; FakeDescriptor(events) },
                attach = { events += "attach"; "worker" },
                start = { events += "start" },
                rollback = { events += "rollback" },
            )
            fail("Consent revocation must abort")
        } catch (expected: SecurityException) {
            assertEquals("revoked", expected.message)
        }
        assertEquals(listOf("revalidate", "rollback"), events)
    }

    @Test fun androidEstablishRefusalAbortsWithoutWorker() {
        val events = mutableListOf<String>()
        try {
            establishRestrictedTunTransaction(
                revalidate = { events += "revalidate" },
                establish = { events += "establish"; null as FakeDescriptor? },
                attach = { events += "attach"; "worker" },
                start = { events += "start" },
                rollback = { events += "rollback" },
            )
            fail("Null descriptor must abort")
        } catch (expected: IllegalStateException) {
            assertTrue(expected.message!!.contains("refused"))
        }
        assertEquals(listOf("revalidate", "establish", "rollback"), events)
    }

    @Test fun attachFailureClosesDescriptorAndCancels() {
        val events = mutableListOf<String>()
        try {
            establishRestrictedTunTransaction(
                revalidate = { events += "revalidate" },
                establish = { events += "establish"; FakeDescriptor(events) },
                attach = { events += "attach"; throw IOException("attach failed") },
                start = { events += "start" },
                rollback = { events += "rollback" },
            )
            fail("Attach failure must abort")
        } catch (expected: IOException) {
            assertEquals("attach failed", expected.message)
        }
        assertEquals(listOf("revalidate", "establish", "attach", "rollback", "descriptor.close"), events)
    }

    @Test fun startFailureRetainsOriginalErrorAndSuppressesCleanupErrors() {
        val events = mutableListOf<String>()
        try {
            establishRestrictedTunTransaction(
                revalidate = { events += "revalidate" },
                establish = { events += "establish"; FakeDescriptor(events, closeFails = true) },
                attach = { events += "attach"; "worker" },
                start = { events += "start"; throw IOException("start failed") },
                rollback = { events += "rollback"; throw IOException("cancel failed") },
            )
            fail("Start failure must abort")
        } catch (expected: IOException) {
            assertEquals("start failed", expected.message)
            assertEquals(listOf("cancel failed", "descriptor close failed"),
                expected.suppressed.map { it.message })
        }
        assertEquals(listOf("revalidate", "establish", "attach", "start", "rollback", "descriptor.close"), events)
    }
}
