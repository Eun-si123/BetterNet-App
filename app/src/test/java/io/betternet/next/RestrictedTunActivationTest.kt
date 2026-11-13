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

    @Test fun rejectedAdoptionDoesNotCloseAlreadyReleasedDescriptorTwice() {
        val events = mutableListOf<String>()
        val descriptor = FakeDescriptor(events)
        val caught = assertThrows(RestrictedTunAdoptionRejected::class.java) {
            establishRestrictedTunTransaction(
                revalidate = {},
                establish = { descriptor },
                attach = {
                    it.close() // Lifecycle rejection releases its candidate owner.
                    throw RestrictedTunAdoptionRejected("VPN lifecycle already revoked")
                },
                start = { fail("Rejected worker must never start") },
                rollback = { events += "rollback" },
            )
        }
        assertEquals("VPN lifecycle already revoked", caught.message)
        assertEquals(listOf("descriptor.close", "rollback"), events)
    }

    @Test fun startFailureCancelsAdoptedWorkerWithoutDoubleClosingItsDescriptor() {
        val events = mutableListOf<String>()
        val descriptor = FakeDescriptor(events)
        try {
            establishRestrictedTunTransaction(
                revalidate = { events += "revalidate" },
                establish = { events += "establish"; descriptor },
                attach = { events += "attach"; "worker" },
                start = { events += "start"; throw IOException("start failed") },
                rollback = { events += "rollback"; descriptor.close() },
            )
            fail("Start failure must abort")
        } catch (expected: IOException) {
            assertEquals("start failed", expected.message)
            assertTrue(expected.suppressed.isEmpty())
        }
        // The adopted worker owns closure. Transaction must never close it twice.
        assertEquals(listOf("revalidate", "establish", "attach", "start", "rollback", "descriptor.close"), events)
    }

    @Test fun startFailureRetainsOriginalErrorAndSuppressesOwnerCleanupError() {
        val events = mutableListOf<String>()
        val descriptor = FakeDescriptor(events, closeFails = true)
        try {
            establishRestrictedTunTransaction(
                revalidate = { events += "revalidate" },
                establish = { events += "establish"; descriptor },
                attach = { events += "attach"; "worker" },
                start = { events += "start"; throw IOException("start failed") },
                rollback = { events += "rollback"; descriptor.close() },
            )
            fail("Start failure must abort")
        } catch (expected: IOException) {
            assertEquals("start failed", expected.message)
            assertEquals(listOf("descriptor close failed"), expected.suppressed.map { it.message })
        }
        assertEquals(listOf("revalidate", "establish", "attach", "start", "rollback", "descriptor.close"), events)
    }

    @Test fun failedAttachStillClosesUnownedDescriptorAndPreservesBothErrors() {
        val events = mutableListOf<String>()
        try {
            establishRestrictedTunTransaction(
                revalidate = {},
                establish = { FakeDescriptor(events, closeFails = true) },
                attach = { throw IOException("attach failed") },
                start = { fail("Must not start") },
                rollback = { events += "rollback" },
            )
            fail("Attach failure must abort")
        } catch (expected: IOException) {
            assertEquals("attach failed", expected.message)
            assertEquals(listOf("descriptor close failed"), expected.suppressed.map { it.message })
        }
        assertEquals(listOf("rollback", "descriptor.close"), events)
    }

    @Test fun rollbackRethrowingOriginalFailureDoesNotMaskIt() {
        val revoked = SecurityException("revoked")
        val caught = assertThrows(SecurityException::class.java) {
            establishRestrictedTunTransaction(
                revalidate = { throw revoked },
                establish = { FakeDescriptor(mutableListOf()) },
                attach = { "worker" },
                start = {},
                rollback = { throw revoked },
            )
        }
        assertSame(revoked, caught)
        assertTrue(caught.suppressed.isEmpty())
    }

    @Test fun descriptorCloseRethrowingAttachFailureDoesNotMaskIt() {
        val events = mutableListOf<String>()
        val original = IOException("attach failed")
        val descriptor = Closeable { events += "descriptor.close"; throw original }
        val caught = assertThrows(IOException::class.java) {
            establishRestrictedTunTransaction(
                revalidate = {},
                establish = { descriptor },
                attach = { throw original },
                start = {},
                rollback = { events += "rollback" },
            )
        }
        assertSame(original, caught)
        assertTrue(caught.suppressed.isEmpty())
        assertEquals(listOf("rollback", "descriptor.close"), events)
    }

    @Test fun foregroundPromotionMustPrecedeTunAndRemainOwnedOnSuccess() {
        val events = mutableListOf<String>()
        val result = withRestrictedForegroundOwnership(
            revalidate = { events += "preflight" },
            promote = { events += "foreground" },
            activate = { events += "establish"; "worker" },
            demote = { events += "demote" },
        )
        assertEquals("worker", result)
        assertEquals(listOf("preflight", "foreground", "establish"), events)
    }

    @Test fun failedPreflightNeverPromotesOrEstablishesTun() {
        val events = mutableListOf<String>()
        try {
            withRestrictedForegroundOwnership(
                revalidate = { events += "preflight"; throw SecurityException("revoked") },
                promote = { events += "foreground" },
                activate = { events += "establish" },
                demote = { events += "demote" },
            )
            fail("Revoked consent must prevent foreground service and TUN")
        } catch (expected: SecurityException) {
            assertEquals("revoked", expected.message)
        }
        assertEquals(listOf("preflight"), events)
    }

    @Test fun foregroundOrActivationFailureDemotesWithoutMaskingPrimaryError() {
        for (failAt in listOf("foreground", "establish")) {
            val events = mutableListOf<String>()
            try {
                withRestrictedForegroundOwnership(
                    revalidate = { events += "preflight" },
                    promote = {
                        events += "foreground"
                        if (failAt == "foreground") throw IOException("foreground failed")
                    },
                    activate = { events += "establish"; throw IOException("establish failed") },
                    demote = { events += "demote"; throw IOException("demote failed") },
                )
                fail("Expected activation failure")
            } catch (expected: IOException) {
                assertEquals("$failAt failed", expected.message)
                assertEquals(listOf("demote failed"), expected.suppressed.map { it.message })
            }
            assertEquals(if (failAt == "foreground")
                listOf("preflight", "foreground", "demote")
                else listOf("preflight", "foreground", "establish", "demote"), events)
        }
    }

    @Test fun notificationStopCancelsTunOwnerBeforeServiceShutdown() {
        val events = mutableListOf<String>()
        stopRestrictedServiceFailClosed(
            cancel = { events += "cancel" },
            stop = { events += "stop" },
        )
        assertEquals(listOf("cancel", "stop"), events)
    }

    @Test fun notificationStopStillStopsServiceIfTunCancellationThrows() {
        val events = mutableListOf<String>()
        val error = IOException("TUN close failed")
        try {
            stopRestrictedServiceFailClosed(
                cancel = { events += "cancel"; throw error },
                stop = { events += "stop" },
            )
            fail("Cancellation error must not be silently swallowed")
        } catch (caught: IOException) {
            assertSame(error, caught)
        }
        assertEquals(listOf("cancel", "stop"), events)
    }

    @Test fun serviceStopFailurePreservesFirstCancellationError() {
        val first = IOException("cancel failed")
        val second = IOException("stop failed")
        val events = mutableListOf<String>()
        try {
            stopRestrictedServiceFailClosed(
                cancel = { events += "cancel"; throw first },
                stop = { events += "stop"; throw second },
            )
            fail("Both failures must be reported")
        } catch (caught: IOException) {
            assertSame(first, caught)
            assertEquals(listOf(second), caught.suppressed.toList())
        }
        assertEquals(listOf("cancel", "stop"), events)
    }

    @Test fun revokeDuringForegroundPromotionCannotEstablishTun() {
        val lifecycle = RestrictedTunLifecycle()
        val events = mutableListOf<String>()
        try {
            withRestrictedForegroundOwnership(
                revalidate = { lifecycle.requireNotCancelled(); events += "preflight" },
                promote = { events += "foreground"; lifecycle.cancel() },
                activate = {
                    establishRestrictedTunTransaction(
                        revalidate = { lifecycle.requireNotCancelled() },
                        establish = { events += "establish"; FakeDescriptor(events) },
                        attach = { events += "attach"; "worker" },
                        start = { events += "start" },
                        rollback = { events += "rollback" },
                    )
                },
                demote = { events += "demote" },
            )
            fail("Revoked owner must not establish a TUN after foreground promotion")
        } catch (expected: IllegalStateException) {
            assertEquals("VPN lifecycle already revoked", expected.message)
        }
        assertEquals(listOf("preflight", "foreground", "rollback", "demote"), events)
    }

}
