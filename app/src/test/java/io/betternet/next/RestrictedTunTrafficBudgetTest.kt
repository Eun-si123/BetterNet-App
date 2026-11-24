package io.betternet.next

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.net.InetAddress
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import org.junit.Assert.*
import org.junit.Test

/** Pure TUN fixtures; never creates a VPN, socket or public network request. */
class RestrictedTunTrafficBudgetTest {
    private fun plan(): RestrictedTestTunPlan {
        val syn = TunTcpSynAckTest().request(4)
        return RestrictedTestTunPlan(
            syn.header.source,
            InetAddress.getByName("198.18.0.1"),
            syn.header.destination, 1280,
        )
    }

    private fun dispatcher(plan: RestrictedTestTunPlan, dns: (java.io.OutputStream) -> Unit = {}):
        RestrictedTestTunDispatcher = RestrictedTestTunDispatcher(
            plan,
            { _, out -> dns(out); null },
            { _, _, _, _ -> throw AssertionError("No gateway tunnel must open") },
        )

    @Test fun exactLimitPassesButNextByteIsRefusedWithoutRollover() {
        val budget = RestrictedTunTrafficBudget(10)
        budget.charge(4)
        budget.charge(0)
        budget.charge(6)
        assertEquals(10L, budget.bytesUsed())
        try {
            budget.charge(1)
            fail("Over-budget byte must be refused")
        } catch (expected: IOException) {
            assertEquals("Restricted TUN byte budget exceeded", expected.message)
        }
        assertEquals(10L, budget.bytesUsed())
        try {
            budget.charge(-1)
            fail("Negative count must not extend allowance")
        } catch (_: IllegalArgumentException) {}
        for (invalid in listOf(0L, -1L, Long.MIN_VALUE)) {
            try {
                RestrictedTunTrafficBudget(invalid)
                fail("Invalid max bytes accepted")
            } catch (_: IllegalArgumentException) {}
        }
        val large = RestrictedTunTrafficBudget(Long.MAX_VALUE)
        large.charge(Int.MAX_VALUE)
        assertEquals(Int.MAX_VALUE.toLong(), large.bytesUsed())
    }

    @Test fun excessiveInboundTunDatagramClosesBeforeParsingOrGatewayUse() {
        val syn = TunTcpSynAckTest().request(4)
        var closes = 0
        val session = RestrictedTunSession(
            dispatcher(plan()), ByteArrayInputStream(syn.bytes),
            ByteArrayOutputStream(), { closes++ },
            maxTunBytes = syn.bytes.size.toLong() - 1L,
        )
        try {
            session.pumpOneTunPacket(100)
            fail("An oversized byte allocation must stop the debug TUN")
        } catch (expected: IOException) {
            assertEquals("Restricted TUN byte budget exceeded", expected.message)
        }
        assertEquals(1, closes)
        assertFalse(session.pumpOneTunPacket(101))
        session.requestStop()
        session.close()
        assertEquals(1, closes)
    }

    @Test fun outboundQuotaRefusesResponseBeforeAnyPartialTunWrite() {
        val p = plan()
        val udp = RestrictedTestTunDispatcherTest().udp(p)
        val out = ByteArrayOutputStream()
        var closes = 0
        val session = RestrictedTunSession(
            dispatcher(p) { it.write(ByteArray(64) { 0x56 }) },
            ByteArrayInputStream(udp), out, { closes++ },
            maxTunBytes = udp.size.toLong() + 63L,
        )
        try {
            session.pumpOneTunPacket(100)
            fail("Reply exceeding the shared ingress+egress limit must fail")
        } catch (expected: IOException) {
            assertEquals("Restricted TUN byte budget exceeded", expected.message)
        }
        assertEquals(0, out.size()) // Never send a partially approved packet.
        assertEquals(1, closes)
        assertFalse(session.pumpOneTunPacket(101))
    }

    @Test fun exactBidirectionalBudgetStillForwardsResponseAndThenReleases() {
        val p = plan()
        val udp = RestrictedTestTunDispatcherTest().udp(p)
        val out = ByteArrayOutputStream()
        val expected = ByteArray(64) { 0x22 }
        var closes = 0
        val session = RestrictedTunSession(
            dispatcher(p) { it.write(expected) },
            ByteArrayInputStream(udp), out, { closes++ },
            maxTunBytes = udp.size.toLong() + expected.size.toLong(),
        )
        assertTrue(session.pumpOneTunPacket(100))
        assertArrayEquals(expected, out.toByteArray())
        assertEquals(0, closes)
        assertFalse(session.pumpOneTunPacket(101)) // EOF closes ownership.
        assertEquals(1, closes)
    }

    @Test fun rejectedIpPacketsStillConsumeDebugSessionAllowance() {
        val p = plan()
        val udp = RestrictedTestTunDispatcherTest().udp(p).apply {
            // Invalid IPv4 checksum but still a kernel-originated TUN read.
            this[10] = (this[10].toInt() xor 0xff).toByte()
        }
        var closes = 0
        val session = RestrictedTunSession(
            dispatcher(p), ByteArrayInputStream(udp),
            ByteArrayOutputStream(), { closes++ },
            maxTunBytes = udp.size.toLong() - 1L,
        )
        try {
            session.pumpOneTunPacket(100)
            fail("Malformed packets must not bypass the traffic ceiling")
        } catch (_: IOException) {}
        assertEquals(1, closes)
    }

    @Test fun concurrentDebitsCannotExceedQuota() {
        val max = 600L
        val budget = RestrictedTunTrafficBudget(max)
        val pool = Executors.newFixedThreadPool(4)
        val successes = AtomicInteger()
        try {
            val futures = List(4) {
                pool.submit {
                    repeat(250) {
                        try {
                            budget.charge(1)
                            successes.incrementAndGet()
                        } catch (_: IOException) {}
                    }
                }
            }
            futures.forEach { it.get(4, TimeUnit.SECONDS) }
        } finally { pool.shutdownNow() }
        assertEquals(max, budget.bytesUsed())
        assertEquals(max.toInt(), successes.get())
    }
}
