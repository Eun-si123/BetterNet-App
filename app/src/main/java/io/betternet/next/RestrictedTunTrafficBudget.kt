package io.betternet.next

import java.io.IOException
import java.util.concurrent.atomic.AtomicLong

/** Debug-only per-session *TUN byte* ceiling, counting both inbound and
 * outbound datagrams including overhead. This is not a mobile data billing
 * ceiling: protected gateway TLS, DNS and radio retransmissions are separate.
 * The VPN owner must close the session on any exceeded budget.
 */
internal class RestrictedTunTrafficBudget(private val maxBytes: Long) {
    init { require(maxBytes > 0) { "TUN byte budget must be positive" } }
    private val used = AtomicLong(0)

    fun charge(count: Int) {
        require(count >= 0) { "Negative TUN byte count" }
        if (count == 0) return
        while (true) {
            val before = used.get()
            if (count.toLong() > maxBytes - before) {
                throw IOException("Restricted TUN byte budget exceeded")
            }
            if (used.compareAndSet(before, before + count.toLong())) return
        }
    }

    fun bytesUsed(): Long = used.get()
}
