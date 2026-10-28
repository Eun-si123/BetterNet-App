package io.betternet.next

/**
 * Dormant, in-memory correlation for a future authenticated DNS upstream.
 *
 * The caller must send each registered request only over an authenticated,
 * encrypted channel and return its opaque local handle with that response.
 * Handles are NOT credentials. This class opens no network connection,
 * starts no VPN and writes no TUN packet.
 */
internal class PendingDnsReplies(
    private val clockNanos: () -> Long = System::nanoTime,
    private val maxPending: Int = 64,
    private val ttlNanos: Long = 10_000_000_000L,
) {
    init {
        require(maxPending in 1..64)
        require(ttlNanos in 1..10_000_000_000L)
    }

    private data class Entry(val request: TunIngressResult.Packet, val createdNanos: Long)
    private val pending = LinkedHashMap<Long, Entry>()
    private var nextHandle = 1L

    /** Refuse malformed DNS, full queues and handle exhaustion without eviction. */
    @Synchronized
    fun register(request: TunIngressResult.Packet): Long? {
        if (!isSupportedDnsTunQuery(request)) return null
        val now = clockNanos()
        expire(now)
        if (pending.size >= maxPending || nextHandle == Long.MAX_VALUE) return null
        val handle = nextHandle++
        // TUN read buffers may be reused by the caller; keep a private snapshot.
        pending[handle] = Entry(request.copy(bytes = request.bytes.clone()), now)
        return handle
    }

    /**
     * Consume exactly once, including on a malformed or oversized reply.
     * A late, unsolicited or replayed response cannot produce a TUN packet.
     * Only call after verifying the response came from the authenticated upstream.
     */
    @Synchronized
    fun consume(handle: Long, dnsResponse: ByteArray, mtu: Int): ByteArray? {
        expire(clockNanos())
        val entry = pending.remove(handle) ?: return null
        return buildDnsUdpReply(entry.request, dnsResponse, mtu)
    }

    /** Called when the future VPN session closes or its upstream changes. */
    @Synchronized
    fun clear() = pending.clear()

    private fun expire(now: Long) {
        val iterator = pending.values.iterator()
        while (iterator.hasNext()) {
            val elapsed = now - iterator.next().createdNanos
            if (elapsed < 0 || elapsed >= ttlNanos) iterator.remove()
        }
    }
}
