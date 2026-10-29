package io.betternet.next

/**
 * Offline TCP handshake return-packet primitive for a future *single* selected
 * application flow. It never opens a VPN or socket, sends traffic, or stores a
 * connection. Do not emit a SYN-ACK until an authenticated gateway is ready and
 * a bounded TCP flow state machine owns the tuple and both sequence spaces.
 *
 * The caller supplies a cryptographically unpredictable 32-bit server ISN.
 * This deliberately advertises a zero receive window: no application payload
 * can be accepted until a separately reviewed flow controller exists.
 */
internal fun buildTcpSynAck(
    syn: TunIngressResult.Packet,
    serverIsn: Long,
    mtu: Int,
): ByteArray? {
    require(mtu in 1280..9000) { "TUN MTU must support IPv6 and be bounded" }
    if (serverIsn !in 0..0xffff_ffffL) return null
    val input = syn.bytes
    val header = parseTunPacketHeader(input, input.size) ?: return null
    if (header.protocol != 6 || header.destinationPort != 443 || header.sourcePort == 0 ||
        header.transportOffset + header.transportHeaderBytes != input.size) return null
    val offset = header.transportOffset
    fun read16(at: Int): Int = ((input[at].toInt() and 255) shl 8) or
        (input[at + 1].toInt() and 255)
    fun read32(at: Int): Long = ((read16(at).toLong() shl 16) or read16(at + 2).toLong())
    // SYN only, no ECN/NS, reserved bits, ACK, payload, or urgent pointer.
    if ((input[offset + 12].toInt() and 15) != 0 ||
        (input[offset + 13].toInt() and 255) != 2 ||
        read32(offset + 8) != 0L || read16(offset + 18) != 0) return null
    if (!validSynOptions(input, offset + 20, offset + header.transportHeaderBytes)) return null

    val ipBytes = if (header.ipVersion == 4) 20 else 40
    // MSS is derived from the bounded virtual-link MTU, not a claimed path MTU.
    val mss = minOf(1460, mtu - ipBytes - 20)
    val reply = ByteArray(ipBytes + 24) // 20-byte TCP + 4-byte MSS option
    fun put16(at: Int, value: Int) {
        reply[at] = (value ushr 8).toByte()
        reply[at + 1] = value.toByte()
    }
    fun put32(at: Int, value: Long) {
        put16(at, (value ushr 16).toInt())
        put16(at + 2, value.toInt())
    }
    val source = header.destination.address
    val destination = header.source.address
    if (header.ipVersion == 4) {
        reply[0] = 0x45
        put16(2, reply.size)
        put16(6, 0x4000) // Do not fragment.
        reply[8] = 64
        reply[9] = 6
        source.copyInto(reply, 12)
        destination.copyInto(reply, 16)
    } else {
        reply[0] = 0x60
        put16(4, 24)
        reply[6] = 6
        reply[7] = 64
        source.copyInto(reply, 8)
        destination.copyInto(reply, 24)
    }
    put16(ipBytes, header.destinationPort)
    put16(ipBytes + 2, header.sourcePort)
    put32(ipBytes + 4, serverIsn)
    put32(ipBytes + 8, (read32(offset + 4) + 1) and 0xffff_ffffL)
    reply[ipBytes + 12] = 0x60 // 24-byte TCP header
    reply[ipBytes + 13] = 0x12 // SYN | ACK
    put16(ipBytes + 14, 0) // Fail closed until receive flow control exists.
    reply[ipBytes + 20] = 2 // MSS
    reply[ipBytes + 21] = 4
    put16(ipBytes + 22, mss)
    val pseudo = wordSumTcp(source, 0, source.size) +
        wordSumTcp(destination, 0, destination.size) + 24 + 6
    put16(ipBytes + 16, checksumTcp(pseudo + wordSumTcp(reply, ipBytes, 24)))
    if (header.ipVersion == 4) put16(10, checksumTcp(wordSumTcp(reply, 0, 20)))
    return reply
}

/** Accept only well-formed, common SYN options; reject unknown or ambiguous TLVs. */
private fun validSynOptions(packet: ByteArray, start: Int, end: Int): Boolean {
    var at = start
    while (at < end) {
        when (val kind = packet[at].toInt() and 255) {
            0 -> return (at + 1 until end).all { packet[it] == 0.toByte() }
            1 -> at++
            else -> {
                if (at + 2 > end) return false
                val size = packet[at + 1].toInt() and 255
                if (size < 2 || size > end - at) return false
                if (size != when (kind) { 2 -> 4; 3 -> 3; 4 -> 2; 8 -> 10; else -> -1 }) return false
                if (kind == 2 && packet[at + 2] == 0.toByte() &&
                    packet[at + 3] == 0.toByte()) return false
                if (kind == 3 && (packet[at + 2].toInt() and 255) > 14) return false
                at += size
            }
        }
    }
    return true
}

private fun wordSumTcp(bytes: ByteArray, offset: Int, length: Int): Int {
    var sum = 0
    var at = offset
    while (at + 1 < offset + length) {
        sum += ((bytes[at].toInt() and 255) shl 8) or (bytes[at + 1].toInt() and 255)
        at += 2
    }
    if (at < offset + length) sum += (bytes[at].toInt() and 255) shl 8
    return sum
}

private fun checksumTcp(initial: Int): Int {
    var sum = initial
    while (sum > 0xffff) sum = (sum and 0xffff) + (sum ushr 16)
    return sum.inv() and 0xffff
}
