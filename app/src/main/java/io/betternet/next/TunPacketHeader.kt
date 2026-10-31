package io.betternet.next

import java.net.InetAddress

/**
 * Read-only first step toward an A1 TUN data path. Validates one complete IP
 * datagram before any transport processing. Unsupported/fragmented packets
 * are rejected, never silently reinterpreted as a different protocol.
 * No VPN service calls this parser and it never sends network traffic.
 */
internal data class TunPacketHeader(
    val ipVersion: Int,
    val protocol: Int,
    val source: InetAddress,
    val destination: InetAddress,
    val sourcePort: Int,
    val destinationPort: Int,
    val transportOffset: Int,
    val transportHeaderBytes: Int,
    val totalBytes: Int,
)

/** Validate the IPv4 header's one's-complement checksum before reading its addresses. */
private fun hasValidIpv4HeaderChecksum(packet: ByteArray, headerBytes: Int): Boolean {
    var sum = 0
    for (i in 0 until headerBytes step 2) {
        sum += ((packet[i].toInt() and 0xff) shl 8) or (packet[i + 1].toInt() and 0xff)
    }
    while (sum > 0xffff) sum = (sum and 0xffff) + (sum ushr 16)
    return sum == 0xffff
}

/** Returns null for unsupported, truncated, inconsistent or fragmented packets. */
internal fun parseTunPacketHeader(packet: ByteArray, readBytes: Int): TunPacketHeader? {
    if (readBytes !in 1..packet.size || readBytes > 65_575) return null
    fun u8(at: Int): Int = packet[at].toInt() and 0xff
    fun u16(at: Int): Int = (u8(at) shl 8) or u8(at + 1)

    val version = u8(0) ushr 4
    val ipHeaderBytes: Int
    val protocol: Int
    val addressBytes: Int
    val sourceOffset: Int
    val destinationOffset: Int
    when (version) {
        4 -> {
            if (readBytes < 20) return null
            ipHeaderBytes = (u8(0) and 0x0f) * 4
            // IPv4 options are not supported by this first forwarding boundary.
            if (ipHeaderBytes != 20 || u16(2) != readBytes) return null
            if (!hasValidIpv4HeaderChecksum(packet, ipHeaderBytes)) return null
            // Reserved bit, more-fragments flag, or nonzero fragment offset.
            if ((u16(6) and 0xbfff) != 0) return null
            protocol = u8(9)
            addressBytes = 4
            sourceOffset = 12
            destinationOffset = 16
        }
        6 -> {
            if (readBytes < 40 || u16(4) + 40 != readBytes) return null
            ipHeaderBytes = 40
            // No IPv6 extension-header or jumbogram support yet. Fail closed.
            protocol = u8(6)
            addressBytes = 16
            sourceOffset = 8
            destinationOffset = 24
        }
        else -> return null
    }
    if (protocol != 6 && protocol != 17) return null
    val remaining = readBytes - ipHeaderBytes
    if (remaining < if (protocol == 6) 20 else 8) return null
    val headerBytes = if (protocol == 6) {
        val length = (u8(ipHeaderBytes + 12) ushr 4) * 4
        if (length < 20 || length > remaining) return null
        // TCP checksums are mandatory for both IP families. Never admit a
        // corrupt segment to a future state machine or gateway forwarding path.
        if (!hasValidTransportChecksum(
                packet, ipHeaderBytes, remaining, sourceOffset, destinationOffset, addressBytes, 6
            )) return null
        length
    } else {
        if (u16(ipHeaderBytes + 4) != remaining) return null
        // IPv4 permits a zero UDP checksum; IPv6 requires one. If present,
        // verify it against the IP addresses and the entire UDP datagram.
        val checksum = u16(ipHeaderBytes + 6)
        if (checksum == 0 && version == 6) return null
        if (checksum != 0 && !hasValidTransportChecksum(
                packet, ipHeaderBytes, remaining, sourceOffset, destinationOffset, addressBytes, 17
            )) return null
        8
    }
    return TunPacketHeader(
        version, protocol,
        InetAddress.getByAddress(packet.copyOfRange(sourceOffset, sourceOffset + addressBytes)),
        InetAddress.getByAddress(packet.copyOfRange(destinationOffset, destinationOffset + addressBytes)),
        u16(ipHeaderBytes), u16(ipHeaderBytes + 2), ipHeaderBytes, headerBytes, readBytes,
    )
}

/**
 * Verify the complete TCP/UDP segment (header and payload) with the
 * IPv4/IPv6 pseudo-header. This binds transport bytes to IP addresses;
 * IPv4 UDP zero-checksum datagrams are handled separately by the caller.
 * Fragmented packets and IPv6 extension headers are rejected by the caller.
 */
private fun hasValidTransportChecksum(
    packet: ByteArray, offset: Int, length: Int,
    sourceOffset: Int, destinationOffset: Int, addressBytes: Int, protocol: Int,
): Boolean {
    fun sumWords(start: Int, count: Int): Int {
        var sum = 0
        var at = start
        val end = start + count
        while (at + 1 < end) {
            sum += ((packet[at].toInt() and 0xff) shl 8) or (packet[at + 1].toInt() and 0xff)
            at += 2
        }
        if (at < end) sum += (packet[at].toInt() and 0xff) shl 8
        return sum
    }
    // Both pseudo-header formats contribute the segment length and protocol.
    // The IPv6 32-bit length's high half is zero (jumbograms unsupported).
    var sum = sumWords(sourceOffset, addressBytes) +
        sumWords(destinationOffset, addressBytes) + length + protocol +
        sumWords(offset, length)
    while (sum > 0xffff) sum = (sum and 0xffff) + (sum ushr 16)
    return sum == 0xffff
}
