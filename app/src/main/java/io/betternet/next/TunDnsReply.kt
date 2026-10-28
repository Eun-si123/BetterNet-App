package io.betternet.next

import java.io.OutputStream

/**
 * Offline, packet-only A1 return-path primitive. Produces a DNS UDP response
 * for one already validated TUN request; it neither resolves DNS nor opens a
 * VPN, socket, or listener. The future caller must authenticate its upstream
 * and correlate responses to an outstanding request.
 */
internal fun buildDnsUdpReply(
    request: TunIngressResult.Packet,
    dnsResponse: ByteArray,
    mtu: Int,
): ByteArray? {
    require(mtu in 1280..9000) { "TUN MTU must be bounded and support IPv6" }
    val original = request.bytes
    val header = parseTunPacketHeader(original, original.size) ?: return null
    if (header.protocol != 17 || header.destinationPort != 53 || header.sourcePort == 0) return null
    if (dnsResponse.size !in 12..1232) return null

    val requestPayloadStart = header.transportOffset + 8
    if (original.size - requestPayloadStart < 12) return null
    // DNS ID must match; only a query may receive a response.
    if (original[requestPayloadStart] != dnsResponse[0] ||
        original[requestPayloadStart + 1] != dnsResponse[1] ||
        (original[requestPayloadStart + 2].toInt() and 0x80) != 0 ||
        (dnsResponse[2].toInt() and 0x80) == 0) return null

    val originalUdpLength = original.size - header.transportOffset
    val originalChecksum = u16(original, header.transportOffset + 6)
    if (originalChecksum != 0 && !validUdpChecksum(
            original, header.transportOffset, originalUdpLength,
            header.source.address, header.destination.address
        )) return null

    val ipHeaderBytes = if (header.ipVersion == 4) 20 else 40
    val udpLength = 8 + dnsResponse.size
    val packetLength = ipHeaderBytes + udpLength
    if (packetLength > mtu) return null

    val reply = ByteArray(packetLength)
    val source = header.destination.address
    val destination = header.source.address
    if (header.ipVersion == 4) {
        reply[0] = 0x45
        put16(reply, 2, packetLength)
        put16(reply, 6, 0x4000) // Don't fragment: no implicit IP fragmentation.
        reply[8] = 64
        reply[9] = 17
        source.copyInto(reply, 12)
        destination.copyInto(reply, 16)
        put16(reply, 10, internetChecksum(wordSum(reply, 0, 20)))
    } else {
        reply[0] = 0x60
        put16(reply, 4, udpLength)
        reply[6] = 17
        reply[7] = 64
        source.copyInto(reply, 8)
        destination.copyInto(reply, 24)
    }
    val udpOffset = ipHeaderBytes
    put16(reply, udpOffset, 53)
    put16(reply, udpOffset + 2, header.sourcePort)
    put16(reply, udpOffset + 4, udpLength)
    dnsResponse.copyInto(reply, udpOffset + 8)
    val sum = pseudoHeaderSum(source, destination, udpLength) +
        wordSum(reply, udpOffset, udpLength)
    val checksum = internetChecksum(sum)
    put16(reply, udpOffset + 6, if (checksum == 0) 0xffff else checksum)
    return reply
}

/**
 * One dormant, bounded TUN return-path write. A caller must supply an already
 * correlated and authenticated DNS response; this function performs no DNS
 * lookup, VPN activation, or network access. Invalid replies write nothing.
 *
 * OutputStream.write(ByteArray) either writes the complete IP datagram or
 * throws. Propagate I/O failures so a future pump can tear down its session;
 * never retry an uncertain partial write as a new datagram.
 */
internal fun writeOneDnsTunReply(
    output: OutputStream,
    request: TunIngressResult.Packet,
    dnsResponse: ByteArray,
    mtu: Int,
): Boolean {
    val reply = buildDnsUdpReply(request, dnsResponse, mtu) ?: return false
    output.write(reply)
    return true
}

private fun u16(bytes: ByteArray, at: Int): Int =
    ((bytes[at].toInt() and 0xff) shl 8) or (bytes[at + 1].toInt() and 0xff)

private fun put16(bytes: ByteArray, at: Int, value: Int) {
    bytes[at] = (value ushr 8).toByte()
    bytes[at + 1] = value.toByte()
}

private fun wordSum(bytes: ByteArray, offset: Int, length: Int): Int {
    var sum = 0
    var index = offset
    val end = offset + length
    while (index + 1 < end) {
        sum += u16(bytes, index)
        index += 2
    }
    if (index < end) sum += (bytes[index].toInt() and 0xff) shl 8
    return sum
}

private fun pseudoHeaderSum(source: ByteArray, destination: ByteArray, udpLength: Int): Int =
    wordSum(source, 0, source.size) + wordSum(destination, 0, destination.size) +
        udpLength + 17 // IPv4/IPv6: zero bytes and upper length bits contribute zero.

private fun internetChecksum(sumInput: Int): Int {
    var sum = sumInput
    while (sum > 0xffff) sum = (sum and 0xffff) + (sum ushr 16)
    return sum.inv() and 0xffff
}

private fun validUdpChecksum(
    packet: ByteArray, offset: Int, length: Int,
    source: ByteArray, destination: ByteArray,
): Boolean = internetChecksum(
    pseudoHeaderSum(source, destination, length) + wordSum(packet, offset, length)
) == 0
