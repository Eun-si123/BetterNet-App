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
    if (!isSupportedDnsTunQuery(request)) return null
    val original = request.bytes
    val header = parseTunPacketHeader(original, original.size) ?: return null
    if (dnsResponse.size !in 12..1232) return null
    // A 16-bit DNS ID alone does not correlate a response to a question.
    // The authenticated upstream must also be bound to this outstanding request.
    if (!hasMatchingDnsQuestion(original, header.transportOffset + 8, original.size, dnsResponse)) return null

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
 * Validate a bounded, unfragmented DNS/UDP request before allocating pending
 * state. This does not authenticate any upstream or perform DNS resolution.
 */
internal fun isSupportedDnsTunQuery(request: TunIngressResult.Packet): Boolean {
    val packet = request.bytes
    val header = parseTunPacketHeader(packet, packet.size) ?: return false
    if (header.protocol != 17 || header.destinationPort != 53 || header.sourcePort == 0) return false
    val start = header.transportOffset + 8
    if (!isSupportedDnsQueryMessage(packet.copyOfRange(start, packet.size))) return false
    val udpLength = packet.size - header.transportOffset
    val checksum = u16(packet, header.transportOffset + 6)
    return checksum == 0 || validUdpChecksum(
        packet, header.transportOffset, udpLength,
        header.source.address, header.destination.address
    )
}

/**
 * Only forward one well-formed question, optionally with a single EDNS(0) OPT
 * record. Reject undeclared trailing bytes, arbitrary additional records and
 * malformed EDNS options before any upstream I/O. Only zero-filled EDNS
 * padding (option 12) is permitted for now. In particular, do not silently
 * forward client-subnet, cookie or other identifying/unknown EDNS options
 * to a new resolver without a separate privacy and compatibility review.
 */
internal fun isSupportedDnsQueryMessage(query: ByteArray): Boolean {
    if (query.size !in 17..1232) return false
    if ((query[2].toInt() and 0xfe) != 0 ||
        (query[3].toInt() and 0x4f) != 0 ||
        u16(query, 4) != 1 || u16(query, 6) != 0 || u16(query, 8) != 0) return false
    val questionEnd = dnsQuestionEnd(query, 0, query.size) ?: return false
    return when (u16(query, 10)) {
        0 -> questionEnd == query.size
        1 -> {
            // OPT: root NAME, TYPE=41, UDP payload size, extended RCODE,
            // EDNS version, flags, and RDLEN followed by bounded TLV options.
            if (questionEnd + 11 > query.size ||
                query[questionEnd] != 0.toByte() ||
                u16(query, questionEnd + 1) != 41 ||
                u16(query, questionEnd + 3) !in 512..4096 ||
                u16(query, questionEnd + 5) != 0 ||
                (u16(query, questionEnd + 7) and 0x7fff) != 0) return false
            val optionsStart = questionEnd + 11
            if (u16(query, questionEnd + 9) != query.size - optionsStart) return false
            var at = optionsStart
            while (at < query.size) {
                if (query.size - at < 4) return false
                val optionCode = u16(query, at)
                val optionLength = u16(query, at + 2)
                at += 4
                if (optionLength > query.size - at) return false
                // RFC 7830 padding must be all zero. No opaque options
                // cross the future DNS trust boundary by default.
                if (optionCode != 12 || (at until at + optionLength).any {
                    query[it] != 0.toByte()
                }) return false
                at += optionLength
            }
            true
        }
        else -> false
    }
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

/**
 * Accept only one uncompressed, identical IN question in a standard DNS
 * query/response pair. Reject pointers, malformed labels and truncated
 * questions rather than returning a same-ID answer for a different name/type.
 * This is correlation, not upstream authentication or full DNS validation.
 */
private fun hasMatchingDnsQuestion(
    queryPacket: ByteArray, queryStart: Int, queryEnd: Int, response: ByteArray,
): Boolean {
    val queryLength = queryEnd - queryStart
    if (queryLength < 17 || response.size < 17) return false
    if (queryPacket[queryStart] != response[0] ||
        queryPacket[queryStart + 1] != response[1]) return false
    val queryFlags = queryPacket[queryStart + 2].toInt() and 0xff
    val responseFlags = response[2].toInt() and 0xff
    if ((queryFlags and 0xfe) != 0 || // standard query, RD optionally set
        (responseFlags and 0xfa) != 0x80 || // QR, no opcode or truncation
        (queryPacket[queryStart + 3].toInt() and 0x4f) != 0 ||
        (response[3].toInt() and 0x40) != 0) return false
    if (u16(queryPacket, queryStart + 4) != 1 || u16(response, 4) != 1) return false

    val queryQuestionEnd = dnsQuestionEnd(queryPacket, queryStart, queryEnd) ?: return false
    val responseQuestionEnd = dnsQuestionEnd(response, 0, response.size) ?: return false
    val questionLength = queryQuestionEnd - (queryStart + 12)
    if (questionLength != responseQuestionEnd - 12) return false
    for (index in 0 until questionLength) {
        if (queryPacket[queryStart + 12 + index] != response[12 + index]) return false
    }
    return true
}

private fun dnsQuestionEnd(bytes: ByteArray, start: Int, limit: Int): Int? {
    var at = start + 12
    var nameLength = 1 // root terminator
    while (at < limit) {
        val labelLength = bytes[at++].toInt() and 0xff
        if (labelLength == 0) {
            if (at + 4 > limit) return null
            // IN class only; other classes are outside the first DNS path.
            if (u16(bytes, at + 2) != 1) return null
            return at + 4
        }
        if (labelLength > 63 || at + labelLength > limit) return null
        nameLength += 1 + labelLength
        if (nameLength > 255) return null
        at += labelLength
    }
    return null
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
