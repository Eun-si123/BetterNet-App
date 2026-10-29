package io.betternet.next

import org.junit.Assert.*
import org.junit.Test

/** Pure DNS framing checks: no socket, VPN, external DNS or test listener. */
class DnsQueryValidationTest {
    private fun query() = byteArrayOf(
        0x12, 0x34, 0x01, 0, 0, 1, 0, 0, 0, 0, 0, 0,
        1, 'a'.code.toByte(), 0, 0, 1, 0, 1,
    )

    private fun withOpt(): ByteArray {
        val message = query()
        message[11] = 1 // ARCOUNT: one OPT
        return message + byteArrayOf(
            0, 0, 41, 4, 0xd0.toByte(), // root, OPT, 1232-byte UDP budget
            0, 0, 0x80.toByte(), 0, // EDNS v0, DNSSEC OK
            0, 0, // RDLEN = 0
        )
    }

    @Test fun acceptsPlainAndBoundedEdnsQueries() {
        assertTrue(isSupportedDnsQueryMessage(query()))
        assertTrue(isSupportedDnsQueryMessage(withOpt()))
        val padded = withOpt().apply {
            this[this.size - 2] = 0
            this[this.size - 1] = 6 // six bytes of EDNS option TLV
        } + byteArrayOf(0, 12, 0, 2, 0, 0)
        assertTrue(isSupportedDnsQueryMessage(padded))
    }

    @Test fun rejectsTrailingBytesUndeclaredRecordsAndMalformedOpt() {
        val good = withOpt()
        val invalid = listOf(
            query() + byteArrayOf(0),
            query().apply { this[7] = 1 }, // answer count
            query().apply { this[9] = 1 }, // authority count
            query().apply { this[11] = 1 }, // OPT declared but missing
            good.clone().apply { this[11] = 2 }, // multiple additional records
            good.clone().apply { this[19] = 1 }, // non-root OPT name
            good.clone().apply { this[21] = 42 }, // not TYPE 41
            good.clone().apply { this[22] = 1 }, // UDP size below 512
            good.clone().apply { this[24] = 1 }, // nonzero extended RCODE
            good.clone().apply { this[25] = 1 }, // nonzero EDNS version
            good.clone().apply { this[26] = 1 }, // unknown EDNS flag
            good.clone().apply { this[29] = 1 }, // RDLEN larger than payload
            (good + byteArrayOf(0, 12, 0)).apply { this[29] = 3 }, // truncated option
            (good + byteArrayOf(0, 12, 0, 3, 1, 2)).apply { this[29] = 6 },
        )
        invalid.forEachIndexed { index, bytes ->
            assertFalse("invalid DNS variant $index", isSupportedDnsQueryMessage(bytes))
        }
    }

    @Test fun rejectsMalformedQuestionAndUnsupportedFlags() {
        val base = query()
        val invalid = listOf(
            ByteArray(16),
            base.clone().apply { this[2] = 0x81.toByte() }, // QR response
            base.clone().apply { this[3] = 1 }, // nonzero RCODE
            base.clone().apply { this[5] = 2 }, // multiple questions
            base.clone().apply { this[12] = 0xc0.toByte() }, // compression pointer
            base.clone().apply { this[18] = 3 }, // non-IN class
        )
        invalid.forEachIndexed { index, bytes ->
            assertFalse("invalid query $index", isSupportedDnsQueryMessage(bytes))
        }
    }
}
