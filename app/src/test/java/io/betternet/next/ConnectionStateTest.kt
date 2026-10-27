package io.betternet.next

import org.junit.Assert.assertEquals
import org.junit.Test

class ConnectionStateTest {
    private fun snapshot(present: Boolean = true, validated: Boolean = false, portal: Boolean = false) =
        ConnectionState(present, validated, portal, false, ConnectionState.Kind.WIFI)

    @Test fun disconnectedOutranksConflictingFlags() {
        assertEquals(ConnectionState.Assessment.DISCONNECTED,
            snapshot(present = false, validated = true, portal = true).assessment())
    }
    @Test fun captivePortalOutranksValidation() {
        assertEquals(ConnectionState.Assessment.CAPTIVE,
            snapshot(validated = true, portal = true).assessment())
    }
    @Test fun validationAndUnknownAreDistinct() {
        assertEquals(ConnectionState.Assessment.VALIDATED, snapshot(validated = true).assessment())
        assertEquals(ConnectionState.Assessment.UNVALIDATED, snapshot().assessment())
    }
}
