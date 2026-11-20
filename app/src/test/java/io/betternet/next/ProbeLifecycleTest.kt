package io.betternet.next

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ProbeLifecycleTest {
    @Test fun currentScreenAndSelectionAllowsProbe() {
        assertTrue(probeStillCurrent(7, 7, false))
    }

    @Test fun changedSelectionCancelsProbe() {
        assertFalse(probeStillCurrent(7, 8, false))
    }

    @Test fun destroyedScreenCancelsProbe() {
        assertFalse(probeStillCurrent(7, 7, true))
    }
}
