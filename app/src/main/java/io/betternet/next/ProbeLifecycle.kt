package io.betternet.next

/** A diagnostic is valid only for its original screen and selection generation. */
internal fun probeStillCurrent(expected: Int, actual: Int, destroyed: Boolean): Boolean =
    !destroyed && expected == actual
