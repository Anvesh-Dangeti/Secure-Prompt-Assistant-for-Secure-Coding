"""Independent verification of a fix: rescan, then three gates. No LLM appears in this package.

    gate 1  target resolved     every finding of the weakness verifiably gone
    gate 2  no new findings     nothing introduced at the weakness's severity or above
    gate 3  function preserved  3a static structure (both modes) + 3b fixture tests (lab only)

All must pass for VERIFIED_RESOLVED; any failure is FIX_REJECTED with its
reason; missing evidence is UNVERIFIED. Nothing here ever defaults to a pass.
"""
