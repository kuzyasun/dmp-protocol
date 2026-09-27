# P04 independent review and coordinator acceptance

Reviewer: independent `gpt-6-astra`, xhigh, read-only. Coordinator: source/diff
inspection, real build/test execution and final package acceptance. The reviewer
read logs directly but did not independently execute the commands. Worker:
`gpt-6-luna`, high, limited to base implementation and three consumer sources.

Reviewed: five public headers, `src/core/base.c`, three C/C++ tests, their CMake
registration and root archive graph, `dev/DMP_Core_Interfaces.md`,
`tests/harness/PROTOCOL.md`, and the actual validation logs linked in README.

| Confirmed finding | Resolution |
|---|---|
| cancel(context,token) ambiguous if two owners reuse a token in one context | Exactly one owner per transport context; shared drivers expose separate contexts; token uniqueness persists across resets |
| Framing init/encode/bound errors and overlap rules underdefined | Explicit unchanged state/bytes, written=0, nonoverlap, reset status and time/overflow rules |
| Horizon trace could hide undelivered copies after local completion | Separate pending-local and pending-delivery counters sampled before cleanup, explicit drop/copy definitions |
| Manifest ceilings did not select exact self-test event times | Exact FIFO source/return calendar, origin/arrival/completion times, quota/deadline rejection and cancellation state rules |
| Unused fault discovered at horizon contradicted pre-execution error trace | Preserve executed trace/counters, settle ownership, then append invalid-input terminal record |
| Timer could start after an incomplete L length prefix and wait indefinitely | L arms on first magic/prefix byte; R on first nonzero candidate after synchronization |

Coordinator additionally made same-time start/cancel ordering explicit: phase-2
cancellation can prevent a phase-3 start at the same timestamp; classification
uses actual started state. Corrected worker test entrypoints to three independent
executables before first build. No wire/security document or profile was changed.

Final reviewer conclusion: P04 can be accepted within its declared scope; no
unresolved material findings. Logs support Debug 6/6, Release core 3/3, final
header core 3/3, and the library-only archive with five exports and no undefined
references. Coordinator accepts P04 on that fixed source/test snapshot, recorded
by SHA-256 in checks.json.

This is foundation/interface acceptance, not implemented codec/framing/harness
or endpoint conformance. Actual adapter asynchronous races remain P07/P13-P15
work; target memory, sanitizers/fuzz and multi-toolchain gates remain pending.
