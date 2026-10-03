# P11 bounded reassembly acceptance

**Status:** independent source review pending. The worker turn completed, but
P11 is not accepted until the read-only review closes and the coordinator
records its result.

## Scope and provenance

- Package: P11, bounded fixed-stride reassembly.
- Git baseline: `feat/initial-version` at
  `fdf0456e0a0c79118c77061f7fdf1ad5136a879c`.
- Author workspace baseline: `snap-3b1f87f0ed3e4e5e033f089d`.
- Worker: Agent Broker route `dmp_cursor_large` (Cursor,
  `grok-4.7-high`, configured `high` effort), session
  `session-b6770e61209c024ec9c0c337`, turn
  `turn-40b707c9750f6ac5b3c2917a`; terminal state `SUCCEEDED`.
- Worker source additions are limited to `src/reassembly/reassembly.c` and
  `tests/reassembly/test_reassembly.c`. Coordinator-owned API, admission,
  profile, normative, CMake, and manifest-validator changes are outside the
  worker write set.

## Contract and integration

The engine uses caller-owned fixed-stride storage, accepts verified plaintext
and canonical immutable metadata, reserves the complete buffer, identity
context retain, and future tombstone before the first slice, and publishes a
handle only after complete assembly. It validates exact slice geometry,
duplicates/conflicts, immutable frame associations, quotas and absolute
deadlines. Expiry releases payload/context ownership and permanently fences the
message identity until that context is retired; tombstones are not evicted.
Completed messages remain borrowed until release. There is no inactivity timer
in the admitted profile.

Manifest contract v2 charges 48 bytes per bounded tombstone. The six initial
host deployment profiles reserve 16 tombstones per peer. During acceptance the
coordinator found that the executable C manifest validator still expected 15
resource charges; it now validates the v2 tombstone count and byte floor, and
enforces that the tombstone budget covers active assemblies.

The coordinator also found that all validators checked only
`message_bytes` for each endpoint assembly slot, even though the deployment
budget reserves an additional 512 bytes for metadata and slot state. Python,
device C, and harness validators now enforce `message_bytes + 512`; a C
compile-time assertion ensures the fixed slot plus canonical metadata fit that
reserve. The six deployment manifests already met the floor, so their exact
bytes and digests did not change. A boundary mutation checks rejection at 511
reserve bytes in both Python and C profile-parity paths.

## Coordinator verification

- Clean configured host build before the final reserve-validator addition:
  `cmake --build build/host --target clean`, followed by
  `cmake --build build/host --parallel 2`; all 52 build steps passed.
- After the reserve-validator addition, `cmake --build build/host --parallel 2`
  rebuilt and linked all affected C targets in 18 steps.
- Full CTest: `ctest --test-dir build/host --output-on-failure` — **17/17
  passed**, including `reassembly.direct`, `identity.profile_parity`,
  `profiles.contract`, and `harness.subprocess`.
- Python profile suite: **24/24 tests passed**.
- The C harness accepted all six deployment manifests; the same six-profile
  boundary is exercised by the passing `harness.subprocess` test.
- The C reassembly suite covers exact and short tails, out-of-order/final-first
  arrival, identical and conflicting duplicates, association mismatches,
  reservation and quota failures, expiry fences, context retirement, stale
  handles, and deadline overflow.

## Review and limits

The read-only broker reviewer completed source review of target snapshot
`snap-0e7b805be21cf8a435d42142` against author baseline
`snap-3b1f87f0ed3e4e5e033f089d`. It reported no active P0–P2 findings and
confirmed the fixed-stride, atomic reservation, quota, deadline, tombstone,
retirement, and manifest-v2 behavior. That snapshot predates the 512-byte
assembly reserve enforcement above, so a final review of the updated target is
pending. The updated target is sealed as
`snap-7d33a9cebada7cf17a2683b3`. Two final-review turns failed before
inference with `INPUT_UNSUPPORTED`: the broker could not generate a text diff
for ignored binary Python cache paths (`tests/profiles/__pycache__` and
`profiles/schema/__pycache__`). Removing local caches did not remove the
baseline-to-target binary paths. The registered snapshot coverage must exclude
`**/__pycache__/**` (or preserve identical cache bytes) before the final review
can run. The exact route, turn IDs, impact, and recovery are in
`dev/DMP_Execution_Log.md`.

The host authenticated-context fixture does not perform a handshake, AEAD, or
replay check. These results do not establish SEC-1, endpoint integration, MCU,
independent-peer, interoperability, or physical transport conformance. P12
remains the next package and is not started by this acceptance.
