# P11 bounded reassembly implementation

## Frozen contract

- The engine accepts only structurally parsed FRAG frames after the caller has
  verified per-frame integrity/authentication, resolved authorization, and
  provided plaintext plus the canonical immutable TLVs with the per-frame
  SECURITY TLV omitted. Identity source keys are resolved through P09's bound
  context table. No application callback runs from this module.
- One assembly reserves its full message buffer, fixed metadata, identity
  context reference, and one future expiry-tombstone slot before accepting its
  first slice. The first accepted slice sets the absolute `assembly_ms` deadline.
- Out-of-order slices and identical duplicates are accepted. TTL and security
  packet number may differ; type, sequence/source context, service, ACK_REQ,
  geometry, route destination/mode, descriptor, integrity algorithm, security
  cipher/CID, and immutable metadata must match. A conflict never changes
  accepted bytes or deadline.
- Completion exposes one handle to the full copied message. Its payload and
  canonical metadata remain borrowed from caller-owned storage until release.
  Incomplete assemblies are never exposed. Completed assemblies do not expire
  while application ownership is held.
- Expiry converts the pre-reserved tombstone into a permanent identity fence
  for that context generation. It is retained until the caller has successfully
  retired that identity context and calls `dmp_reassembly_context_retired`.
  Tombstones are never evicted. A full per-peer tombstone budget refuses new
  assemblies before accepting their first slice. Context/table and engine calls
  are serialized by one owner.

## Resource contract

Manifest contract 2 adds `limits.assembly_tombstones_per_peer` and an
`assembly_tombstone` resource charge. The admitted global count is exposed as
`assembly_tombstone_slots`; operational limits use the admitted count and
per-peer value even if caller storage is larger. Endpoint assembly slots must
reserve `message_bytes + 512` bytes; that fixed metadata/slot reserve is
validated by the host, device and test-harness profile validators. The initial
host deployments
reserve 16 tombstones per peer (48 bytes each). The existing active assembly
charge remains separately bounded by `assemblies_per_peer`.

## Acceptance

- Exact-stride and short final tails; final fragment arrives first; complete
  only after all slices.
- Invalid geometry/length, MTU/message/chunk/fragment limits and rejected
  services do not reserve state.
- Duplicate equality and conflict, changed geometry/metadata/context, TTL and
  fresh-PN behavior, and no timer renewal.
- Atomic active-buffer/context/tombstone reservation, per-peer/global limits,
  expiry-to-tombstone conversion, no reopening, context-retirement cleanup,
  generation-safe handles, and undersized/overflowing storage.
- Run P11 tests, profile validator tests and admitted-profile parity; then run
  the full host build and relevant CTest set. Host evidence does not establish
  SEC-1, MCU or physical transport conformance.
