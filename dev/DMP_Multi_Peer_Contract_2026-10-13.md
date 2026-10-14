# Multi-peer endpoint contract proposal — 2026-10-13

Status: revised coordinator proposal for independent review. This freezes only
the minimum software interfaces for the owner-authorized four-peer scope; it is
not implementation or conformance evidence. No normative wire bytes change.

## Implementation sequence

1. Extend the existing logical endpoint to own a bounded table of up to four
   authenticated peers. Keep identity and reliability records shared and
   caller-owned; give each peer isolated association and stream-decoder state.
2. Carry a generation-fenced peer handle through application operations,
   receive dispatch, callbacks, retained replies, and transport submissions.
   Each peer may have one active and one draining association. Noise remains in
   the existing peer-specific `dmp_hs` objects.
3. Keep endpoint-wide storage/adapter limits shared across peer traffic, enforce
   `operations_per_service` per peer and service, and preserve per-peer
   reassembly limits. Exercise cross-peer isolation and pressure before adding
   the SAMPLE-1, handshake transport, and epoch-owner packages.
4. Run `four_serial` and `four_parallel` through the same logical endpoint and
   real library sources. Reconcile all 137 normative rows against actual test
   IDs after the software packages land; keep P01C target evidence separate.

## Proposed minimum contracts

### Peer and association ownership

- A peer handle is `{slot, generation}`. Retirement makes the slot unavailable
  until all accepted TX callbacks and peer-bound retained message/cache records
  have settled. Only then may reuse increment generation. A late callback can
  release only its TX-generation-owned bytes and cannot mutate a new peer.
- A peer slot binds one authenticated `(namespace_id, principal)` and a
  peer-specific `dmp_hs*`. It owns the current active identity/attempt and at
  most one draining identity/attempt with an absolute expiry.
- Identity contexts remain in one endpoint-owned table. Capacity covers at
  least `2 * max_peers` live active/draining contexts plus any independently
  admitted bootstrap candidates. One peer's rotation or revocation cannot
  cancel or retire another peer's associations.
- Every peer-specific handshake uses one endpoint-wide security-admission
  owner. It atomically reserves/releases local RX CIDs across pending, active,
  draining, and referenced associations. Before confirmation/activation it
  atomically checks and reserves both directional `(namespace, origin, epoch)`
  keys against all endpoint-retained associations and message identities.
  Epoch reservations release only when their message/cache references expire;
  CID reservations release only after all association and queued/live transport
  references are gone. Capacity failure or collision fails closed. Standalone
  single-handshake tests may use a local registry; a multi-peer endpoint may
  not silently fall back to per-handshake registries.
- RX identifies its peer by a generation-fenced peer handle supplied by the
  binding. The endpoint then verifies CID, principal, namespace, epoch and
  authenticated frame under that peer's own handshake. A routing hint alone
  never authenticates a frame.

### Addressed API and reply routing

- Bind, rotate, revoke, RX, submit, complete and abandon operations take an
  explicit peer handle. Notices return the same handle. No operation silently
  selects a default peer once the endpoint supports more than one.
- Reliability sender/history/result/correlation records retain their peer
  handle and identity-context generation. A reply, ACK, retry, fragment status,
  or terminal outcome is emitted only on the recorded peer route and association
  allowed by the original message/association lifetime.
- Each peer's active association is the only route for locally originated
  messages after local rotation commits. A draining association remains valid
  for authenticated receive traffic until the earlier of its original lifetime
  and the explicit drain deadline. The wire format has no drain-boundary marker,
  so the receiver cannot distinguish a delayed first delivery/retry from new
  work sent by a peer that has not yet switched; both are admitted during that
  bounded window and remain subject to ordinary peer/service quotas, ACLs and
  deadlines. This is the accepted reliability tradeoff. Replies and retries
  remain on the association of the original work and cannot outlive the bound.
  Unknown, expired or cross-peer correlations fail closed.

### Shared and per-peer quotas

- `peers` is the endpoint-wide peer ceiling, up to four. Reliability storage
  arrays (`sender_slots`, `result_slots`, `history_slots`, `correlation_slots`,
  `adapter_slots`, `application_queue_slots`, and `control_slots`) are shared
  endpoint-wide ceilings; they are not cloned once per peer.
- `operations_per_service` remains a per-peer/per-service admission ceiling.
  Count all active and draining association epochs for the stable peer handle
  together; a rotation cannot grant another outstanding operation. Assembly
  and tombstone admission follows the same stable peer and sums active/draining
  epochs, while duplicate/tombstone identity keeps its exact association
  context. Backing storage is sized to the validated aggregate. Global storage
  exhaustion is bounded and cannot evict another peer's retained accepted
  operation.
- Pending handshake attempts and concurrent crypto operations are endpoint-wide
  budgets, not four copies of a per-peer allowance. The endpoint-wide admission
  owner enforces configured pending, scratch, global-work, and ingress-work
  limits for every peer handshake. Pending/scratch slots are acquired before
  attempt/provider work and released after abort/completion and provider use has
  settled. Global/ingress work is charged at the existing SEC-1 work points and
  cannot be reset or replenished by adding peers or attempts. Calls are
  serialized; the owner fails closed when a shared reservation is unavailable.
- Configure and prove `four_serial` at one crypto slot and `four_parallel` at
  two crypto slots, while retaining four peers, four pending attempts, four
  active plus four draining associations, two services, and four application
  operations in each declared per-endpoint envelope.

### Transport lifetime and memory

- Add the addressed peer handle to each accepted transport submission. The
  binding owns routing from that handle to its peer path; the endpoint remains
  the single logical transport owner and token-generation namespace.
- Preserve `DMP_TX_COPY` (bytes copied before submit returns) and
  `DMP_TX_BORROW` (immutable bytes remain pinned until exactly one terminal
  callback). Accepted cancellation does not release storage; stale callbacks
  are checked against peer-slot and TX-slot generations. A retired peer slot is
  not reusable while an accepted borrowed submission or retained operation/cache
  still refers to it. A terminal callback releases its TX-generation-owned
  storage before peer retirement may complete. If a required callback never
  arrives, keep the slot/resources held and fail closed rather than reuse memory
  still visible to a transport.
- Keep endpoint API calls and completion processing serialized. Use shared
  endpoint-wide TX/adaptor slots and control reserve. Ingress stream decoder
  candidates are isolated per peer; account up to `max_peers` decoder state and
  candidate bytes.
- Account host reservations as fixed endpoint metadata plus per-peer peer/decoder
  metadata, identity contexts, up to two association records per peer,
  configured handshake/provider owners and their retained/scratch state, and
  the shared reliability/reassembly/TX payload arrays. Runtime target peaks
  remain P01C evidence.

### MTU dimensions

- The normative manifest distinguishes the decoded DMP Core frame MTU
  (`forward_mtu` / `return_mtu`) from `encoded_mtu`, the complete binding frame
  including any binding envelope and delimiter. They are different quantities.
- DIRECT-1/SIM-STREAM-R has a 256-byte DMP Core frame ceiling and a 263-byte
  maximum Stream R encoded binding frame, including its COBS delimiter. The
  packet binding adds no Stream R expansion, so its encoded frame cap equals
  the core frame cap.
- Update the C admitted-profile/endpoint buffer contract so core parsing and
  encoding use the directional core bound, while transport buffers/capabilities
  use the encoded binding bound. Derive and validate the Stream R bound from
  the core ceiling; never pass 263 as the decoded-core limit. Preserve
  `tests/provider/experiment_manifest.json::mtu_bytes = 256` as a core-frame
  limit unless a separately reviewed manifest revision states otherwise.
- Stream R's initial empty synchronization delimiter is a separate binding
  action on coordinated open/reset, before frame transmission, as specified by
  the manifest contract. Do not prefix every frame. The delimiter is accounted
  in open/reset airtime and transport control resources, not in `encoded_mtu`;
  each encoded frame submission is at most 263 bytes for the 256-byte core
  profile. If the binding API cannot represent this lifecycle, add a narrow
  synchronization operation/state instead of silently increasing every frame
  submission by one byte.

### Shared security-admission interface

- One endpoint-owned, caller-provided admission state is shared by every
  `dmp_hs` instance attached to that endpoint. Add the narrow port to the
  existing handshake API; keep Noise state transitions, cryptographic calls,
  message encoding, and owned state machine in the existing handshake module.
- The port has bounded reserve/release operations for pending attempts,
  simultaneous provider scratch, local RX CIDs, and the two epoch keys. It also
  charges global and ingress work at the current SEC-1 work points. Each
  successful reservation has an opaque generation-fenced token so abort,
  timeout, peer removal, and delayed provider cleanup release exactly the
  reservation they acquired.
- Candidate activation is one serialized transaction: reserve/check both
  directional epoch keys, complete existing local authorization and FINISH /
  READY requirements, then publish association ownership. On any failure,
  release the candidate's unreferenced reservations and keep it inactive.
- Epoch-key reservations are reference-counted by endpoint-owned live identity,
  reliability, confirmation, and cache records. Removing one `dmp_hs` object
  cannot release a key still needed by another module's retained record.

## Review questions

1. Does a shared reliability arena plus peer-tagged records provide safe
   isolation without multiplying the four-peer storage envelope?
2. Is the shared endpoint admission interface sufficient to guarantee endpoint
   CID uniqueness, both directional epoch-key reservations, and shared SEC-1
   pending/scratch/work limits across peer-specific handshakes?
3. Is adding a peer route to `dmp_tx_submission` the narrowest transport API
   change, with COPY/BORROW and completion semantics preserved?
4. Are endpoint-wide reliability quotas, per-peer/service operations, and the
   handshake/provider shared pending/crypto budgets assigned to the correct
   owners and unambiguously testable?
5. Do stable-peer aggregate operation/assembly quotas preserve active/draining
   isolation and exactly match profile/manifest language?
6. Is the proposed 256-byte core / 263-byte Stream R mapping, plus one separate
   open/reset sync delimiter and no per-frame prefix, consistent with manifests,
   current stream codec, endpoint buffers, and timing/resource accounting?

Review is read-only and must identify concrete counterexamples or confirm the
reviewed scope and remaining gaps before code changes begin.
