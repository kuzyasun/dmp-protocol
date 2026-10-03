# P10 direct reliability implementation plan

P10 implements the main specification's direct, unfragmented reliable
request/result exchange on top of the accepted P09 identity/profile contracts
and P07 transport harness. Its scope is `REQ`, `RSP`, `ERR`, and `ACK`; routed
delivery, fragmentation/reassembly, generic reliable `DATA`/`EVENT`, SEC-1, and
application schemas remain outside this package.

The coordinator freezes `include/dmp/reliability.h` and root build/test
registration. The worker owns only `src/reliability/reliability.c`,
`tests/reliability/CMakeLists.txt`, and
`tests/reliability/test_reliability.c`. The implementation uses caller-owned
bounded pools sized from P09's validated endpoint charges and limits; it does
not allocate, silently evict live state, or renew deadlines on duplicates.

Ingress to P10 carries a structural frame view, resolved service, and verified
plaintext as separate values. The caller must complete integrity/authentication
and service payload validation first. A protocol-rejected request uses a
separate cached-rejection entry point and is never reported as accepted. The
test-manifest contract's late-result behavior is used for this implementation:
ACK a valid retained late result, never repeat the application result callback,
and emit a payload-free diagnostic event.

Validation will cover receipt versus result, immediate result substitution,
loss/retry/duplicate and cached rejection behavior, deadlines and cancellation,
result retention, correlation/tombstone expiry, quota pressure, stop-and-wait
with ACK bypass, and delayed transport completion/buffer ownership. These are
host structural endpoint tests; SEC-1, MCU, independent-peer, and physical
transport acceptance remain later gates.

## Coordinator review checkpoint

The first independent API review found gaps in cached-rejection re-entry,
protocol/application ERR classification, notice payload lifetime, canonical
duplicate metadata, pool capacity/operational-limit validation, and cancel/TX
ownership. The implementation turn was cancelled before it changed any files.
The coordinator is closing those findings in the public contract and will
seal a new target before dispatching implementation. The review confirmed the
current P10 profiles are single-peer (`peers == 1`); this ABI explicitly binds
one engine/context to that admitted scope.

The first closure pass confirmed those fixes and found two further contract
details to state explicitly: `complete` accepts only `(application_err=false,
wire_status=0)` or `(application_err=true, wire_status>=64)`, and both
`DMP_TX_CANCELLED_UNSENT` and `DMP_TX_FAILED_UNSENT` prove the current attempt
did not transmit; any attempt that transmitted or may have transmitted makes
the exchange `UNKNOWN`; cancellation before any accepted transport submission
is `LOCAL_UNSENT`. The contract now states those outcomes as a single
exhaustive classification. The final API closure review completed successfully:
reviewer turn `turn-74a13665074a409ea9627221`, artifact
`art-0a8dff0138592b11c34d20cb`, baseline
`snap-0a0dbbbc54fb3284f0cbfd25`, target
`snap-1c7684daa52c8a2cce3ff09d`. It confirmed the cancellation classification
is exhaustive and reported no residual or new P0-P2 findings. Implementation
may proceed against a fresh sealed snapshot of the frozen header and build
registration.

## Implementation review checkpoint

The Cursor implementation turn timed out before reporting or sealing a final
snapshot. Coordinator syntax checks compiled both implementation and tests;
the clean GCC/MinGW host build succeeds, but `reliability.direct` fails on four
assertions. Independent review of the retained target found two implementation
defects: an inbound result sender with a zero send deadline is released on the
first poll before its receipt ACK; and a late completion allocates the terminal
result SEQ before the due ACK. The test assertions reflect these defects.
Coordinator fixes, rerun validation, and the final closure review are recorded
below. SEC-1, endpoint, MCU, interoperability and physical transport gates
remain outside P10.

Coordinator fixes now preserve the inbound result sender through its result
deadline and defer terminal SEQ allocation until any due receipt ACK has been
submitted. Storage validation accepts caller buffers at or above profile
minima while keeping runtime slot quotas at the admitted counts; initialization
rejects multi-peer profiles, and receive handling rejects ROUTE as well as
FRAG. Added targeted regression coverage for those contracts. The explicit GCC
host build and `reliability.direct` pass. The full host build also passes; 14 of
15 CTests pass, while the unrelated `harness.subprocess` suite cannot create
files in Windows temporary directories (`PermissionError`). Independent
closure review against baseline `snap-9261f786fd5144306a8e7daf` and final target
`snap-720d3be8d6c007aac6523d67` completed on reviewer route
`dmp_cursor_reviewer`, turn `turn-d9f0485de21f19c997310b33`, findings artifact
`art-07485688a0ee086119fec258`. It confirmed the previous P0/P1 fixes and
reported no remaining actionable P0-P2 findings. Coordinator acceptance is
limited to P10 host reliability behavior; SEC-1, endpoint integration, MCU,
independent-peer, and physical transport gates remain outside this package.
