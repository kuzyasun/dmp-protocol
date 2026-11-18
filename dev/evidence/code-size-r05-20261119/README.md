# DMP R05 endpoint helpers

The baseline is the accepted R04 commit `a3dfca4`.
[R04 review and evidence](../code-size-r04-20261118/README.md).

## Probe correction

The NONE endpoint used its shared decoded fragment frame to size reliable
DATA/EVENT and explicit fragmented DATA submissions. A packet adapter may
still be borrowing that frame for another peer. The probes now use the
existing header-only Core preflight into local scratch. Core checks the
complete header, payload and trailer against the directional MTU.

A successful NONE preflight still rejects inputs overlapping the exact
range the previous encoder would have occupied. This keeps the idle-buffer
alias status and runs before retain or sequence consumption. The SEC-1
preflight retains its existing largest-PN geometry and borrows no transport
storage.

The multi-peer NONE regression holds a fragment in an asynchronous packet
adapter. It checks byte-for-byte immutability after a rejected small
fragmented submission, a valid fragmented submission and a reliable DATA
submission for another peer. It also checks sequence consumption, the idle
alias status for both entry points, and completion against the original
peer. The initial regression reproduced the changed frame bytes with R04
and passed after the probe change in isolation. The final fixture also
failed at the ownership assertion against the original R04 library and
passed against R05. [Regression and test excerpts](verification.txt).

## Endpoint consolidation

- The checked peer-route helper shares peer selection followed by active
  route selection. Callers retain their individual argument and failure
  mappings. Encoder completion still selects the peer's active context.
- Reservation storage clears through the existing store operation. Active
  and draining tokens retain their separate public fields. Release clears
  the selected reservation only after the provider accepts its tokens.
- Staged fragment and telemetry handles share validation and lease release.
  Promotion of the next telemetry payload and expiry remain in the
  owning branches.
- Reliable REQ, DATA and EVENT share size admission. DATA and EVENT share
  their peer and authorization preflight. Service 0 remains the secured
  control request path. The freshness helper is reused for ACL denial and
  after ordinary reliability RX where the service/type and outcome guards
  agree.

## Validation

- Independent Sol 6.2 high review confirmed the ownership correction and
  found a potential change to the NONE idle-scratch alias status. The
  exact-range check and new test retain that status. The reviewer rechecked
  the correction and found no further issues.
- The closeout Sol 6.2 high review confirmed the remaining endpoint
  behavior and matched all 28 recorded artifact digests. It requested
  a portable regression transcript, a paired build recipe and static
  frame sums for the two changed call paths. Those records accompany
  this package.
- Windows GCC 15.2.0, Release, with the pinned Noise/libsodium provider.
  Ninja builds and CTest each ran with a single worker. The R04 host
  recipe applies with `build/r05-host`. All 104 selected CTests passed,
  including the 100 endpoint cases, handshake/transport, reliability and
  FRAG_STATUS. Both DMP archive allocator checks passed.
  [CTest excerpts](verification.txt).
- The independent peer suite passed all 454 cases with both C executables
  enabled. It included SEC-1 and NONE SAMPLE-1, mixed path, COPY/BORROW
  interop, and loopback TCP. [Peer excerpts](verification.txt).

## Paired ESP-IDF links

The two R04 qualification builds were reused for R05. The retained baseline
ELF, map, binary and config matched the active build directories before
the new links. The disposable source was checked against the R04 tree and
only the endpoint implementation changed. On S3 Ninja also rebuilt the
byte-identical R04 reliability source after its timestamp changed during
the earlier target build. Its linked object sections are identical in
the pair. C3 rebuilt only the endpoint C source before linking.

ESP-IDF 6.1, GCC 15.2.0 and the qualification configuration are from the
[R04 recipe](../code-size-r04-20261118/commands.md). Each link ran with
`IDF_PY_BUILD_JOBS=1`. Each pair matched configuration, dependency lock,
linker scripts and linker command. The linked Noise/sodium sizes and app
static RAM matched as well.

| Target | DMP Flash R04 → R05 (B) | Endpoint object Flash R04 → R05 (B) | Image estimate R04 → R05 (B) | Padded `.bin` R04 → R05 (B) |
| --- | ---: | ---: | ---: | ---: |
| ESP32-S3 | 87,582 → 87,417 (−165) | 26,372 → 26,207 (−165) | 889,683 → 889,519 (−164) | 889,792 → 889,632 (−160) |
| ESP32-C3 | 91,963 → 91,933 (−30) | 26,792 → 26,762 (−30) | 929,778 → 929,748 (−30) | 930,144 → 930,112 (−32) |

The linked prologues show the same own frame for `take_frame` on S3
(864 bytes) and C3 (880 bytes), and for `dmp_endpoint_poll` (320 bytes on
both). The summed local frames on the REQ size-probe path rise by 64 bytes
on both targets. The staged release path from `release_peer_buffer_contexts`
to the identity release call rises by 64 bytes on S3 and 32 bytes on C3.
These are static frame sums along those paths. Hardware operation, runtime
stack high-water and latency were outside the offline run.
[Measurements and artifact digests](size-measurements.txt) · [Reproduction commands](commands.md).
