# DMP R04 reliability slot and receive paths

Baseline `389b295441257b2fded7c4e010e2f942327dee6a` is the accepted R03 commit.
[R03 review and evidence](../code-size-r03-20261118/README.md).

## Scope

- Sender, result, history, correlation and adapter wrappers share the same
  release and reset operations. Generation stays in the first member, which
  is verified for all five slot types during compilation. Clearing a slot
  after release restores its generation. Reservation and rollback order
  remain with the typed lifecycle paths, including grouped reservations.
- The size probe and the send path share logical request, data/event and
  result field construction. The probe's logical result key and the send
  destination and sequence policy remain at their call sites. A deferred
  result reserves its sequence before asking for an adapter. A rejection
  reserves a sequence only once an adapter is available.
- Ordinary RX, the retained-request query and rejection ingress share
  expiry, source-key lookup and service resolution after their original
  argument and frame-type checks. Unacknowledged requests keep the retained
  rejection-only route. FRAG_STATUS keeps its separate validation and
  feedback path.

## Regression coverage

- The queue and ACK bypass case fills both application and control adapter
  slots. It checks receipt before the deferred result sequence, a stable
  result sequence while waiting for an adapter, and no rejection sequence
  use until an adapter is available. It checks the two emitted frames
  after delayed completion frees the buffers.
- The buffer ownership case forces the transport to reject submit after
  encoding and adapter reservation. It checks queued sender state,
  unchanged identity reference count, empty adapter slots, and a new
  generation when the same adapter is successfully reused.
- Existing reliability and endpoint tests cover expiry, stale handles,
  full quotas and queues, duplicate and conflict handling, delayed
  completion, secured traffic, and selective recovery.

## Source review and validation

Independent Sol 6.2 high review confirmed that the reserve, expiry and
release order is preserved. Its test finding led to checking actual
transport entry and the adapter generation on reuse. The reviewer
rechecked the corrected test and found no remaining source issues.
`git diff --check` passed. Raw working source SHA-256 values follow.

| Source | SHA-256 |
| --- | --- |
| `src/reliability/reliability.c` | `909479928f3cf3ed70fea1c98eddf9226158fb98af61c1408080b7191fe6475c` |
| `tests/reliability/test_reliability.c` | `e2273fb03af815d794ac90bdeffb9a1c37d80e6a8ed11e1cf3bdec9164609d51` |

The RBO worker disconnected before a baseline job could be created. RBO
rejected another targeted attempt in local fallback mode at source capture
because no agent was connected. The operator authorized the local host gate.

Two further independent Sol 6.2 high closeout reviews found no source or
test changes to make. The first requested portable evidence and an exact
host and firmware recipe. The second verified the recipes against the
configured host build, the source blobs against their digests, and the
measurement and verification excerpts against the local archives. The
verification excerpt labels the Git LF blobs separately from the raw
checkout bytes above.

## Local Windows host results

GCC 15.2.0, Ninja, CMake Release, `DMP_BUILD_TESTS=ON`. The real-provider
configuration used the cached sodium wrapper at
`build/noise-upstream/_deps/esphome_libsodium-1.10021.11`. CMake verified the
Noise, wrapper and nested libsodium revisions from
`tests/security/CMakeLists.txt`. Each `cmake --build build/r04-local-provider
--parallel 1` invocation completed before the next began. GCC emitted a
`-Wstringop-overread` warning in the pinned Noise dependency.

- `ctest --test-dir build/r04-local-provider --output-on-failure -j 1 -R
  '^(reliability\.direct|endpoint\.|security\.handshake|recovery\.frag_status)'`
  passed all 104 tests after all selected executables were built. The run
  includes 100 endpoint cases, both handshake cases, reliability and
  FRAG_STATUS. [Verification excerpts](verification.txt).
- `python -B -m unittest discover -v -s tests/peer/tests -p 'test_*.py'`
  collected 454 tests. Both `DMP_P23_ENDPOINT_SEC_EXE` and
  `DMP_P23_SAMPLE1_NONE_DRIVER` pointed to the built Windows executables.
  The suite passed 453 cases and skipped one local TCP case in the sandbox.
  That case passed when run alone with local loopback access.
  [Peer and loopback excerpts](verification.txt).
- `tools/check_core_allocators.py` found zero allocator references for
  `libdmp.a` and `libdmp_none.a` using MinGW `nm`.

## Local ESP32 qualification links

The operator authorized local size measurements without boards. Both targets
used the `tests/embedded/espnow_dmp` qualification image with diagnostics
enabled, SEC-1, Stream R and RETRY-ALL. The local EIM profile selected ESP-IDF
6.1 and GCC 15.2.0. Each build ran to completion before the next with
`IDF_PY_BUILD_JOBS=1`.

The source snapshot came from R03 commit `389b295` and Noise gitlink
`c40f2dca78eee064e521233a5d884853d471028a`. It used the cached ESPHome
libsodium component 1.10021.11 at component hash
`860ef0c4c58b57e5c83f9396cbfb9b664cea8c457fc1baf447518079a3da4207`.
The target dependency locks were matched to the recorded R03 hashes.
For each target the baseline was built into an empty output directory.
Its artifacts were saved, then only `src/reliability/reliability.c`
was replaced with the reviewed R04 index blob and rebuilt in the same
directory. The candidate build logs show recompilation of that source
and relinking of the application. The same `PROJECT_VER=389b295-r04-size`
was used for all four links.

The two source blobs used LF line endings. Their SHA-256 values were
`73390d456a7e427e3c27d914bf70da91d31cc03f245ffb8e0b791bba957d0d2d`
for R03 and
`ac18510b29df5979d020db41fa646b593b0bd40e603e13d0bf4c1e1d09b1b42a`
for R04. The R04 blob matches the CRLF working source after newline
normalization.

The build command was `idf.py -C <snapshot>/tests/embedded/espnow_dmp
-B <build> -DIDF_TARGET=<target> -DPROJECT_VER=389b295-r04-size build`.
`idf.py size` provided the application estimate. `python -m esp_idf_size
--format csv --archives` and `--files` on the archived map provided
linked Flash for DMP and the reliability object. File lengths give the
actual padded application binaries.

### Matched sizes

All values are bytes. DMP Flash combines the Flash Code and Flash Data
columns for `libdmp.a`, including the linked SAMPLE-1 code.

| Target | DMP Flash R03 → R04 | Reliability object Flash R03 → R04 | Image estimate R03 → R04 | Padded `.bin` R03 → R04 |
| --- | ---: | ---: | ---: | ---: |
| ESP32-S3 | 87,895 → 87,582 (−313) | 18,693 → 18,380 (−313) | 890,011 → 889,683 (−328) | 890,128 → 889,792 (−336) |
| ESP32-C3 | 92,099 → 91,963 (−136) | 19,420 → 19,284 (−136) | 929,914 → 929,778 (−136) | 930,288 → 930,144 (−144) |

Each pair matched byte-for-byte on generated `sdkconfig`, dependency
lock, linker script digests and linker command. Both local baseline size
rows also matched the R03 archived qualification sizes. DMP static RAM
was 4 bytes on both targets before and after. The whole image's static
DRAM/DIRAM and IRAM, and the linked provider totals, matched within each
pair. The smallest app partition had 71% free on S3 and 70% on C3 after
R04. The two fresh baselines each reported five ESP-IDF component
validation warnings. The incremental links compiled the single R04
source and emitted zero warning headers.

### Selected stack frames from the linked ELF

| Function | ESP32-S3 R03 → R04 (B) | ESP32-C3 R03 → R04 (B) |
| --- | ---: | ---: |
| `dmp_reliability_on_rx` | 352 → 352 | 368 → 368 |
| `dmp_reliability_req_is_retained` | 128 → 128 | 128 → 112 |
| `dmp_reliability_reject_req` | 128 → 144 | 144 → 160 |
| `expire_and_resolve_rx` compiler clone | — → 64 | — → 64 |

The shared RX helper contributes its 64-byte frame while it runs inside
each listed caller during expiry and source lookup. The combined rejection
ingress frames rise by 80 bytes on both targets. These values come from the
function prologues and exclude deeper callees. Physical operation, runtime
stack high-water and target latency remain unmeasured.

[Size measurements and artifact digests](size-measurements.txt) ·
[Reproduction commands](commands.md). The full host logs remain in the
local evidence directory. The full build logs, ELF, map, images, CSV and
disassembly are in the local `build/r4s/<target>-baseline-artifacts` and
`build/r4s/<target>-candidate` directories.
