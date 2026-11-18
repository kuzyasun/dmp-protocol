# DMP R06 release diagnostics and private storage

The baseline is R05 commit `c5a9f88`.
[R05 closeout](../code-size-r05-20261119/README.md).

## Private plaintext capture and qualification diagnostics

The private getter `dmp_hs_copy_accepted` has two handshake fixture
call sites. The linked R05 qualification image already discarded that
getter, but calls `dmp_hs_offer_protected` and retains the per-attempt
copy buffer. R06's `DMP_ENABLE_TEST_APIS=OFF` removes that buffer, the
copy operation, the associated cleanup and the getter. The default is ON
in root CMake, the ESP-IDF component and direct compilation. CMake owners
propagate the flag to consumers. Allocators still query `dmp_hs_size()`
from the linked variant.

The protected receive path still performs authorization, AEAD, replay,
traffic accounting, FINISH, READY and application-proven readiness.
Decrypted scratch is wiped on the same exits. Only the optional
post-decrypt plaintext copy is conditional.

The qualification project's `DMP_ESP_NOW_QUAL_DIAGNOSTICS` cache option
now accepts OFF. The default stays ON. It independently controls the
failure-stage diagnostics compiled into the handshake.

## Host and Cortex-M4 checks

Both capture modes passed all 195 CTests and 454 independent peer tests
with the same pinned Noise and libsodium provider; builds ran serially.
The handshake suite kept implicit and explicit READY, protected receipt,
replay, cleanup and shared admission coverage in both modes. The only
conditional test assertions compare a stored plaintext copy. The trimmed
GNU RESCAN link also passed five focused handshake and endpoint CTests.
Compile commands confirm the matching flag on the library and test.
The trimmed archive still exports protected receive and omits the copy
getter. Allocator symbol checks passed for both library compositions.
[Verification excerpts](verification.txt).

| ABI | `sizeof(hs_attempt)` ON → OFF | `dmp_hs_size()` ON → OFF |
| --- | ---: | ---: |
| Windows x64 | 1,904 → 1,664 B | 11,168 → 10,208 B |
| Cortex-M4 compile-only | 1,896 → 1,656 B | 11,096 → 10,136 B |

The Cortex-M4 CTest passes the selected flag to its direct compiler.
The paired reports use arm-none-eabi GCC 13.3.1.
An independent Sol 6.2 high review verified the guards and preservation
of the protected receive state transitions and found no blocking changes.

For reproduction, use the [pinned host recipe](../code-size-r04-20261118/commands.md)
with `-DCMAKE_EXPORT_COMPILE_COMMANDS=ON` and separate build directories for
`-DDMP_ENABLE_TEST_APIS=ON` and `OFF`. Build with `--parallel 1` and run the
full CTest gate with `-j 1`, followed by the peer driver and allocator checks.
The explicit GNU RESCAN check adds
`-DCMAKE_C_LINK_GROUP_USING_RESCAN_SUPPORTED=TRUE` and
`-DCMAKE_C_LINK_GROUP_USING_RESCAN=LINKER:--start-group;LINKER:--end-group`,
then builds `dmp_test_handshake` and `dmp_test_endpoint_sec`. It runs
`security.handshake`, `security.handshake_transport` and the protected
endpoint activation, single-peer bounds and drain cases.

## ESP-IDF qualification links

The local ESP-IDF 6.1 builds reused the R05 qualification snapshots and
recorded build metadata. The SDK configuration, dependency locks, linker
scripts and link command matched in each pair. Each link used one Ninja
worker. The active SDK reported its existing component validation warnings
during configuration.

| Configuration | S3 DMP Flash | S3 app `.bin` | C3 DMP Flash | C3 app `.bin` |
| --- | ---: | ---: | ---: | ---: |
| Capture on, diagnostics on | 87,417 B | 889,632 B | 91,933 B | 930,112 B |
| Capture off, diagnostics on | 87,214 B | 889,408 B | 91,821 B | 930,000 B |
| Capture off, diagnostics off | 87,021 B | 888,800 B | 91,613 B | 929,344 B |

The capture-off build saves 203 B of linked DMP Flash on S3 and 112 B on
C3. Disabling diagnostics then saves another 193 B and 208 B. Linked
provider sizes and app static RAM matched within each pair. The SDK ELF
debug info shows a 240 B reduction per attempt and 960 B per handshake
object on both targets.

| ABI | `sizeof(hs_attempt)` ON → OFF | `dmp_hs_size()` ON → OFF |
| --- | ---: | ---: |
| ESP32-S3 | 1,904 → 1,664 B | 11,128 → 10,168 B |
| ESP32-C3 | 1,904 → 1,664 B | 11,136 → 10,176 B |

Repeat the [R05 qualification link recipe](../code-size-r05-20261119/commands.md)
with the R06 handshake sources and ESP-IDF CMake files. Append
`-DDMP_ENABLE_TEST_APIS=<ON|OFF>` and
`-DDMP_ESP_NOW_QUAL_DIAGNOSTICS=<ON|OFF>` to the configuration options
for each row. The stored compile commands show the expected flag for both
the handshake and its qualification consumer. The protected receive
symbol links in every image. Both the diagnostic callback and the
`provider-write` string disappear in the diagnostics-off image.
The ELF/map/bin digests, link inputs and compiler-flag checks are in
[measurements](measurements.txt). Hardware execution, runtime stack
high-water and latency remain unmeasured.

## Shared-admission-only composition

`DMP_HS_SHARED_ADMISSION_ONLY=ON` removes embedded standalone admission
storage from each handshake. Both CMake owners default to OFF, as does a
direct build. The variant retains the private standalone constructor
symbol, which returns `DMP_HS_UNSUPPORTED` before touching the object.
Shared initialization still validates the registry before writing the
handshake. Callers allocate the size from the linked library and keep the
external owner initialized through cleanup and retained reservation
release. The retained table, partial ingress, work counters and external
registry capacity are identical across these two configurations.

The focused real-provider CTest exercises both compositions. It runs
explicit READY after FINISH loss, implicit readiness via authenticated
application traffic, application replay, exact CID and directional epoch
token invalidation at expiry, fresh slot reuse, and peer-shared work/scratch/pending/CID reservations
and retained token cleanup. Its full exchanges use one initialized
registry per simulated device. Quota tests share a single registry
across peer instances on the same device. The owner requirement test
checks return codes and object-byte preservation.

With `DMP_BUILD_TESTS=ON`, the shared-only root configuration selects the
focused fixture target, requires the same pinned Noise and libsodium
provider, and rejects the standalone Noise experiment and fuzz suites.
`DMP_BUILD_TESTS=OFF` can build the library archive by itself. See the
[pinned host recipe](../code-size-r04-20261118/commands.md). Configure a
fresh build directory with `-DDMP_HS_SHARED_ADMISSION_ONLY=ON`, `-DDMP_ENABLE_TEST_APIS=OFF`
and `-DCMAKE_EXPORT_COMPILE_COMMANDS=ON`. Build with `--parallel 1` and run
`ctest --test-dir <build> -j 1 --output-on-failure -R '^security[.]handshake_shared$'`.

The allocation comparison below uses the same shared-owner topology
in both columns, with capture and qualification diagnostics disabled.
The total includes one 14,384-byte external registry per device. Each
ESP-NOW qualification image supports up to four peer instances.

| Target | Handshake bytes per peer, OFF → ON | Four peers plus registry, OFF → ON | Linked DMP Flash delta | App `.bin` delta |
| --- | ---: | ---: | ---: | ---: |
| ESP32-S3 | 10,168 → 7,424 | 55,056 → 44,080 | −602 B | −640 B |
| ESP32-C3 | 10,176 → 7,424 | 55,088 → 44,080 | −640 B | −640 B |

The IDF comparisons apply the same source snapshot and use the same
target SDK configuration, dependency lock, link command, linker scripts
and project version within each pair. The archive and its app consumer
compile with the same flag. To reproduce, use the R05 qualification
recipe and the R06 source snapshot, keep capture and diagnostics OFF,
and vary only `-DDMP_HS_SHARED_ADMISSION_ONLY=<OFF|ON>`. Run each link
with one Ninja worker. DWARF in the linked ELF gives the handshake
layout and the external registry header and entry sizes. The ESP-IDF
map shows unchanged static DIRAM/DRAM. The dynamic totals describe
requested object storage and exclude allocator metadata, provider heap
peaks and stack. [Shared-link measurements](shared-measurements.txt).

The final shared fixture passed all 11 cases in the actual trimmed
library and both controls. Each default-mode host configuration passed
196 CTests. The capture-off control also passed all 454 independent
Python peer tests. Host GCC 15.2 reported an existing warning in the
pinned Noise source during the fresh provider build. ESP-IDF 6.1
reported its existing component validation and Kconfig diagnostics.
Independent Sol 6.2 high review found no product defect and identified
expiry after activation and explicit owner lifetime as coverage and
documentation improvements. Both are included in the final patch.
[Final host and compiler results](verification.txt).

With capture disabled, Windows x64 measured 10,208 → 7,456 B per peer
and Cortex-M4 measured 10,136 → 7,392 B. The registry is 14,384 B on both
ABIs and in both build modes. To reproduce Cortex-M4, run the direct
compiler probe twice with GCC 13.3.1, selecting `$shared` as 0 and 1.

```powershell
python tools/ram_mcu_abi.py --source-root . --layout tests/memory/mcu_layout.c `
    --output "build/r06-arm-shared-$shared/mcu-abi.json" `
    --work "build/r06-arm-shared-$shared" --test-apis 0 --shared-admission-only $shared
```
