# DMP R02 TLV iteration and value decoding

The R02 candidate was compared with R01 qualification jobs
`job_01M7QHMN3S7M0KGBPM2ZBC9BQC` (S3) and `job_01M7QHMX4BYDSZQ9V45M5XHERP` (C3).
[Reproduction commands](commands.md).

## R01 review closeout

Two independent Sol 6.2 high reviews found no R01 source issues. The first
identified a gap in the reproduction commands when collecting hashes for
staged or committed code. The commands now compare with the fixed base
commit. The second verified the fix and cross-checked the current source
hashes and the reported size data against the RBO archive.

## R02 implementation

- The Core iterator, structural validator and role checks use one bounded
  TLV reader. A malformed tag or length keeps its original offset. A duplicate
  or out-of-order tag takes precedence over a value truncated after a valid
  TLV header. The public iterator advances and publishes only on success.
- Core, identity, reliability, reassembly, relay and routed SEC-1 confirmation
  share the canonical scalar, CONTEXT and REPLY_TO value decoders where their
  rules agree. Core still rebases relative errors to the frame. Identity still
  selects the REPLY_TO form from the selected context's security mode.
- The endpoint still checks SERVICE and STATUS before unknown critical flags.
  The forwarder still stops on the first forwarder-critical extension. The
  endpoint's separate scalar lookup shares its SERVICE/STATUS traversal and
  retains the permissive value reader used with synthetic views. Reliability
  keeps first-match semantics, and reassembly keeps its own service policy.
- Routed SEC-1 confirmation still checks exact options, route and CONTEXT
  tag, requires the cursor to finish at the extension span's end, and compares
  the decoded namespace and epoch. The handshake and replay paths are covered
  by the existing real-provider tests.

R02's independent Sol 6.2 high review found no functional issues and identified
avoidable padding in `id_ext`. The final source groups the reply and epoch
before the 32-bit fields. New regressions exercise iterator output and cursor
sentinels, malformed TLV precedence and absolute offsets, role-policy early
returns, and the first STATUS in reliability's synthetic RX entry point.

Two later independent Sol 6.2 high closeout reviews found no source defects.
The first identified that the qualification recipe lost the input list after
commit and that the host recipe omitted test directories from that list.
Both recipes now use the fixed pre-R00 commit and their explicit source/test
scope. The second verified the fixes, raw input records and archived results.

## Linked Flash and static RAM

The qualification links matched R01's `sdkconfig` and effective dependency
lock on each target. They used ESP-IDF v6.1, GCC 15.2.0, `-Os`, section GC,
and qualification diagnostics. `libdmp.a` includes SAMPLE-1 in those links.

| Workload | DMP Flash R01 → R02 | Whole `.bin` R01 → R02 |
| --- | ---: | ---: |
| ESP32-S3 qualification | 90,689 → 89,282 B (−1,407 B) | 892,960 → 891,520 B (−1,440 B) |
| ESP32-C3 qualification | 93,603 → 92,805 B (−798 B) | 931,792 → 930,992 B (−800 B) |
| ESP32-S3 Tier 0 Core + CRC32C | 4,568 → 4,472 B (−96 B) | 137,696 → 137,600 B (−96 B) |
| ESP32-S3 Tier 0 Core + CRC32C + Stream R | 6,804 → 6,708 B (−96 B) | 140,192 → 140,096 B (−96 B) |

Qualification `.bin` headroom within the 3,080,192 B factory partition is
2,188,672 B on S3 and 2,149,200 B on C3. Archive and whole-app static RAM
sections match R01. The archives use 4 B for DMP, 0 B for Noise-C, and
143 B for libsodium. On S3, Noise-C's attributed Flash shifts from 9,612 B to
9,608 B. The dependency revision is matched. Its C3 attribution remains
11,194 B. libsodium measures 29,170 B on S3 and 30,506 B on C3 in both links.
The Tier 0 ELF audit retained the public workload entry points and found no
provider, endpoint or reliability symbols. The separate ESP-NOW Core pair
project also linked.

Selected linked S3 symbols decreased in size. `take_frame` went from 6,238 B
to 5,875 B, `dmp_core_check_role` from 547 B to 323 B, and `dmp_core_parse`
from 1,615 B to 1,487 B. On C3, `take_frame` went from 5,518 B to 5,352 B and
`dmp_core_check_role` from 534 B to 324 B. Some of the shared logic now lives in
separate symbols, and the archive totals include that code.

| S3 function | R01 entry frame | R02 entry frame |
| --- | ---: | ---: |
| `dmp_core_parse` | 272 B | 224 B |
| `dmp_core_check_role` | 80 B | 64 B |
| `dmp_extension_next` | 64 B | 64 B |
| `read_extensions` (identity) | 64 B | 48 B |
| `dmp_identity_source_key` | 144 B | 144 B |
| `dmp_identity_reply_to` | 160 B | 160 B |
| `dmp_reliability_on_rx` | 352 B | 352 B |
| `take_frame` | 864 B | 864 B |
| `dmp_hs_open_logical` | 1,056 B | 1,056 B |

The stack table comes from Xtensa `entry` instructions in the matched ELFs.
The shared `read_extension`, `dmp_decode_extension_reply_to` and
`dmp_decode_extension_context` functions have entry frames of 64 B, 80 B
and 64 B respectively. Peak nested usage remains open. The endpoint
role still scans SERVICE/STATUS before the unknown-flag pass. Reliability
still stops its lookup on the first match. MCU execution, latency and stack
high-water remain open alongside the R00 deployment budgets.

## Validation and artifacts

- Final macOS arm64 Release with pinned SEC-1 provider and both peer drivers
  passed 187/187 CTests and 454/454 independent Python tests. This covered Core,
  identity, endpoint, reliability, reassembly, relay and security, including P23,
  P24 and both Node vector gates. Allocator symbol checks passed for the default
  and NONE archives. RBO `job_01M7QK9MYK38PQGA5JKP932S9P` records test/source
  hashes that match the local final source.
- AppleClang ASan/UBSan passed `core.codec`, `stream.framing` and `fuzz.selfcheck`
  in `job_01M7QK24VETJMDQW2FJH8QD7P2`. This run preceded the identity field
  reorder. Its targeted Core and Stream sources are identical to the final
  snapshot. The separate libFuzzer runtime remains unavailable on the worker.
- `job_01M7QK9RCHPVXAGE53T2JHX4W3` ran the updated Core fixtures on the archived
  R01 codec and matched 100,000 seeded Core cases between R01 and R02. It checked
  iterator cursors and outputs, both role verdicts, parse status/offset/spans,
  full and header-only encode status, written counts and destination bytes.
- The eight ARM-dependent CTests were excluded because the RBO worker lacks
  `arm-none-eabi-gcc`. The Linux allocator runtime test and MSVC were outside
  this run. Existing physical qualification statuses remain unchanged.

| RBO evidence | Job |
| --- | --- |
| ESP32-S3 qualification and static prologues | `job_01M7QK8VFXEQAEYFP9AF107HX4` |
| ESP32-C3 qualification | `job_01M7QK93QZVBSPQJTZ78KV5FNW` |
| Both S3 Tier 0 probes and ESP-NOW Core pair | `job_01M7QK9C4M31YYFHKJM0YP0JT6` |

| Final qualification target | ELF SHA-256 | Map SHA-256 | Application image SHA-256 |
| --- | --- | --- | --- |
| S3 | `86e3de9be33a1a3a35a84364d6e17dcf4ffbd93f5d67d360ef14c25ff99d0f6e` | `fb8fd3268f644c07edd229579a340206e186a6bf15572306662313ff53408b28` | `203af0e43f1ca25c7278bce4ce94d54dff71059a125b89115ffa5dbfa0a5f20f` |
| C3 | `4f391246360c47d4e750a2b1e28b3b9279b40737b6c26c522ab706b7439817a4` | `45fbd4e7f37c7803bc8afd2b3b99098430c5da8c6ac04090e92aa295e6bab998` | `73972db46a41336762db9d35b67a887f90592ab8527af591a9d06b6ca193752b` |

The jobs retain map, ELF, image, compile commands, generated configuration,
size reports and symbol listings. S3 artifact identities above use terminal
attempt `att_01M7QK900KYVZQB80VRRFR28XA`.
