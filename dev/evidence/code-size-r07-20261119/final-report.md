# DMP size reduction from Stage 0 to R07

Stage 0 is `67e1f67c0a11eaac172906cdd186f6cab3864fbf`. The original
[Stage 0 measurements](../code-size-r00-20261118/README.md) and the local
paired rebuild use the `dmp_espnow_dmp` qualification application with
`test-direct-sample-retry-2-nnpsk0.json` and
`test-direct-multi-peer-nnpsk0.json`. These are one-peer and four-peer
SEC-1 NNpsk0 workloads with Stream R and RETRY-ALL, respectively. Their
manifest bytes and workload source are unchanged across the comparison.

All values are bytes. Default retains capture and diagnostics and permits
standalone initialization. Trimmed sets `DMP_ENABLE_TEST_APIS=OFF`,
`DMP_ESP_NOW_QUAL_DIAGNOSTICS=OFF`, and
`DMP_HS_SHARED_ADMISSION_ONLY=ON`. Endpoint Stream R stays enabled in
both qualification images.

## Application binary and linked Flash

| Target | Stage 0 app `.bin` | Final default | Final trimmed | Stage 0 to default | Stage 0 to trimmed |
| --- | ---: | ---: | ---: | ---: | ---: |
| ESP32-S3 | 892,992 | 889,616 | 888,160 | 3,376 (0.38%) | 4,832 (0.54%) |
| ESP32-C3 | 931,904 | 930,112 | 928,704 | 1,792 (0.19%) | 3,200 (0.34%) |

The linked Flash figures below sum Flash Code and Flash Data. DMP includes linked
SAMPLE-1. The combined value adds the linked Noise and libsodium portions.

| Target | DMP Flash Stage 0 → default → trimmed | Combined Flash Stage 0 → default → trimmed | Combined reduction |
| --- | ---: | ---: | ---: |
| ESP32-S3 | 90,729 → 87,401 → 86,403 | 129,511 → 126,179 → 125,177 | 4,334 (3.35%) |
| ESP32-C3 | 93,721 → 91,927 → 90,967 | 135,421 → 133,627 → 132,667 | 2,754 (2.03%) |

## RAM

Handshake sizes come from each linked ELF's DWARF. Requested handshake storage
is the number of peers times the handshake object size plus one external registry.
The qualification application allocated an external registry in Stage 0 and
uses the same shared-owner topology in all rows.

| Target | Configuration | Per-peer handshake | External registry | One peer + registry | Four peers + registry |
| --- | --- | ---: | ---: | ---: | ---: |
| ESP32-S3 | stage0 | 11,128 | 14,384 | 25,512 | 58,896 |
| ESP32-S3 | final-default | 11,128 | 14,384 | 25,512 | 58,896 |
| ESP32-S3 | final-trimmed | 7,424 | 14,384 | 21,808 | 44,080 |
| ESP32-C3 | stage0 | 11,136 | 14,384 | 25,520 | 58,928 |
| ESP32-C3 | final-default | 11,136 | 14,384 | 25,520 | 58,928 |
| ESP32-C3 | final-trimmed | 7,424 | 14,384 | 21,808 | 44,080 |

| Target | Per-peer reduction | Four peers + registry reduction |
| --- | ---: | ---: |
| ESP32-S3 | 3,704 (33.29%) | 14,816 (25.16%) |
| ESP32-C3 | 3,712 (33.33%) | 14,848 (25.20%) |

| Target | Static memory | Stage 0 | Final default | Final trimmed |
| --- | --- | ---: | ---: | ---: |
| ESP32-S3 | DIRAM | 237,459 | 237,459 | 237,459 |
| ESP32-S3 | IRAM | 16,384 | 16,384 | 16,384 |
| ESP32-S3 | RTC FAST | 24 | 24 | 24 |
| ESP32-S3 | RTC SLOW | 36 | 36 | 36 |
| ESP32-C3 | DRAM | 237,420 | 237,420 | 237,420 |
| ESP32-C3 | RTC SLOW | 60 | 60 | 60 |


These RAM numbers cover linked static regions and requested handshake/registry
allocation. Allocator metadata, runtime heap and stack high-water, record scratch
peaks, and on-device latency remain unmeasured.

## Separate R07 probe images

| Workload | DMP Flash S3 | S3 app `.bin` | DMP Flash C3 | C3 app `.bin` |
| --- | ---: | ---: | ---: | ---: |
| Core + CRC32C | 4,472 | 137,600 | 4,886 | 119,968 |
| Core + CRC32C + Stream R | 6,708 | 140,096 | 7,163 | 122,384 |
| DIRECT-1 NONE with Stream R and SAMPLE-1 | 54,389 | 196,656 | 57,859 | 179,152 |
| RADIO-1 NONE with Packet and SELECTIVE-32 | 45,631 | 184,496 | 48,390 | 166,800 |
| Same RADIO-1 with endpoint Stream R compiled out | 43,580 | 182,432 | 46,396 | 164,800 |


The NONE runs use the raw `direct-none.json` and `radio-none.json` manifests
to generate typed configuration and arena capacities. Host execution
verified the SAMPLE-1 request/result, publication and context replacement
over Stream R, and routed RADIO-1 DATA with loss, CRC check, selective repair
and terminal receipt. ESP-IDF links the same workload sources through a
component without DMP handshake, provider, Noise, or sodium dependencies.
The two RADIO variants use the same workload and target SDK configuration.
Their size difference isolates the endpoint Stream R option.

The independent SEC-1 Tier 4 and Tier 5 host tests exercise the exact
`direct-nnpsk0.json` and `radio-xx.json` profiles with pinned Noise/libsodium.
The shared driver contains both profiles, so its PE sections cover the
driver and its linked dependencies, including the host runtime. Capture is
the only changed library option in the host comparison.

| Shared SEC-1 driver | `.text` | `.rdata` |
| --- | ---: | ---: |
| Capture on | 554,176 | 96,312 |
| Capture off | 553,728 | 96,312 |


## Scope and reproduction

- The qualification links use ESP-IDF 6.1 and GCC 15.2 with identical
  target SDK configurations, dependency locks, linker scripts and link
  commands within each pair. Stage 0 was rebuilt from its source snapshot
  and reproduced the originally recorded application binary sizes.
- The default qualification and trimmed qualification changes are measured
  separately from the NONE and Packet probe compositions. No image was
  flashed or executed on hardware.
- NONE-only and endpoint Packet-only are accepted combinations. The Packet
  build keeps the independent Stream codec and SEC-1 handshake transport.
  The measured RADIO-1 configuration uses SELECTIVE-32. The measured
  DIRECT-1 configuration requires endpoint Stream R. The existing
  SEC-1 Packet RETRY-ALL test manifests still require freshness, and the
  reference RADIO-1 XX exercises it. Profiles without S7 can omit the
  caller-provided token arena. The qualification app still reserves its
  existing static eight-slot arena in all compared builds.
  Selective recovery and freshness stripping remain proposals. A
  fragment-free deployment remains outside the validated manifest schema.
- [R07 build recipes and gate results](README.md) ·
  [link and artifact evidence](esp-idf-measurements.txt) ·
  [host verification](verification.txt)
