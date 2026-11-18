# DMP R03 SEC-1 record, teardown and transport deduplication

This package uses `6d490df40afe2f702d8e10ff4b88f8bba166c35c` as the accepted
R02 source baseline. [R02 review and evidence](../code-size-r02-20261118/README.md).

## Slices

- Record seal and open share AAD construction. The helper copies the exact
  encoded header to the AAD suffix and masks only the routing TTL nibble there.
  The wire header length and AAD length remain distinct. Seal uses one header,
  one body, and one AAD buffer and writes the output only after successful
  encryption. Confirmation retains its separate cap and zero padding. The
  logical wrapper retains caller capacity, lifetime and counter handling.
- Open still checks wrapper-specific admission, association state and capacity
  before AEAD. The shared body operation wipes scratch on failure, accounts
  for failed AEAD, commits replay after successful authentication, then updates
  receive accounting. The caller owns one body buffer and its successful-use
  wipe. Both explicit READY and application-confirmed readiness remain in the
  confirmation wrapper.
- Teardown shares checked token release and the exact directional-key release
  pair. Abort keeps CID release before keys, expiry keeps CID release after
  keys, and cleanup keeps its original per-token release order. Generation,
  cached-flight permits, retained enrollment, timers and zeroization remain in
  the owning lifecycle paths.
- Handshake transport selects either the cached bootstrap slice or the
  protected frame, then uses a common Packet/Stream R encoding block. Existing
  frame caps, including the zero uncapped sentinel, and reservation rollback,
  output wipes, rejection and completion order are preserved.

The protected single-peer bounds test now checks a one-byte-short seal output
for an unchanged destination and PN. It also checks a one-byte-short logical
open for an unchanged output and no failed-AEAD charge. The same sealed record
then reaches the endpoint successfully, proving the failed capacity check did
not consume its receive PN.

## RBO runs

The [command recipes](commands.md) rerun the qualification links and host gates.
The baseline and each slice used a separate source snapshot. The tables refer
to terminal attempts. The two qualification links exercise the same SEC-1
Stream R qualification application on different architectures.

| Stage | Job | Source content SHA-256 |
| --- | --- | --- |
| R02 baseline S3 | `job_01M7QMYNNZMT6N72HJ65FGZXHD` | `sha256:23cb17984bf346b1b0401a68311165fe3fc065e0419b9d10936e51a027a39b66` |
| R02 baseline C3 | `job_01M7QMYDJG006BS7JFWDC1CH53` | `sha256:23cb17984bf346b1b0401a68311165fe3fc065e0419b9d10936e51a027a39b66` |
| Record S3 | `job_01M7QN656ACB2WGTM2ZK6VDBCM` | `sha256:1fd201891354fd2d483baa90907ff660a3f50cfb44ab84ab2c127acab6d171dd` |
| Record host | `job_01M7QN5X8W8NE7QZGN7DDRD4CQ` | `sha256:1fd201891354fd2d483baa90907ff660a3f50cfb44ab84ab2c127acab6d171dd` |
| Record and teardown S3 | `job_01M7QN84AY3GCNGAG8A4JAH5VP` | `sha256:69691efcee0af59d17f71f82967a2554183ebe550330caf78f327ba0cfb59608` |
| Final S3 | `job_01M7QNBPDD5W6F7GAZXJA9TK2M` | `sha256:889be4d4c037da356e9b619d2dff37d78e0336ce443da8302d4edbf8d90ed13a` |
| Final C3 | `job_01M7QNBEMMX2PV4P6TBRWKPKJ2` | `sha256:889be4d4c037da356e9b619d2dff37d78e0336ce443da8302d4edbf8d90ed13a` |
| Final host and peers | `job_01M7QNBYPH5KSKKYS28H18Q5ZM` | `sha256:889be4d4c037da356e9b619d2dff37d78e0336ce443da8302d4edbf8d90ed13a` |
| Final host sanitizers | `job_01M7QNC7GNK0E3STJDNS05WJM5` | `sha256:889be4d4c037da356e9b619d2dff37d78e0336ce443da8302d4edbf8d90ed13a` |

## Paired size results

All sizes below are bytes. DMP Flash is linked `libdmp.a` code plus Flash
data, including the linked SAMPLE-1 code. The 4 bytes of DMP static RAM
are counted separately. Whole-image estimates come from `idf.py size`.
The `.bin` column gives actual padded binary bytes. Both builds used
ESP-IDF 6.1 and GCC 15.2.0. The generated configuration and effective
dependency lock hashes match for all stages on the same target.

| Target and stage | DMP Flash | Change from prior stage | Noise Flash | Sodium Flash | Whole image estimate | Actual `.bin` |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| ESP32-S3 R02 baseline | 89,282 | | 9,608 | 29,170 | 891,407 | 891,520 |
| ESP32-S3 record | 88,130 | −1,152 | 9,608 | 29,170 | 890,243 | 890,352 |
| ESP32-S3 record and teardown | 87,975 | −155 | 9,608 | 29,170 | 890,091 | 890,208 |
| ESP32-S3 final | 87,895 | −80 | 9,608 | 29,170 | 890,011 | 890,128 |
| ESP32-C3 R02 baseline | 92,805 | | 11,194 | 30,506 | 930,620 | 930,992 |
| ESP32-C3 final | 92,099 | −706 | 11,194 | 30,506 | 929,914 | 930,288 |

The DMP Flash reduction from the paired baseline is 1,387 bytes (1.55%) on
ESP32-S3 and 706 bytes (0.76%) on ESP32-C3. The padded binary shrank by
1,392 and 704 bytes, respectively. DMP and provider static RAM did not
change. The application reports 237,459 bytes DIRAM on S3 and 237,420 bytes
DRAM on C3 before and after.

The committed measurement excerpts include the size rows and SHA-256
digests for every linked ELF, map, binary, configuration, linker script and
dependency lock. Full outputs and binaries are identified by the RBO job
IDs above. [Measurement excerpts](measurements.txt).

## Behavioral verification

- The record slice passed five focused real-provider CTests. The final real
  Noise/sodium provider build passed 187 CTests, including both fixture
  generators, the handshake and handshake transport suites, the protected
  capacity regression, TTL, and AAD coverage. The ARM-dependent ABI/layout
  tests were excluded because the macOS worker lacked the ARM toolchain.
  [CTest excerpts](verification.txt).
- The independent peer suite passed all 454 tests, including the P23 SEC-1
  and NONE subprocess interop cases. Both allocator checks passed for
  `libdmp.a` and `libdmp_none.a`.
  [Peer and allocator excerpts](verification.txt).
- AppleClang ASan and UBSan passed the five focused tests covering handshake,
  handshake transport, protected capacity, TTL, and AAD.
  [Sanitizer excerpt](verification.txt).
- An independent Sol 6.2 high review had no actionable findings. It checked
  AAD bytes and TTL, output aliasing and publication order, replay and quota
  accounting, READY transitions, attempt cleanup, and transport rollback.
  Overlapping output buffers and the uncapped transport sentinel were
  checked against source. The review matched the three raw source hashes
  [recorded by the host run](verification.txt).

## R03 closeout review

Two further independent Sol 6.2 high reviews compared the candidate against
R02. The first found two evidence gaps. The report linked to ignored local
archives, and the intermediate source stages lacked a reproducible recipe.
The committed excerpts retain measurements, artifact identities and host
results. The stage recipe reconstructs the three candidate stages and checks
their source digests before writing them. The second review independently
reproduced those digests and verified the archived size, stack and test
evidence. Neither pass found a code change to make. Both were read-only
reviews of the tested R03 sources.

## ESP32-S3 stack evidence

The baseline rows come from the archived Xtensa function prologues. For final
R03, the archived ELF and symbol table were examined directly to include the
three `$constprop$0` clones. Decoding the `ENTRY` instruction also reproduced
all seven named frame sizes already collected by RBO from the same ELF.
[Baseline and final prologues](measurements.txt).

| Function | Baseline own frame (B) | R03 own frame (B) |
| --- | ---: | ---: |
| `seal_record` | 1,504 | 208 |
| `dmp_hs_seal_logical` | 1,408 | 192 |
| `dmp_hs_offer_protected` | 1,024 | 448 |
| `dmp_hs_open_logical` | 1,056 | 480 |
| `seal_prepared_record` clone | | 896 |
| `open_record_body` clone | | 400 |
| `build_record_aad` clone | | 48 |
| `abort_attempt` | 32 | 32 |
| `end_traffic` | 32 | 32 |
| `dmp_hs_tx_submit` | 336 | 336 |

Adding the R03 wrapper, record and AAD frames gives 1,152 bytes for
confirmation seal, 1,136 for logical seal, 896 for confirmation open, and
928 for logical open along the AAD path. These sums cover the listed DMP
functions and exclude deeper crypto and other callees. Hardware execution,
runtime stack high-water, peak crypto scratch at concurrency and target
latency remain unmeasured.
