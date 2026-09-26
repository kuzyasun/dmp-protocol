# MCU-01 provider build feasibility - 2026-09-27

Status: MCU-01 compilation/linking scope accepted after independent read-only review. P01 remains running.

## Bounded plan

1. Preserve the clean parent/fork indexes, source pins and normative hashes.
2. Reuse the reviewed Noise custom allocator, checked entropy startup and pinned
   sodium sources in isolated builds. Keep NNpsk0 and XX enabled. No primitive,
   wire contract, SDK dependency adoption or DTrack integration change.
3. Compile the complete selected provider/backend archives for Cortex-M4,
   ARMv7E-M Thumb soft-float. No board/linker map is selected: archive-only.
4. Build/link an isolated ESP-IDF v6.0.2 ESP32-S3 test image and an SDK baseline.
   Use existing deterministic fixture/arena driver only in explicitly test-only
   targets. Retain config, source hashes, symbol checks, map and size reports.
5. Independently review the fixed source/evidence snapshot. Record failures and
   limitations; compilation/linking do not establish runtime correctness, entropy
   quality, stack high-water, whole endpoint budgets or physical support.

RBO job job_01M3FZKED982WEBDVSKSDWX5H9 failed before command execution because
origin does not contain the local Noise fork pin. Local fallback is used without
publishing. No flashing, hardware operations or DTrack integration are authorized.

Coordinator owns implementation, security choices, build registration and evidence.
A read-only worker investigates portability/build risks; no concurrent file edits.

## Results and limits

- Cortex-M4: complete `noise_c`, checked `sodium` and `dmp_mcu_fixture` archives
  compiled, 74 selected translation units (including empty disabled backends).
  All 73 C units have compiler stack reports; the assembly unit has none.
  This is ARMv7E-M Thumb soft-float archive evidence, not a board link.
- ESP32-S3: the same provider/backend plus main compiled and linked with
  ESP-IDF v6.0.2, revision `7101770dc6db2667b3c477cc31365dd1acd6db4e` and
  Xtensa GCC 15.2.0. An SDK baseline linked from the same project with provider
  disabled. Both generated sdkconfig files match: 4 MB flash, no PSRAM, -Os.
- Both Noise archives refer to custom allocation and checked entropy hooks,
  with no malloc/calloc/realloc/free or legacy randombytes calls. The linked
  ESP ELF contains actual handshake, AEAD, checked startup and port functions;
  legacy randombytes_buf/stir/sysrandom implementation definitions are absent.
  The backend archive still contains unused general-purpose allocator/RNG APIs;
  this is not a claim that libsodium or the SDK is heap-free.
- No compiler warnings were emitted in the recorded MCU build logs. Inherited
  backend/SDK flags include their existing warning policies; this wave adds no
  suppression. The older host Release warning is not reclassified here.
- No MCU code was executed. The linked driver contains public deterministic
  credentials and test entropy. Compile/link success does not pass the fixtures
  on MCU, establish random-source quality, stack high-water, timing or power.

### Linked contributions (ESP-IDF map, bytes)

| Archive | Flash code | Flash data | Static DIRAM |
|---|---:|---:|---:|
| Noise | 9164 | 522 | 0 |
| checked libsodium | 16370 | 12800 | 143 |
| fixture driver, arena and test vectors | 5753 | 20753 | 9272 |

The selected Noise/backend contribution is 38856 bytes of flash code/data plus
143 static DIRAM bytes. Dynamically occupied objects live in the test driver's
8192-byte backing and 1056-byte arena metadata, not in Noise's static globals.
These numbers exclude other SDK/stdio code pulled in by the driver and do not
freeze a production footprint. Actual symbol and map inputs are retained.

| Whole image observation | SDK baseline | Provider test image | Difference |
|---|---:|---:|---:|
| IDF total image size | 128172 | 200348 | 72176 |
| Flash Code region | 47816 | 79640 | 31824 |
| Flash Data region | 27048 | 67320 | 40272 |
| DIRAM used | 39200 | 48640 | 9440 |

IRAM and RTC region totals are unchanged. Use IDF's region accounting rather
than adding overlapping physical IRAM/DRAM capacities. The whole-image delta
includes test vectors, diagnostics, arena and transitively retained SDK code;
it is not the provider-only delta or a complete DMP endpoint RAM budget.

### Recorded repairs and execution route

RBO failed at repo_fetch on the unpublished fork pin. `eim run` returned without
running the command in this session. The v6.0.2 activation script registered in
EIM's installation registry was used; `idf.py --version` confirmed v6.0.2. No
legacy 5.x environment was selected and no tools were installed.

The first IDF configure lost an unquoted Windows `-D...=C:/...` argument through
the PowerShell function. Quoting the complete argument fixed it. The first link
then exposed static archive ordering: the library needed entropy hooks from an
already-scanned fixture archive. A GNU ld RESCAN group fixes the real cyclic
link references. Two intermediate configurations exposed CMake directory-scope
requirements; define the group before project() so both component and final
CXX-link scopes inherit it. All failed logs are retained, with successful final
builds separate. No crypto/state-machine source was changed to fix these issues.

The coordinator observed 12 MCU-01 paths staged during work before explicit
final staging. All belong to this wave; no unrelated index entries were found.
The initial clean baseline is recorded; no reset/unstage was performed and an
unchanged-parent-index claim is not made. The Noise fork remains clean.

## Reproduction

Use the prepared backend from the provider README; there is no implicit fetch.
Replace tool executable placeholders with the recorded compiler paths. From root:

```text
cmake -S tests/provider/targets/cortex-m4 -B build/noise-mcu-cortex-m4 -G Ninja -DCMAKE_TOOLCHAIN_FILE=<repo>/tests/provider/targets/cortex-m4.cmake -DCMAKE_C_COMPILER=<arm-none-eabi-gcc> -DCMAKE_ASM_COMPILER=<arm-none-eabi-gcc> -DDMP_MCU_TEST_ONLY=ON -DDMP_SODIUM_SOURCE_DIR=<prepared-backend>
cmake --build build/noise-mcu-cortex-m4
```

Activate EIM's recorded ESP-IDF v6.0.2 environment. Disable dependency manager
fetch (`IDF_COMPONENT_MANAGER=0`) and run (quote entire -D arguments in PowerShell):

```text
idf.py -C tests/provider/targets/esp32s3 -B <repo>/build/noise-mcu-esp32s3 -DIDF_TARGET=esp32s3 -DDMP_MCU_TEST_ONLY=ON -DDMP_SODIUM_SOURCE_DIR=<prepared-backend> build
idf.py -C tests/provider/targets/esp32s3 -B <repo>/build/noise-mcu-esp32s3-baseline -DIDF_TARGET=esp32s3 -DDMP_MCU_PROVIDER_ENABLED=OFF build
python tests/provider/collect_mcu_build.py --build-dir <build-dir> --nm <target-nm> --size <target-size> --output <evidence-dir>/report.json
```

For ESP add `--elf <build-dir>/dmp_mcu_test_only.elf`. Use the activated SDK Python
`-m esp_idf_size --format json2 [--archives] <map>` for image/region contributions.
`artifact-inventory.json` hashes exact ELF/bin files (kept in ignored build output)
and retained gzip-compressed maps, configs and full compile databases. Gzip data
is a lossless copy, not an edited map. `*-report.json` records selected commands,
source/header hashes, archive/ELF symbol gates and static compiler stack reports.
No flash command was executed; the build tool's printed flash hints are only logs.

Next recommended: P01 per-endpoint ownership/quota sensitivity with multiple live
handshake/traffic contexts and serialized crypto slots. Physical entropy/runtime
and a Cortex board/linker map remain separate unpassed gates.

## Independent acceptance

Independent final review returned scoped PASS with no actionable findings.
The reviewer verified all 9 code and 68 evidence snapshot entries, source and
artifact hashes, the 18-entry artifact inventory, 47+670 backend-file hashes,
ARM/Xtensa archive membership, actual RESCAN link graph and map/size claims.
The reviewer inspected evidence and sources; no new builds or runtime tests
were performed during review. See [review-result.json](review-result.json).
Readable log views normalize only line endings/trailing whitespace; originals
are retained as `.raw.gz` whenever changed. No compiled source changed after
review; historical snapshots remain and acceptance metadata is recorded separately.
