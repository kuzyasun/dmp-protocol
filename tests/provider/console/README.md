# Serial-controlled provider laboratory

This private P01 tool runs the same bounded C command core in host processes or
on MCU boards. It is not a DMP endpoint or a production security service. See
[PROTOCOL.md](PROTOCOL.md) for commands, ownership, error and measurement rules.
Public test keys are compiled in; never use this image with real credentials.

The firmware provides operations, not scripted scenarios. Python drives two
peers, forwards their actual Noise flights and ciphertext, checks responses and
appends commands, raw responses, identities and measurements to a JSONL file.
Adding host scenarios usually requires no firmware change. The portable core
uses platform hooks; ESP-IDF is only the first physical adapter.

## Host verification

Enable the existing `DMP_NOISE_EXPERIMENTS` CMake option and prepared pinned
`DMP_SODIUM_SOURCE_DIR` as described in the repository README. Build the
`dmp_noise_console` target and run:

```text
ctest --test-dir <host-build> -L provider-console --output-on-failure
python tests/provider/console/serial_bench.py --host-exe <dmp_noise_console> --output <new-trace.jsonl> --cycles 8 --mode both
```

The first command tests parser/lifetime/fault cases, Python framing/validation,
and an exchange between two real compiled provider processes. The second is a
longer customizable run. Output files must not already exist.

## ESP-IDF 6.1 images

Use the installed EIM toolchain, selecting 6.1 explicitly without changing the
machine-wide default. Prepare the pinned sodium source using the repository's
existing standalone Noise build. From the repository root, for each chip:

```text
eim run "idf.py -C tests/provider/targets/esp32-console -B <absolute-build-dir> -DIDF_TARGET=esp32s3 -DDMP_MCU_TEST_ONLY=ON -DDMP_SODIUM_SOURCE_DIR=<absolute-prepared-sodium-dir> build" v6.1
eim run "idf.py -C tests/provider/targets/esp32-console -B <different-absolute-build-dir> -DIDF_TARGET=esp32c3 -DDMP_MCU_TEST_ONLY=ON -DDMP_SODIUM_SOURCE_DIR=<absolute-prepared-sodium-dir> build" v6.1
```

Separate build directories are mandatory. The supplied lab configuration uses
UART0 at 115200 baud, no PSRAM or RF stack, a 12 KiB command-task stack and a 4 MiB
flash header. Verify actual chip identity and flash capacity before deploying;
the COM bridge identity alone does not establish either. Flashing requires the
owner's separate authorization and replaces the installed application.

After authorized deployment to ESP32-S3 COM23 and ESP32-C3 COM35:

```text
python tests/provider/console/serial_bench.py --ports COM23 COM35 --output <new-trace.jsonl> --cycles 1 --mode both --timeout 10
```

UART mode needs `pyserial`. Close other serial monitors first. DTR/RTS are set
inactive before opening, but bridge/driver behavior still needs physical
verification. A reset during the run is a failure. The initial run covers eight
handshake pairs: NN/XX, fixed/random ephemeral, each with both role orientations.
Increase `--cycles` for repeated lifetimes after the short run succeeds.
Allocation/RNG fault injection currently exercises peer 1 as an NN initiator;
do not infer equivalent injected-fault coverage for every chip/role/pattern.

Each response includes command time, provider arena live/peak bytes, allocation
and release counters, wipe errors, whole internal heap free/minimum/largest
block, task stack minimum remaining, boot ID and a source fingerprint. Binary
hashes, SDK/compiler/configuration and the build report must accompany a physical
trace. `us` excludes serial round trips and reply formatting but includes command
dispatch; it is not a pure primitive benchmark. Whole-image memory includes the
32 KiB retained arena, metadata, owner table, scratch, 5120 static UART line bytes,
4096-byte RX ring, task stacks and the SDK. Arena usage is not total MCU RAM use.

Successful runs can repeat without reset: ID-0 HELLO reads the last command ID.
An interrupted run may leave live contexts. Inspect the recorded last operation
and explicitly CLOSE affected slots before another scenario; RESET refuses live
owners. A timeout means an unknown operation outcome. Never blindly resend a
mutating command or reuse a TX nonce; retain and retransmit captured bytes when
testing duplicate delivery.

This first bench connects peers through Python and two UART links. It measures
provider operation on different MCU architectures, not ESP-NOW/Bluetooth or DMP
transport behavior. The entropy adapter temporarily enables the SDK ADC entropy
source with RF disabled; a later radio adapter must revise this ownership rule
before enabling Wi-Fi/Bluetooth. SDK entropy calls provide no health-failure
signal, so random exchanges are not an entropy-quality certification.

## Multiple live owners and byte-quota pressure

The Python-only pressure runner uses the same firmware and transport options:

```text
python tests/provider/console/serial_pressure.py --host-exe <dmp_noise_console> --output <new-host-pressure.jsonl>
python tests/provider/console/serial_pressure.py --ports COM23 COM35 --output <new-mcu-pressure.jsonl> --timeout 10
```

It sweeps quotas 2048, 3840, 4096, 8192 and 32768 in both role orientations.
Two established NN/XX guard pairs keep exchanging authenticated traffic while
up to six pending pairs are admitted, advanced, cancelled/recreated and split.
Natural NEW/Split OOM is reported separately from completion. First-allocation
NEW failure is also injected on each peer with guards alive. Every case checks
quota bounds, guard survival, rejected live-owner RESET, final release balance
and zero live allocations/wipe errors; the full-quota cases require all six
candidates to complete. Successful sweeps restore quota 32768.

This covers serialized, interleaved operations on multiple live contexts. It
does not test simultaneous crypto calls from multiple tasks, or retrying the
same candidate after Split OOM: that candidate is explicitly closed. Logical
byte quotas exclude retained backing storage, metadata, stacks and SDK memory.
An unexpected failure stops without blindly retrying mutations or freeing
owners whose last operation has an unknown outcome. Preserve that trace and
inspect it before explicitly cleaning up or starting another run.
