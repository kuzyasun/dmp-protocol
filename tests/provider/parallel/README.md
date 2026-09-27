# Independent-worker provider laboratory

Private P01 / MCU-04 test only. Public fixture keys must never enter production.
This separate image leaves the serial console source unchanged. Each worker
owns both endpoints of a local Noise pair; this is provider concurrency evidence,
not communication between physical boards. The earlier console remains the
cross-board UART experiment. No RF stack is enabled.

The portable workload uses only injected worker-ID, entropy, clock, call-boundary
and yield hooks. Its context, arena and scratch belong exclusively to that
worker. The existing allocator itself remains unsynchronized; separate arenas
never share metadata. Backend initialization happens before task creation.

Host POSIX pthread checks use `dmp_noise_parallel <workers> <cycles>` after
building the existing `DMP_NOISE_EXPERIMENTS` target configuration. CTest label
`provider-parallel` checks one and two workers. Thread startup is synchronized;
the test requires one or two overlapping instrumented provider-call intervals,
respectively. CTest bounds the whole process to 120 seconds.

ESP-IDF 6.1 builds use the same pinned prepared sodium source as the console:

```text
eim run "idf.py -C tests/provider/targets/esp32-parallel -B <absolute-target-build-dir> -DIDF_TARGET=esp32s3 -DDMP_MCU_TEST_ONLY=ON -DDMP_SODIUM_SOURCE_DIR=<absolute-source-dir> build" v6.1
```

Use a separate build directory and `IDF_TARGET=esp32c3` for C3. Flash only with
owner authorization and an explicit verified port. The image has two permanent
static worker tasks, each with a 12288-byte stack, and an 8192-byte main stack.
S3 pins workers to distinct cores; C3 pins both to its single core. Worker state
remains owned until the task signals completion. No shared session calls or
cross-worker frees are supported. Each whole entropy-source enable/read/disable
sequence takes a mutex with a five-second deadline. No other ADC/RF client may
run. The SDK exposes no entropy health failure result.

UART0 is 115200 baud. Commands are bounded ASCII lines:

```text
0 HELLO
1 RUN 1 8
2 RUN 2 32
```

RUN requires a fresh increasing positive command ID, one/two workers and
4..256 cycles in multiples of four. A cycle is one complete local pair; the workload alternates
NNpsk0/XX and fixed/random ephemeral modes with balanced coverage.
Replies start with `DMPPAR ` followed by JSON. HELLO reports the last
RUN ID, boot ID, source fingerprint, target, IDF and core count. RUN reports
per-worker completion/counters/arena/scratch, stack high-water, heap and call
overlap. Maximum call duration includes preemption and entropy-lock waiting;
it is not a pure cryptographic primitive benchmark. Stack/heap minima cover
the whole boot, and both worker stacks remain allocated in one-worker runs.

The start deadline is five seconds and the completion deadline is ninety.
After each cycle workers rendezvous with a five-second deadline, then both
block for two RTOS ticks so that the single-core idle task can run. Independent
per-worker delays alone do not guarantee idle time when its peer stays runnable.
This checkpoint remains outside provider-call intervals; elapsed run time
includes the rendezvous and idle windows. A checkpoint returns zero on success
or a nonzero error that aborts the worker. Arrival bits are cleared per RUN.
A start or completion timeout is fatal to command processing: possibly running workers are not
silently freed or reused. A RUN is never automatically retried. Preserve the
trace and inspect/reset the authorized bench before continuing after failure.
An inter-cycle checkpoint timeout reports a failed RUN after workers finish;
it does not by itself terminate command processing.

`serial_parallel.py --port <port> --target <esp32s3|esp32c3> --build <fingerprint>
--output <new.jsonl>` executes bounded one/two-worker and repeated-lifetime
comparisons, validating identities, cleanup, no heap accumulation and overlap.
Its output is exclusive and includes raw replies. The driver uses pyserial
through the console transport and keeps DTR/RTS inactive.

Call-interval overlap on S3 with distinct pinned cores supports concurrent
provider execution; it is not instruction-level timing proof. C3 can only
execute one task at an instant. Neither target proves scheduler fairness,
shared-owner thread safety, all allocator topologies, RF or whole-DMP budgets.

`serial_soak.py --port <port> --target <esp32s3|esp32c3> --output <new.jsonl>`
is the separately reviewed MCU-05 controller for the accepted MCU-04 image.
It fixes three epochs of four two-worker 128-cycle RUNs and performs two
UART-bridge EN resets between completed epochs. It verifies ROM banner/reset
reason as well as changed boot identity and cleared counters. Use only on an
authorized bench with the matching image and reset wiring; it never retries
failed/unknown commands. [MCU-05 evidence](../../../dev/evidence/noise-mcu-soak-20260927/README.md)
records S3 completion and C3's failed diagnostic gate: absence of C3 ROM output
is not silently accepted as a verified reset.
