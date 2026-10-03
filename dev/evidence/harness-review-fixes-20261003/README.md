# P07 review fixes and acceptance

P07's final fix delta was independently reviewed against sealed baseline and
target snapshots after the initial implementation review found four correctness
defects and coordinator inspection found one adjacent output-flush edge case.
The coordinator checked the final source diff and acceptance evidence before
marking P07 done.

## Sealed review

The read-only reviewer used baseline `snap-a3d7f17808bf7ff6d7e81bb6` and final
target `snap-df6c5b35177fcbf91789a599`. Its diff contained exactly these eight
files: `tests/harness/json.h`, `json.c`, `manifest.c`, `scenario.c`, `harness.c`,
`main.c`, `test_port.c`, and `test_harness.py`. It reported no confirmed defects
and verified the five fixes listed below. This was source review only; the
reviewer did not run builds or tests.

- JSON string/key comparisons now use full lengths and bytes, preventing an
  embedded NUL from aliasing an enum, key, identifier, or operation value.
- A zero-duration transmit completion is ordered after its live start event;
  simultaneous cancel ordering remains defined by the frozen harness contract.
- Cancel validation compares events by scheduled time and input order, not by
  array position.
- Controller input and output paths distinguish EOF from read failure and
  check both writes and flushes, including `--interface-version`.
- Regression coverage was added for these edge cases.

## Build and test evidence

RBO job `job_01M3ZSGFBW4VT46F8VP7EZM4RX`, attempt
`att_01M3ZSGKYVCVF1EEFD737GGMSJ`, ran on macOS/arm64 from sealed source snapshot
`snp_01M3ZSGFNH3E95MZT4CXJ2M6PR` (content SHA-256
`e74fd6f38ede43d0bb9c05cb20d5da4bc465ebb7c7be7b08af8360405d179699`). It
completed with exit code 0 using AppleClang 21.0.0.21000101 and Python 3.14.7.

- Debug configure/build passed; `harness.port` and `harness.subprocess` passed
  2/2.
- Release configure/build passed; the same CTest entries passed 2/2.
- A tests-off Release archive built; the guarded check confirmed that the
  harness target and `harness.*` CTest entries were absent.
- The implementation worker separately reported strict MinGW compilation and
  10 Python unit tests passing. This is worker-reported evidence; the RBO job
  above is the coordinator-run acceptance check.

## Review tooling issue and limits

The first fix-review turn, `turn-8d21362e3a2f395e0502c243`, could not start its
review because a worker-generated
`tests/harness/__pycache__/test_harness.cpython-312.pyc` made the broker diff
generator reject the snapshot as binary/invalid UTF-8. The coordinator removed
only that newly generated cache file and its empty directory, recaptured the
target, and started a new read-only review using the same route. The successful
review turn was `turn-9dac5890dca0e2c9ea14e11d` on
`dmp_cursor_reviewer` / Cursor / `grok-4.7-xhigh` with no effort override. No
private provider output or credentials are included here.

The accepted scope is the host deterministic harness foundation. These checks
do not establish endpoint, SEC-1, provider, physical transport, MCU runtime, or
production resource acceptance; those remain with their later gates. No files
were staged or committed.
