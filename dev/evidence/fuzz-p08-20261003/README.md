# P08 partial checkpoint: fuzz-target contribution

This is a work-in-progress checkpoint, not P08 acceptance. P08 remains open
while the coordinator integrates and verifies the fuzz targets, adds the host
CI matrix and embedded compile-only jobs, and completes applicable map/size and
allocator checks. The owner requested a pause for a broker restart after the
current session completed.

## Broker turn

- Project: `dmp-protocol`
- Route: `dmp_cursor_large` / Cursor / `grok-4.7-high` / high
- Workspace/policy: `dmp-current-project` / `dmp-worker-project`
- Session: `session-786c164cb9f05015191e9613`
- Turn: `turn-b38e6c1420c78485ab8fc779` (`SUCCEEDED`; result quality is
  `unreviewed`)
- Baseline: `snap-1f59469d30b556c798c9ecdf`
- Turn final snapshot: `snap-d6edf6137ed89a61951c2a07`

The session status still reported `latest_snapshot_id` as the baseline after
the turn result exposed the distinct final snapshot ID. Resume from the turn's
`final_snapshot_id` and reconcile the actual checkout; do not treat the worker
report as acceptance.

## Files reported and observed in the checkout

The worker reported the following files, all under `tests/fuzz/`; the
coordinator's read-only checkout status confirmed `tests/fuzz/` is the only new
P08 source directory and no root build or CI file was changed:

- `CMakeLists.txt`
- `README.md`
- `fuzz_core.c`, `fuzz_core.h`
- `fuzz_stream.c`, `fuzz_stream.h`
- `fuzz_limits.h`
- `selfcheck.c`

The worker reports that the core callback uses a 256-byte stack buffer and
calls `dmp_core_parse`, bounded extension iteration, and role checks. The stream
callback feeds separate L/R decoders with fixed 134-byte storage, at most 256
feed calls, and one poll. These are worker descriptions pending source review.

## Checks reported by the worker

The worker reports a strict GCC C11 self-check passed with `dmp fuzz selfcheck
ok`, and strict compilation of both fuzz sources using local MinGW headers
passed. These results have not been independently reproduced.

The worker could not link libFuzzer in its Windows environment: the MSVC target
lacked Visual Studio CRT headers, and the GNU target rejected
`-fsanitize=fuzzer`. No other machine was checked. The report explicitly leaves
root integration, actual libFuzzer execution, host CI, ESP-IDF, Cortex-M4,
map/size, and allocator verification open.

## Broker receipt issue and pause point

The turn event stream recorded 12 `adapter:tool_receipt` events for `shell`
with `status: unknown` and `decision: unknown` at cursors 4675, 4718, 4727,
4730, 4733, 4736, 4739, 4742, 4745, 4748, 4751, and 4766. No diagnostic payload
was supplied. Impact: these receipts do not independently establish the
corresponding command outcomes; the worker's final command results remain
claims. No command was replayed and no replacement turn was created. Verify
after the owner restarts the broker.

The worker session is now `IDLE`; a fully paginated `agent_sessions_list` showed
no other DMP session with an active turn. No reviewer, root CMake/CI integration,
local build, staging, commit, or push was started after the worker completed.
