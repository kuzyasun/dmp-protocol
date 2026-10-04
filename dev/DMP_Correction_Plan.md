# DMP implementation correction plan

Status: stage-2 configuration contract frozen on 2026-10-04. The diagnosis
below is the historical 2026-10-03 inspection of
`fdf0456e0a0c79118c77061f7fdf1ad5136a879c` (P10). It is not the implementation
baseline. Current baseline is HEAD `fc83b84354d16bd72164d37eb5b5e9efd862f321`
plus the stage-1 worktree. P11 is committed and the board status is `review`,
not a live assignment. The frozen rules are in "Frozen stage-2 contract".

## Diagnosis

The implementation contains useful portable protocol code. Codec, framing,
identity and reliability tests exercise library sources. Preserve that work.
However, host configuration machinery has crossed into the embedded library,
and experiment evidence has grown disproportionately to the delivered endpoint.
The remedy is a smaller configuration boundary and a working endpoint milestone,
not another protocol rewrite or another round of general provider experiments.

| Finding | Checked evidence | Consequence |
|---|---|---|
| JSON describes a test deployment, not application payload | `docs/DMP_Test_Manifest_Contract.md`, scope and exact-byte hash rules | Opaque payload semantics are not the cause of this parser. |
| General JSON admission is compiled into `libdmp` | `src/identity/profile_admit.c`, root `CMakeLists.txt` | Embedded initialization is coupled to a host manifest format. |
| Admission requires 419,936 scratch bytes, about 410 KiB | `include/dmp/identity.h`; `KEY_REGION = 419424` in the parser | The duplicate-key/decoded-key workspace is sized for manifests up to 262,144 bytes; the input bytes need separate backing storage. This is not a message buffer. |
| Runtime configuration reflects the two-endpoint test deployment | `dmp_admitted_profile`, fixed node/service arrays in `identity.h` | Host topology and runtime parameter ownership are mixed. |
| P10 also provisions multiple full-message copies | `validate_storage` and payload/metadata accessors in `src/reliability/reliability.c` | Removing JSON alone does not establish a small RAM footprint. |
| Historical evidence dominates repository clutter | 550 tracked files under `dev/evidence`, 45,560,656 bytes at inspection | Consolidate results and retain executable regressions, rather than every successful trace. |

The 410 KiB is caller-supplied scratch when `dmp_profile_admit` is used. It is
not an allocation on every packet, nor proof that every linked firmware reserves
that memory. Nevertheless, requiring it for embedded configuration is unsuitable.

For the inspected `direct-nnpsk0.json`, P10 requires at least:

```text
sender/result/receive payload: (4 + 4 + 1) * 1024 = 9,216 bytes
history/correlation metadata: (8 + 4) * 255     = 3,060 bytes
subtotal                                      = 12,276 bytes
```

This excludes slot structures, adapter frames, identity state, P11 reassembly,
security, stream state and stack. These are the current test configuration's
capacities, not an established minimum for all deployments. Resource charges in
the manifest are design inputs; they are not measured total endpoint RAM.

## Target boundary

1. **Host tools:** read and validate JSON, check full deployment semantics,
   calculate the digest of the original bytes, and emit typed C configuration
   for the selected endpoint. Use the existing validator as the starting point;
   avoid maintaining another complete validator for this conversion.
2. **Portable library:** accept compact typed configuration plus caller-owned
   storage. Check supported features, cross-field invariants, capacities,
   overflow and lifetimes before publishing initialized state. These checks
   must work for handwritten C configuration as well as generated configuration.
3. **Application and adapters:** own payload serialization, transport I/O and
   provisioning. The library transports payload bytes and validates protocol
   headers, services, authorization and security as required by the contract.

Remove the general JSON parser from the embedded library after mapping its
semantic checks to host validation or runtime admission. Do not simply reduce
its scratch constant, skip checks, or keep a second legacy admission path.
Keep identity/context management separate from deployment-file parsing.

Preserve `PROFILE_HASH = SHA256(original complete manifest bytes)`. Generate
configuration and its digest together from the same validated input. Do not hash
C struct layout, canonicalized JSON or an endpoint-only subset. No new binary
configuration wire format is needed. A digest is not a substitute for runtime
configuration validation or SEC-1 authentication.

Changes affect the configuration API and admission/parity tests. Update the
implementation plan and test-manifest integration contract explicitly when
implementing them. They do not require changing DMP wire encoding, payload
semantics or security algorithms. Preserve any separately required independent
peer validation; independence does not require JSON inside MCU `libdmp`.

## Memory requirements

- Treat 1, 2, 3, 4, 8 and 16 KiB as buffer-budget cases to exercise. Do not
  interpret them as already proven total RAM limits for a complete secure
  endpoint. Report both individual buffers and the sum of all live allocations.
- Keep wire MTU, maximum assembled message size, retained sender/result data,
  RX workspace, reassembly, tombstones and crypto workspace separate in the
  accounting. Smaller messages and lower concurrency must reduce storage.
- Configuration admission must not need workspace proportional to JSON input.
  Establish and measure a small fixed validation-stack bound on the target ABI.
- Derive required capacities with checked arithmetic; fail initialization before
  accepting traffic if supplied storage is insufficient. Include alignment and
  structure sizes, not only byte arrays. Prefer extending existing size checks
  over inventing a new allocator or general memory framework.
- Review the difference between resource slot counts and operational limits.
  Allocate necessary overlap for retries/results/control, not unused test
  capacity by default. Keep explicit reserve for control traffic.
- Preserve immutable asynchronous TX ownership, retry cache lifetime, dedup and
  correlation retention, and complete-before-dispatch reassembly. Share storage
  only where lifetimes are proven disjoint; do not force a zero-copy rewrite.
- Account for P11 active assemblies and expiry tombstones after its handoff.
  Verify exhaustion and context retirement as well as ordinary completion;
  bounded memory must not be obtained by forgetting security-relevant history.
- Define an explicit small-buffer deployment when existing reference instances
  do not fit. Do not silently alter their bytes/hashes or label a plaintext
  demonstration DIRECT-1/RADIO-1, both of which require SEC-1.

Acceptance must include byte-exact delivery of binary payloads containing zero,
invalid UTF-8 and JSON-looking content, with core code making no payload-schema
decision. Application-level SAMPLE-1 validation remains in its handler.

## Evidence cleanup

The inspected tracked footprint is decimal bytes, excluding the Noise submodule:

| Area | Files | Bytes |
|---|---:|---:|
| `dev/evidence` total | 550 | 45,560,656 |
| All `.jsonl` traces within it | 15 | 33,040,683 |
| `noise-mcu-pressure-20260927` | 28 | 27,330,443 |
| `noise-mcu-console-20260927` | 57 | 9,420,695 |
| `noise-mcu-parallel-20260927` | 56 | 4,122,117 |
| `noise-mcu-20260927` | 70 | 2,802,385 |

Rows overlap: the four experiment directories contain approximately 96% of the
total. Byte-identical duplicates account for only about 166 KiB; deduplication
alone will not solve the problem.

Stage 1 already wrote `dev/DMP_Validation_Results.md` and reduced tracked
`dev/evidence` present in the worktree to 221 files / 898996 bytes. The census
above is the pre-cleanup inspection. The original instruction was to create
one concise `dev/DMP_Validation_Results.md` (then proposed, target <=32 KiB).
For each useful experiment retain the source revision, target/toolchain,
configuration, decisive measurements with units, outcome, limitations, rerun
command and historical artifact locator. Preserve failures and deferred checks
as such. Provider tests, host tests and physical endpoint tests remain distinct.
Do not copy every event or every successful intermediate build into the summary.

| Keep in the working tree | Summarize and remove after verification |
|---|---|
| Actual `src/`, headers, build definitions and maintained test runners | Repeated successful build/serial logs and raw packet traces |
| Normative vectors and minimal reproducible failure inputs | Superseded successful reports, duplicate disassembly and intermediate archives |
| Provider regression cases still needed by P01B, provenance and licenses | One-off exploratory programs whose useful behavior is already covered by maintained tests |
| Small machine-readable measurements actually consumed by tests | Historical orchestration scripts with no maintained reproduction role |

Inspect scripts inside evidence directories individually. Move useful rerun
tools into existing test/tool directories rather than deleting them by extension.
Do not remove provider failure regressions merely because the provider adapter
has not yet been integrated into the endpoint.

`profiles/deployments/resource-inputs.json` currently hashes several evidence
READMEs and `layout-summary.json`; `test_resource_input_hashes_match_source_bytes`
reads them. Initially retain those small inputs while removing bulky traces.
Then, if consolidating them, move the essential measurements into a compact
machine-readable fixture and update their consumers together. Preserve original
commit/path/hash provenance and exact measurement meaning. Keep a meaningful
fixture-integrity check; do not disable it to make cleanup pass. An exported
source tree must still validate without Git history or network access.

Update live README/board/plan links to the compact results or verified historical
locators. Keep `DMP_Normative_Cases.json` as the case ledger; do not introduce
another competing acceptance table. A useful cleanup target is <=1 MiB of
retained evidence plus the concise results file; justify any necessary excess.

Before deleting historical data, verify it exists in a reachable Git commit.
Preserve unique uncommitted P11 outputs until summarized and safely checkpointed
under separate commit authorization. Do not create another copy of all traces
in the repository. Removal reduces the checked-out tree, not historical `.git`
or full-clone size. History rewriting/force-pushing is outside this plan.

## Execution order after P11

Stage 1 received the committed P11 snapshot and finished the evidence
consolidation described in steps 1 and 2. Step 3 is gated by the frozen
stage-2 contract. Step 4 (P12) is not started.

1. **Receive P11:** inspect its completed diff and acceptance evidence. Record
   the exact baseline and actual active/index state. Reconcile its new manifest
   fields, profile hashes, assembly/tombstone storage and contract decisions.
   Do not restart the completed P00-P10 audit or interfere with its current work.
2. **Consolidate evidence:** produce the compact results, verify archive
   locators, remove redundant tracked artifacts and repair affected references.
   Run the existing resource-input/profile checks and verify footprint reduction.
   No protocol code changes belong in this cleanup package.
3. **Correct configuration and memory:** replace embedded JSON admission with
   typed runtime configuration; adapt P09/P10/P11 and their tests atomically.
   Keep host JSON tooling. Cover semantic admission failures, undersized storage,
   arithmetic overflow and the six buffer-budget cases with explicit settings.
   Re-run affected profile, identity, reliability and reassembly checks.
4. **Deliver P12:** connect the real modules into one runnable two-endpoint
   example with a clear send/receive API. Demonstrate exact payload delivery,
   loss/retry, duplicate suppression, fragmentation and bounded exhaustion using
   the same library sources. Report actual storage requirements for that setup.
   Any provisional authentication context remains visibly test-only.
5. **Integrate security and measure real endpoints:** resume P01B/P13/P14/P15
   dependencies. P13 stops at candidate keys; P14 owns protected FINISH/READY
   and activation after AEAD/AAD/PN. Use the MCU bench to measure this composed
   endpoint, including peak stack/heap and recovery, rather than repeating
   abstract provider throughput experiments. Qualify other MCU families
   separately; ESP32 results do not prove their footprint or behavior.

The coordinator owns the configuration API and shared documents. A cleanup
worker may own only enumerated historical artifacts and their summary; a code
worker may own explicitly assigned implementation/tests after interfaces are
fixed. Do not overlap active P11 paths. One focused independent review of the
configuration/security boundary and memory ownership is appropriate before
acceptance, using the user's agreed reviewer route.

Keep later gates: S10 deferred cases remain deferred, RADIO-1 is not silently
switched to retry-all, and P22 must exercise mixed Stream R/packet paths before
P23. These constraints do not justify expanding the immediate correction scope.

## Completion criteria

- No JSON parser or 419,936-byte admission requirement in embedded `libdmp`.
- Runtime configuration is independent of the host's fixed two-node test shape;
  this does not itself require adding multi-peer support to current modules.
- A checked storage calculation and observed footprint accompany each supported
  buffer configuration. Unsupported combinations fail explicitly.
- Historical experiments are navigable through one short results file; essential
  automated checks still work from a source export without archived raw traces.
- The next functional milestone is a runnable composed endpoint, with remaining
  SEC-1/MCU/interoperability limitations stated accurately.

This planning change does not run tests, change protocol contracts, accept P11,
delete evidence, alter the index, commit, push or operate hardware.

## Frozen stage-2 contract (2026-10-04)

Baseline: HEAD `fc83b84354d16bd72164d37eb5b5e9efd862f321` plus the stage-1
worktree. This section freezes the configuration API. It does not implement it.

Reconciled with current code, not with the 2026-10-03 draft alone:

- `libdmp` compiles an in-tree JSON parser by listing `src/identity/profile_admit.c`
  in the root `CMakeLists.txt`. No cJSON, yyjson, or other JSON library is linked.
  `src/identity/identity.c` does not parse or admit profiles.
- `dmp_profile_admit` requires caller scratch of `DMP_PROFILE_ADMIT_SCRATCH_BYTES`
  (419936). `KEY_REGION` in that parser is 419424. Both leave `libdmp`.
- `fill_profile` hardcodes `default_service = 1` and copies two node ids and two
  services. `DMP_PROFILE_NODE_COUNT` and `DMP_PROFILE_SERVICE_COUNT` stay 2.
- P10/P11 copy `dmp_admitted_profile` by value at init. The 12276-byte payload
  subtotal in the diagnosis matches `dev/DMP_Validation_Results.md` and still
  excludes tombstones. `direct-nnpsk0.json` charges `assembly_tombstone` as
  16 × 48 = 768 bytes. That charge stays.
- `tools/validate_profile.py` sets `PROFILE_HASH` with `hashlib.sha256(raw)` of
  the original manifest bytes. The harness has its own host parser
  (`tests/harness/manifest.c`, `json.c`) and does not call `dmp_profile_admit`.

### 1. Public C API

`dmp_config` and `dmp_admitted_profile` carry the same fields. They are not two
admission APIs. `dmp_config` is the borrowed input. `dmp_admitted_profile` is
the caller-owned admitted copy. Field set is exactly the current admitted view:

- `sha256[32]` — opaque bytes, copied, never computed by `libdmp`
- `namespace_id`, `node_id[2]`
- `default_service`, `service_id[2]`, `recovery[2]`
- `peers`, `operations_per_service`, `assemblies_per_peer`,
  `assembly_tombstones_per_peer`
- `sender_slots`, `assembly_slots`, `assembly_tombstone_slots`, `result_slots`,
  `history_slots`, `correlation_slots`, `adapter_slots`
- `application_queue_slots`, `control_slots`
- `message_bytes`, `fragments`, `chunk_bytes`, `encoded_mtu`, `forward_mtu`,
  `return_mtu`
- `queue_ms`, `response_timeout_ms`, `jitter_ms`, `send_horizon_ms`, `max_bursts`
- `receipt_delay_ms`, `receipt_limit`, `dedup_ms`, `rejection_ms`,
  `result_cache_ms`, `result_deadline_ms`, `correlation_ms`, `tombstone_ms`,
  `late_result_ms`, `collect_ms`, `assembly_ms`
- `tx_borrow`, `synchronous_completion`

Engines today read the service ids, default service, peers (reliability only),
slot counts, message/fragment/chunk/MTU, the deadline fields they already use,
`tx_borrow`, and `synchronous_completion`. The other fields stay in the view
because `fill_profile` already publishes them and the admit tests check them.
This stage does not add engine behavior for the unread fields (`sha256`,
`namespace_id`, `node_id`, `recovery`, `forward_mtu`, `return_mtu`,
`max_bursts`, `late_result_ms`, `collect_ms`).

Replacement entry point:

```text
dmp_status dmp_config_admit(const dmp_config *in, dmp_admitted_profile *out);
```

`in` and `out` are distinct. The call borrows `in` only until it returns and
does not retain it. It writes a copy into caller-owned `*out`. Failure leaves
`*out` unchanged. There is no scratch argument and no allocation. Admission
does not own TX buffers. `tx_borrow` and `synchronous_completion` are flags.
Immutable TX lifetime stays the existing transport rule: borrow mode keeps the
submitted frame immutable and exclusively owned until its one terminal callback.

Outcomes:

- `DMP_OK`
- `DMP_INVALID_ARGUMENT` — null, `in == out`, a zero `message_bytes`,
  `chunk_bytes`, `encoded_mtu`, or `fragments`, `fragments > 32`, or overflow
  of a derived product below
- `DMP_UNSUPPORTED` — `default_service` is 0 or not one of `service_id[]`;
  the two service ids are equal; `chunk_bytes >= message_bytes`; `peers == 0`;
  `assembly_tombstones_per_peer < assemblies_per_peer`; or
  `assembly_tombstone_slots` is below `peers * assembly_tombstones_per_peer`

`DMP_MALFORMED` and `DMP_INTEGRITY_FAILURE` are not admission results. JSON
syntax and digest mismatch stay in the host tools.

Removed from `libdmp` and from `include/dmp/identity.h`: `dmp_profile_admit`,
`dmp_profile_sha256_fn`, `dmp_profile_failure`, `DMP_PROFILE_ADMIT_SCRATCH_BYTES`,
`DMP_PROFILE_MAX_BYTES`, and the parser in `src/identity/profile_admit.c`.
Do not keep that entry point beside `dmp_config_admit`.

`dmp_reliability_init` and `dmp_reassembly_init` keep their current storage,
quota, and control-reserve checks. Callers admit first, then pass the admitted
copy. Reliability still rejects `peers != 1`. It still sets the control reserve
to `min(control_slots, adapter_slots)` and returns `DMP_UNSUPPORTED` unless
`adapter_slots` is strictly greater than that reserve. Reassembly still requires
`fragments` in `[2, 32]`. Those engine rules are not relaxed and are not
duplicated as a second reason to reject `direct-nnpsk0` inside `dmp_config_admit`.

Affected consumers that embed `dmp_admitted_profile` by pointer and by value:
`dmp_reliability_storage`, `dmp_reliability`, `dmp_reassembly_storage`,
`dmp_reassembly`.

### 2. Ownership and sizes

Caller owns every buffer and state object. The library never allocates on the
admit, receive, encode, or retry path.

Inputs are the `dmp_config` fields. Slot counts and `message_bytes` are inputs,
not results. Derived minima are checked at engine init and are not stored in
the profile:

| Derived byte length | Formula |
|---|---|
| sender payload | `sender_slots * message_bytes` |
| result payload | `result_slots * message_bytes` |
| receive payload | `message_bytes` |
| history metadata | `history_slots * DMP_MAX_HEADER_BYTES` (255) |
| correlation metadata | `correlation_slots * 255` |
| adapter frames | `adapter_slots * encoded_mtu` |
| assembly payload | `assembly_slots * message_bytes` |
| assembly metadata | `assembly_slots * DMP_REASSEMBLY_METADATA_BYTES` (255) |

Tombstone storage is separate from those byte arrays: `assembly_tombstone_slots`
objects of type `dmp_reassembly_tombstone`. The manifest contract reserves 48
bytes each. Current `direct-nnpsk0` is 16 slots, 768 bytes. Do not lower that
charge. Implementation confirms `sizeof` on the ABI under test. If it is not
48, stop; do not change the manifest charge to match.

Also account separately, and never fold them into the buffer budget: caller
slot structs (identity, reliability, reassembly), crypto workspace, and stack.
A buffer budget is not total endpoint RAM. Crypto is not implemented in this
library; report it as excluded. Stack is excluded. JSON scratch is zero after
this change.

The six buffer budgets are 1024, 2048, 3072, 4096, 8192, and 16384 bytes. Each
budget is the sum of the eight derived byte lengths above. For each budget the
implementation must record, as an acceptance output rather than a number chosen
here: supported or unsupported; `message_bytes`, `fragments`, `chunk_bytes`,
and the slot counts used; then separate totals for that byte sum, state
structs, tombstone bytes, crypto (excluded), and stack (excluded). A budget
that cannot fund the preserved `direct-nnpsk0` tombstone charge and a
reliability control reserve (`adapter_slots > control_slots >= 1`) is
unsupported. Do not shrink those charges to make the row fit. Unfragmented
reliability may omit the two assembly byte lengths; it may not omit the
tombstone charge when the configuration claims the current direct profile's
reassembly limits.

### 3. JSON, PROFILE_HASH, and tests

JSON stays the host deployment format. `tools/validate_profile.py` and
`tests/profiles/` keep full manifest validation, including cross-field checks
whose inputs are not on `dmp_config` (relay, security, freshness, region sums,
timing inputs such as forward delay and record margin). The library does not
reimplement that proof.

`PROFILE_HASH` remains SHA-256 of the exact original manifest bytes, including
a trailing newline. The host tool computes it. `dmp_config_admit` copies the
32 bytes and does not hash the struct or reformatted JSON. A handwritten test
may set the field, including zeros; that does not assert a manifest identity.
A host emitter that fills `dmp_config` from a validated manifest must copy the
digest of that file's original bytes.

C tests build `dmp_config` with initializers and call `dmp_config_admit`.
They do not embed a parser in `libdmp`. The harness parser stays a host tool.

### 4. Acceptance checks

Existing commands. Their targets exist. They check the host JSON tool and
allocator boundary. They do not by themselves prove typed admission:

```text
python -m unittest discover -s tests/profiles -p "test_*.py" -v
python tools/validate_profile.py profiles/deployments/direct-nnpsk0.json
python -m unittest tests.profiles.test_deployments.DeploymentTests.test_resource_input_hashes_match_source_bytes
python tools/check_core_allocators.py build/host/libdmp.a --nm nm
```

Run the allocator check only after a host build of `libdmp.a`. The same rule
applies to the other five deployment manifests if the implementation claims
their digests.

Existing CTest names whose sources must be retargeted before a pass counts.
A pass of the unmodified binaries still calls `dmp_profile_admit` and is not
acceptance of this contract:

- `identity.profile_admit`
- `identity.profile_parity`
- `reliability.direct`
- `reassembly.direct`

`identity.context` does not admit a profile. Re-run it as a regression.
`profiles.contract` stays the host JSON check. `harness.port` stays a host
parser check. `harness.subprocess` is not an acceptance check for this
contract; stage 1 already recorded its Windows temp-file failure.

Proposed, no target yet, not acceptance until the target exists:

- a test that `libdmp` exports `dmp_config_admit` and does not export
  `dmp_profile_admit`, and that the public header has no 419936 scratch
- a test that fills the six-row buffer-budget table under the rules above
- a host emitter, if added, checked by comparing its `sha256` field with
  `hashlib.sha256` of the original deployment file

After those tests exist, re-run `cmake --build build/host` and
`ctest --test-dir build/host --output-on-failure` for the retargeted names.
That full run is not claimed here.

### 5. Non-goals

- Do not start P12, flash a device, or integrate DTrack.
- Do not change wire encoding, payload opacity, header checks, service/ACL,
  SEC-1, retry, dedup, async TX, or the control-reserve rule.
- Do not keep a legacy JSON admission path inside `libdmp`.
- Do not treat a 1–16 KiB buffer budget as total endpoint RAM.
- Do not edit deployment manifest bytes or their `PROFILE_HASH` values.
- Do not drop the 16×48 tombstone charge or the control reserve to reduce RAM.

### 6. Owner decisions still open

- Closed 2026-10-04. See "Owner decision closed" below. The historical pair
  was `control_slots == 2` and `adapter_slots == 2`. P10's handwritten fixture
  still uses `adapter_slots == 4` and `control_slots == 2`.
- Widening `node_id` or `service_id` past the fixed pair is not part of this
  contract. Current modules and manifest contract 2 are still one pair and
  two services.
- If `sizeof(dmp_reassembly_tombstone)` is not 48 on an ABI under test, that
  ABI is not admitted by this freeze.

Not blockers, already authorized by the operator: proceed with this correction
while P11 is in `review`. Affected tests must be re-run. The existing P11
review does not cover the new admit path. Leave the uncommitted ignored files
`dev/evidence/p00/initial-staged.patch` and
`dev/evidence/p00/initial-unstaged.patch` in the worktree.

Implementation of this frozen contract can start without another owner
decision. It must not resolve the open items above by editing code or manifests.

## Stage 3 measurement pointer

Stage 3 recorded `sizeof(dmp_reassembly_tombstone)` and the six-row buffer
budget in `dev/DMP_Validation_Results.md`. This pointer does not change the
frozen contract above.

## Coordinator check (2026-10-04)

The typed-admission implementation matches the frozen contract. A first
reassembly-test draft treated `DMP_UNSUPPORTED` as success and still called
`dmp_reassembly_init`. That bypass is removed: success paths initialize only
after `DMP_OK`, and `assembly_tombstones_per_peer < assemblies_per_peer` is
rejected without init.

Coordinator rerun, existing `build/host`, 5/5 passed:
`identity.context`, `identity.profile_admit`, `identity.profile_parity`,
`reassembly.direct`, `reliability.direct`. Earlier same-day host checks remain
the profile unittest run (24), `validate_profile.py` on `direct-nnpsk0.json`,
the resource-input hash test, and `check_core_allocators.py` (no allocator
references; `dmp_config_admit` present, `dmp_profile_admit` absent).

Not done: full host CTest, P11 independent review of this snapshot, and P12.
P12 stays pending until P11 is accepted. The control/adapter item and the
buffer rows are updated in "Owner decision closed" below.

The 2026-10-04 independent review found no defect in the listed scope, so
there was nothing to fix. P11 acceptance is recorded on the work board. P12
was not started.

## Owner decision closed (2026-10-04)

The owner closed the control/adapter decision as a configuration correction
plus the same reserve check in admission. The reliability formula is unchanged:
reserve `min(control_slots, adapter_slots)`, reject unless `adapter_slots` is
strictly greater, including a zero reserve. `dmp_config_admit` and
`tools/validate_profile.py` use that rule. This supersedes the frozen sentence
that declined to duplicate the reserve inside `dmp_config_admit`.

`direct-nnpsk0.json` and `direct-xx.json` keep `control_slots` 2 and set
`adapter_slots` 3. Their endpoint adapter charge count is 3; `bytes_each`
stays 512. No deployment already had `adapter_slots` strictly above the
reserve. The four radio manifests have `control_slots` 4, so `adapter_slots`
3 would still fail the same reserve. Those manifests set `adapter_slots` and
the endpoint adapter charge count to 5. `control_slots` was not lowered.
Relay adapter charges are unchanged.

The six buffer-budget rows, including what was initialized and exchanged, are
in `dev/DMP_Validation_Results.md` under "Stage 3 buffer budget". They are not
total endpoint RAM. This note does not accept P11 and does not start P12.
