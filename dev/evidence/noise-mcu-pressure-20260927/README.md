# MCU-03 serialized live-owner and quota pressure

Status: MCU-03 accepted after independent source, host and physical evidence
review. P01 remains running.

Continue from accepted MCU-02 serial provider evidence. Owner authorized this
next step and repeated bench-board flashing. No firmware change is planned:
ESP32-S3 COM23 and ESP32-C3 COM35 retain source fingerprint
71e3a2d6f1a77ce124ea402eded20bcb44aee34c6a23de5007bd41e67a791086.
Existing dirty work and Git index are preserved; no commit/push in this wave.
Preflight confirmed both original MCU-02 boot IDs and empty provider arenas.
Heap minimum and task-stack high-water therefore cover the continuing boot
session, including MCU-02; they are not isolated per-case peaks. RESET changes
only empty provider arena accounting/quota, not SDK memory or task history.

## Scope and acceptance

Add a Python-only runner using the existing strict serial client and real
provider operations. First validate two actual host processes on RBO, then run
the same scenarios on the supplied MCU pair. One endpoint owns its own quota;
do not sum the RAM of both boards as an endpoint budget.

- Sweep byte quotas 2048, 3840, 4096, 8192, 32768, each in two role orientations.
  Metadata/backing/scratch/SDK memory remain outside the logical byte quota.
  The 3840 boundary uses MCU-02 observations: C3's two NN plus one XX pending
  contexts and two guards occupy 3824 bytes, leaving less than a Split clone.
  This is an experimental pressure point, not a production memory envelope.
- Preserve two established guard pairs (NN and XX) while admitting up to six
  pending pairs, alternating patterns and roles. Actual Noise flights pass
  unchanged between peers; validate actions/plaintext/handshake hashes.
- Interleave pending flights with bidirectional guard traffic, using fresh TX
  PN and slot-specific payload/AAD. Cancel/recreate a middle pending pair while
  neighbors remain live, then complete or explicitly refuse pending Split.
- A refused NEW must have exact OOM and restore the candidate's pre-call arena
  bytes/blocks. Split OOM is recorded separately with preserved ownership; it
  never counts as completion. Other failures abort the run.
- Inject NEW allocation failure on each board while guards remain alive;
  verify unchanged baseline and subsequent authenticated guard traffic.
- RESET with live owners must fail without changing quota/accounting. Close
  every accepted owner; live arena/blocks and wipe errors must be zero and
  successful allocations equal releases. Restore quota 32768 when finished.
- The full-quota cases must admit and complete all six requested pending pairs.
  Smaller quotas characterize safe refusal, not successful full admission.

Coordinator owns security/state/resource acceptance, registration, source
identity and evidence. Worker owns only the new pressure runner; an independent
read-only review checks the fixed runner and actual host/MCU traces. No new
protocol wire contract, radio or production API.

This tests multiple live owners with serialized, interleaved operations. It is
not concurrent task/thread execution, a DMP admission policy, endpoint memory
budget, RF behavior or non-Espressif runtime proof.

## Frozen source and host verification

The scenario runner added in MCU-03 is
`tests/provider/console/serial_pressure.py`. Its final LF-normalized SHA-256 is
`3902ee4c2398bb301c5c0ed58138fcf3a24dc0b5d196fe3c9a85a984d4396c0a`.
The shared serial client is unchanged; see [runner-hashes.json](runner-hashes.json)
and the pre-wave [baseline](baseline.json). Python scripts are not part of the
embedded source fingerprint. No C, SDK configuration, binary or board flash
changed in this wave.

Commands are preserved in [remote-validation.sh](remote-validation.sh). RBO
macOS ARM64 final job `job_01M3GAPJMFMTAGXQVYV2KP1Q6J`, attempt
`att_01M3GAPNDV5XMTJBRW5A31ZX2W`, snapshot
`snp_01M3GAPJVWSVNGBGQWB2V94RAM` / content
`sha256:a9b2139ec37099f7de80a969accdbffc1969488deb023f875cb4555277d54462`
completed successfully. The three provider-console CTests passed; both real
host processes completed all ten pressure cases (5192 responses). All seven
collected artifact hashes were checked before copying to [host-final](host-final/)
against [RBO metadata](host-final-artifacts.json).

An initial successful host run is retained under [host](host/). Independent
review found a harness gap: it could miss a provider that exceeded its quota.
The final runner asserts `0 <= live <= peak <= quota`, the expected configured
quota at case boundaries, and at least one actual quota refusal in the sweep.
The final host job reran the corrected snapshot. Initial runner SHA was
`0203c98371359bf8e7f41d10d8db84a8026bd512ca187eb2aeaf2d4492eba557`;
its run is historical evidence, not acceptance of the corrected harness.

Independent review of final source and host evidence found no remaining
blockers: raw/decoded replies, command IDs, identities, byte forwarding,
fresh direction PN, allocation bounds, reset rejection, cleanup and summaries
agreed. Host ABI reached NEW OOM at lower quotas but did not reach Split OOM.
The standalone [summarize.py](summarize.py) additionally audits every raw
response and forwarded flight/packet without importing the scenario runner;
its final host output is [audit.json](host-final/audit.json).

## Physical command and provenance

Run from the repository root, using local Python 3.12.8 and pyserial 3.5:

```text
python tests/provider/console/serial_pressure.py --ports COM23 COM35 --output dev/evidence/noise-mcu-pressure-20260927/physical.jsonl --timeout 10
python dev/evidence/noise-mcu-pressure-20260927/summarize.py dev/evidence/noise-mcu-pressure-20260927/physical.jsonl
```

Stdout and stderr are captured in `physical-summary.json` and
`physical-stderr.log`; the independent offline audit is saved as
`physical-audit.json`. [Preflight](preflight.jsonl) precedes this sweep.
Peer 1 is S3 COM23 / boot `2fd98bd7d15e1414`; peer 2 is C3 COM35 /
boot `248c7a1b27b9a9e4`. Physical identification, binary hashes, build/compiler
configuration and verified flash logs remain in the accepted
[MCU-02 physical evidence](../noise-mcu-console-20260927/physical/README.md).

Only a completed candidate with successful Split on both endpoints and
bidirectional authenticated traffic counts as completed. Split OOM proves the
reported action and ownership/accounting remain suitable for explicit cleanup;
the scenario does not retry that same candidate later or claim preserve-state
handshake semantics. In particular, one peer may already have split when its
partner refuses; both are explicitly closed before testing continued guard
traffic.

## Observed physical results

All ten cases passed in 383.147 s, exit 0 and empty stderr. The trace contains
5717 responses, 152 forwarded handshake flights and 1380 authenticated packet
transfers. There were 327 complete guard rounds (four directional packets per
round) plus 72 candidate packets. Boot/build identities stayed constant; no
reset, timeout or unexpected return code occurred. Raw trace SHA-256:
`d47469897495e35894d079f05e8e35348e36e92792b79caffefd968242d3128f`.

Each table row applies to both role orientations; peaks are maxima across the
two orientations. Candidate counts exclude the two established guard pairs.

| Per-endpoint byte quota | Candidates admitted / completed | Peak S3 / C3 bytes | Natural refusal |
|---:|---:|---:|---|
| 2048 | 1 / 1 | 1944 / 1632 | S3 NEW for next XX candidate |
| 3840 | 3 / 2 | 3800 / 3824 | S3 NEW for next XX; C3 Split for one NN candidate |
| 4096 | 3 / 3 | 4048 / 3936 | S3 NEW for next XX candidate |
| 8192 | 6 / 6 | 7280 / 7568 | None |
| 32768 | 6 / 6 | 7280 / 7568 | None |

At quota 3840, C3's 3824 live bytes left insufficient room for its Split clone.
In orientation 0 S3 had already split; in orientation 1 C3 refused first. Both
cases explicitly released the unsuccessful pair and continued guard traffic.
These two refused candidates are excluded from the 36 completed candidates.
Every scenario also cancelled/recreated one pending pair and injected the
first NEW allocation failure on each MCU while both guards remained live.
No whole failure-ordinal sweep is claimed.

At the largest admitted configuration, each MCU held six pending contexts
alongside two active contexts; all six later became active and passed their
own bidirectional traffic checks. Every scenario ended with zero live bytes,
blocks and wipe errors, balanced allocations/releases, then the final sweep
restored both quotas to 32768. No allocation occurred during guard/candidate
packet encryption/decryption.

| Measurement (bytes) | ESP32-S3 | ESP32-C3 |
|---|---:|---:|
| Peak charged provider arena | 7280 | 7568 |
| Retained arena backing | 32768 | 32768 |
| Arena metadata / owner table / shared scratch | 1056 / 192 / 2177 | 1056 / 192 / 2177 |
| Free internal heap at every response | 346888 | 285192 |
| Minimum free internal heap since boot | 346872 | 285192 |
| Minimum largest heap block | 286720 | 147456 |
| Task stack high-water used out of 12288 | 2256 | 1712 |

Heap/stack minima cover the continuing MCU-02 boot session. S3's observed stack
usage increased by 64 bytes over MCU-02. Logical quota, measured live provider
bytes and total firmware RAM are different quantities; the retained arena was
not resized for smaller quota cases. No accumulation was observed in this
bounded run; it is not a duration-independent leak proof.

Recommended next step: bounded simultaneous crypto execution on independent
owners, with explicit allocator/entropy ownership and per-task stack evidence,
then a longer repeated-lifetime run. Keep radio disabled until its entropy
ownership is addressed. Non-Espressif runtime and the full P01 resource gates
remain open; MCU-03 does not advance P02 or select a production memory budget.

## Independent review and coordinator acceptance

Read-only reviewer `pressure_review` (GPT-6 Astra, xhigh) accepted the final
runner, final host artifacts and physical evidence without unresolved findings.
The initial harness quota-check finding was fixed and host checks repeated
before physical execution. The reviewer independently reconstructed ownership
and role/flight actions from all 11870 physical records, including 5717 replies;
checked raw/decoded JSON, IDs, stable identities, byte forwarding, fresh PN,
quota/counter invariants, no traffic allocations and agreement of all case/run
summaries. Both asymmetric Split failures and their immediate explicit cleanup
were checked, as was subsequent guard traffic and return to the guard baseline.

The observed nonzero results were exactly 26 NEW OOMs (six natural and twenty
injected first-allocation failures), two C3 Split OOMs and twenty rejected
live-owner RESETs. The coordinator checked the actual runner, repeated host
results, raw physical evidence and offline audit, and accepts this bounded
serialized/interleaved multi-owner experiment. Split retry-state, parallel
crypto execution, RF, production admission and whole-DMP budgets remain unproven.

[validation.json](validation.json) records final trace/report hashes and
unchanged pre-existing console executable, normative-document and Git index
hashes. Existing dirty work was preserved; no commit or push was performed.
