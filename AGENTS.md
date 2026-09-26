# DMP agent workflow

## Scope and authority

- Reply to the operator in Ukrainian unless requested otherwise; write repository artifacts in English.
- Read [README](README.md), [implementation plan](dev/DMP_Implementation_Plan.md), and [work packages](dev/DMP_Work_Packages.md) before implementation. Read only the normative sections needed for the assignment. `docs/` defines the protocol; the plan defines implementation gates; the work packages schedule those gates. Historical reviews in `dev/` are not normative.
- This repository currently contains documentation and fixture helpers. Creating this workflow does not authorize starting implementation. Once implementation is requested, proceed within that authorized scope without asking again for routine reversible work.
- Implement the single agreed contract. Do not silently resolve wire/security ambiguities, invent compatibility layers, weaken security, or change SAMPLE-1 to simplify tests. Report a concrete contradiction to the coordinator; material protocol choices require owner direction.
- Preserve unrelated changes and the existing Git index. Do not stage, commit, push, publish, deploy, provision credentials or operate hardware without explicit authorization. Preserve LICENSE and review dependency provenance before adoption.

## Team and ownership

- Use one coordinator, at most two implementation workers concurrently, and an independent reviewer when useful. Four agents is a concurrency ceiling, not a target; serial work is appropriate when dependencies dominate.
- The coordinator owns decomposition, public interfaces, integration, shared configuration, task status, evidence, and final acceptance. Workers do not spawn more workers by default.
- Follow the global Codex model-routing and escalation policy. Delegate bounded tasks with clear edit boundaries and checks; keep protocol/security decisions and final integration acceptance with the coordinator. Do not assign critical work to a weaker model merely to fill a slot.
- Give workers a concise brief, not the full conversation. Use native subagents for assignments; do not create separate user tasks unless requested.
- Every running assignment has an exclusive write set. The coordinator owns `include/dmp/`, root build/configuration and dependency files, `profiles/`, `docs/`, this file, README and the work board. Delegate a shared file only by explicitly transferring its ownership for that assignment. Other agents may propose changes but must not edit it concurrently.
- Workers normally own only their component implementation and dedicated tests. Before dispatch, expand package path prefixes into exact files or bounded, non-overlapping directories. Coordinate test/build registration through the coordinator. Shared filesystem agents see each other's writes: do not run acceptance checks on a moving snapshot.

## Coordinator loop

1. Inspect the checkout, relevant local guidance, branch, staged/unstaged changes and existing evidence. Preserve a baseline of relevant file hashes/diffs; a commit ID alone does not identify a dirty checkout.
2. Resume the work board. Select only packages whose dependencies are `done` and whose required decisions/contracts are available. A pending package becomes `ready` only inside the authorized implementation scope.
3. Freeze the minimum interfaces needed for the next packages: outcomes, ownership/lifetimes, injected ports, quotas and test seams. Avoid designing all future APIs at once. Record decisions in the package evidence; contract changes invalidate affected assignments and require revalidation.
4. Dispatch at most two independent assignments. Work locally on integration contracts or other non-overlapping work. If no independent work exists, use one worker or implement locally.
5. Receive the actual diff, commands and results. Inspect changes against the original brief and run the smallest meaningful integration checks. A worker's success message is not proof. Arrange independent read-only review for security gates and major state-machine integration, with a fixed snapshot and concrete test evidence.
6. Fix confirmed findings, rerun affected checks, and mark `done` only when acceptance evidence is recorded. After a failed check, clarify a missing requirement once or take over/escalate with the existing evidence; avoid repeated blind retries by weak workers.
7. Update the board and next dependency readiness. On interruption, record unfinished changes and stop/collect active workers before transferring ownership. A new session must check live workers and the actual files before resuming a stale `running` assignment.

## Assignment and completion format

Use the template in [work packages](dev/DMP_Work_Packages.md#assignment-template). Include the repository's actual absolute path, package ID, baseline, inputs, exact write set, excluded areas, frozen interfaces, acceptance checks and stop conditions. A proposed command becomes an acceptance check only after its target exists.

Workers return: changed files; behavior implemented; exact commands and outcomes; test-to-requirement mapping; resource/security limitations; open issues. Do not report fixtures, simulated traffic or compilation as physical transport evidence. Reviewers return actionable findings with file/line references, consequence, and a concrete failing case, or explicitly state the scope and remaining evidence gaps.

## Implementation invariants

- Keep the C core portable and payload agnostic. Platform, RTOS, transport adapters and application codecs remain outside it. No allocation in receive/encode/retry hot paths; caller-owned bounded state and explicit admission limits.
- Define copy/borrow, immutable TX buffer lifetime, delayed completion and cancellation before wiring transports. Structural parsing does not imply authentication or acceptance. PN/replay/acceptance changes must be atomic under the chosen concurrency contract.
- Use reviewed existing cryptographic primitives. The owner-authorized SEC-1 revision 5 direction permits a controlled Noise fork or reviewed C organization/port of the standard state machine, with provenance/licenses, an owned maintenance/change ledger and independent verification; no novel primitives, nonstandard transitions or ad-hoc KDF. Abort-first is current; preserve-state is deferred. Milestone 0 must prove required provider behavior before handshake layout or budgets are frozen. Documentation/research authorization alone does not authorize implementing a fork or adopting a production dependency. Test credentials and authenticated-context stubs cannot enter production builds.
- Use exact normative bytes and independent expected values. Maintain the plan's case-to-test matrix; provisional secure-context tests require real SEC-1 reruns. Unsupported optional modules require explicit rejection and a scope statement.
- The deterministic harness injects faults into real endpoints; it must not implement a substitute protocol. The independent peer owns its codec and state machines and is developed from the published contract, without reading/copying the primary implementation. Permitted shared inputs are specified in the plan.
- Host, simulation and physical evidence are separate. Do not advertise a transport or embedded RAM budget based only on host tests. Release readiness does not authorize release publication.

## Checks and documentation

The existing fixture check is `node dev/dmp_verify_security_vectors.cjs`. The CMake, profile, simulator and benchmark commands in the implementation plan are proposed until their packages implement them. Do not claim they ran before they exist. Record actual tool versions, source/configuration hashes and test outcomes. Keep secrets out of logs and diagnostic fixtures.

Use focused existing tests and then the applicable integration gate. Update canonical documentation only for accepted durable changes; put execution evidence in `dev/`. Keep this workflow small: the work board and its linked evidence are sufficient; no additional task-management service is required.
