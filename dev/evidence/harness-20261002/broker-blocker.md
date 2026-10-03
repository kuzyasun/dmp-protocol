# P07 broker dispatch blocker

Observed 2026-10-02 after live READY and fully paginated DMP discovery at
configuration revision 3. All eight DMP route bindings matched saved config.

- Operation: `agent_session_spawn`, idempotency key
  `dmp-p07-worker-spawn-20261002-a1`.
- Route: `dmp_cursor_worker`; provider Cursor; model `grok-4.7-high`;
  effort `high`; adapter discovery version `0.2.9`.
- Requested workspace: current `dmp-current`; policy selected by route.
- Result: `PROVIDER_INCOMPATIBLE: Wrapper shell identity unavailable`.
- Broker explicitly reported `execution_started=false`. No turn ID exists.
  A subsequent sessions list was empty. No paid inference was launched.
- Impact: P07 implementation dispatch cannot start on the selected Cursor route.
- Source diagnosis: `src/providers/common/readiness.ts` in Agent Broker throws
  this error when a cmd/PowerShell shim's shell executable cannot be resolved.
  Saved Cursor pin is the PowerShell `cursor-agent.ps1` wrapper. This identifies
  the preflight class, not the exact daemon environment fault.
- Workaround/status: none applied. No daemon restart, quarantine clearing,
  route/model substitution, Beehive cancellation or broker source/config edit.
  Resolve the runtime shell identity through the operator or obtain explicit
  authorization for a different configured route before paid dispatch.

Owner response: keep Cursor; the owner will repair the broker launch. Do not
use alternative providers. Await confirmation of the repaired runtime, then
repeat live READY/full DMP discovery and resolve the failed no-inference spawn
using its original idempotency key before sending the P07 turn.

RBO initially returned `fetch failed`. The owner subsequently started RBO and
authorized using it, with local host builds if RBO fails or fuller logs are
needed. Repeat discovery found idle `agt_01M3BXVR9A72WFMTYCFS4ZEK67`, macOS/arm64,
with capacity five jobs; no build was submitted yet. Reviewer/complex routes are fixed for this chat to
`dmp_cursor_reviewer` (`grok-4.7-xhigh`, no effort override) and
`dmp_cursor_large` (`grok-4.7-high`, `high`); escalation needs owner agreement.
