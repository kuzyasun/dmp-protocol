# Independent P02 source review

Reviewer: `/root/profile_review`, GPT-6 Astra, xhigh, fresh bounded assignment.
Read-only review of the frozen contract, schema generator/export and validator;
tests were being authored in a disjoint worker assignment and were excluded.
The coordinator checked the actual findings against the normative text and
implemented the confirmed corrections. No protocol document revision changed.

| Finding | Confirmed correction |
|---|---|
| P1: bootstrap omitted one-byte CRC32C descriptor | Include descriptor independently of four-byte trailer; 119-byte bootstrap chunk requires 145-byte direct core frame, not 144 |
| P1: return slots could consume all half-duplex time; relay service could be slower than incoming frames | Selected test binding now serializes bursts across the pair and reserves an entire path traversal plus two reverse control traversals per period; relay copies/tail/serial service fit per-hop and endpoint bounds |
| P1: missing cached-flight/confirmation/duplicate-response schedule and complete wire budget | Separate establishment attempts, intervals and response rate/byte windows; derive complete frame, duration and encoded-wire reserves, propagate through episode and relay gates |
| P1: freshness enabled without token admission, service-0 authorization and RAM | Explicit authorized node set, association/principal/request quotas, token/result lifetimes and retained-token/control resource charges |
| P2: late-result diagnostic behavior unspecified | Fixed ACK plus redacted diagnostic, no reopened operation or repeated callback; unmatched expired correlation drops |
| P1 follow-up: XX confirmation omitted cached flight 3 retries | Reserve a complete flight-3 copy in every confirmation slot and include it in timing/bytes/responses/relay/cache budgets |
| P2 follow-up: grant-result pool could be 17 bytes although grant RSP is 21 | Require every result slot to hold at least 21 bytes when freshness grants are enabled |

Final focused source review: all seven confirmed findings closed; no additional
concrete blockers found. Corrected symmetric R3 bound, worst four-byte PN and
fragment-index sizing, compact references, canonical service addressing,
first-admission lifetimes and final-admission freshness were also checked.
`source-review.json` identifies the exact accepted source files by SHA256.

Limits: source review is not execution evidence. No build, test, hardware,
production layout, physical scheduling or endpoint acceptance was claimed.
The test binding's conservative serialized model is a selected simulation
contract; later adapters must actually implement its reservations. Per-component
state sizes remain explicit design reserves until real library layouts exist.
