# P21D execution checkpoint — 2026-10-12

## Objective and boundary

Implement the independent peer's SELECTIVE-32 sender/receiver behavior and bounded transparent RADIO-1 relay role. Exercise applicable R6/R7 peer-local cases with protected fragmented DATA and the canonical large service-2 request/result fixtures, relay S10.06 behavior, and P03 retry-all under its own frozen manifest.

This checkpoint covers the independent Python peer and its tests only. No primary C source, C test, normative document, schema, profile manifest, public peer API, dependency, hardware, or deployment artifact changed. The peer uses the published contracts and maintained `cryptography==46.0.4`; it does not reuse the primary endpoint/recovery/relay state machines.

## Frozen inputs and implementation snapshot

- Branch / HEAD: `feat/initial-version` / `734d20aa7d078b4799559f55050dca4dc4d2fac5`.
- Runtime: CPython 3.12.8; `cryptography` 46.0.4.
- Frozen RADIO-1 NNpsk0 manifest: `9767b5daff88424e64887dd78a335c4de0f9b93900d4512c1cec9c4d041b53a9`.
- Frozen TEST-RADIO-RETRY-ALL NNpsk0 manifest: `bc8bba7c929c6d0fe9ad39dbe66a6699d342304ae8485ddf5cac9e32605b55f1`.
- Other manifest/schema/normative hashes were not changed.

Reviewed source/test snapshot SHA-256:

| File | SHA-256 |
|---|---|
| `tests/peer/dmp_peer/delivery.py` | `C2BE262F74CC6C232E760EC4B00309F73B66DAAB9650A436747592E3A31CF72` |
| `tests/peer/dmp_peer/endpoint.py` | `5D254FA9DD8B9E5A3513433B663923DA474AECA648E9E2783C3B6729D81C2B1B` |
| `tests/peer/dmp_peer/reassembly.py` | `621B0E7F941D8A905C94293EF4F9506A0E44A29B114031E25C4089799DFE7477` |
| `tests/peer/dmp_peer/relay.py` | `C90A12F6AA7AD000C830B6A9C6168F5522A43C0DAB8E2BFB4D49E8D996A716F4` |
| `tests/peer/dmp_peer/selective.py` | `1EF6FCC01586AC5541734D110B36B127451785F46EAEBEDE6A02D10F95A2E687` |
| `tests/peer/tests/test_p21d_relay.py` | `D16EF3BC606CE40BB4FA85632EEF97928CAC87413E34BB79010A4537E2007AAB` |
| `tests/peer/tests/test_p21d_relay_integration.py` | `38B45F98FF455949B14B0E8E69048164FDAA01DFBB37113EA485186732CC39A1` |
| `tests/peer/tests/test_p21d_selective.py` | `032BAB0D1F5EB9FBB837B5C0B2E465A99D3D1F46C395F0920C59C5D5B6862E01` |
| `tests/peer/tests/test_p21d_selective_edges.py` | `D8F2C1B82CDE8B7E7AD97C30A6CC6FEB45E1E2B8A8DD6C10CCBA683EA617D01E` |
| `tests/peer/tests/test_p21d_selective_state.py` | `26E2852EAD8BBD27DEC03E5A61D7D2834DCF35D14C407D6E8F38C8EFBAA93FBE` |

## Implemented coverage

- Independent bounded SELECTIVE-32 transfer state for reliable fragmented REQ/RSP/DATA, fresh-PN repairs, single-flight scheduling, final-fragment probes, status/burst/probe budgets, horizon expiry, terminal ACK/result precedence, sequence exhaustion, and maximum-PN protected sizing.
- Protected R6 N=8 request case drops fragment indices 2 and 6, checks mask `0x44`, repairs only 2 and 6 with fresh packet numbers, and verifies one accepted request/result. The 1,024-byte R6 request/result path uses P20 canonical bytes: request `(i mod 256) XOR 0x5A`, result `(i mod 256) XOR 0xA5`.
- R7 receiver/admission cases cover feedback binding to a live same-service transfer and association, ACL and freshness admission before reassembly, terminal result behavior, due feedback retained through `feedback_delay` while adapter slots are unavailable, bounded expiry/rearming, tombstone pressure, and TYPE-8 extension rules. Unknown safe extensions are ignored opaquely for both empty and nonempty values; unknown critical and forbidden known extensions are rejected.
- TX admission and failed-unsent completion retire selective queued/active siblings; receipt replay honors the frozen receipt limit. TELEM and protocol-rejection ERR do not open feedback, while EVENT is eligible.
- Transparent RADIO-1 relay state enforces exact frozen-profile admission, protected frame bounds, explicit route/context, TTL decrement, fragment identity consistency, per-key cooldown/count/expiry, cache slots and per-origin/global airtime. Integration tests forward protected endpoint traffic, FRAG_STATUS and fresh-PN repairs/results through relays while verifying protected bytes remain unchanged except permitted TTL framing.
- P03 retry-all uses a fresh peer association and the separate frozen TEST-RADIO-RETRY-ALL manifest. Loss triggers a full-fragment retry, with no TYPE-8 or selective downgrade path.

## Validation

Commands run from `tests/peer` unless stated otherwise:

- `$env:PYTHONPATH = 'tests'; python -B -m unittest tests.test_p21d_selective tests.test_p21d_selective_edges tests.test_p21d_selective_state tests.test_p21d_relay tests.test_p21d_relay_integration -q` — 46/46 passed.
- `python -B -m unittest discover -s tests -q` — 284/284 passed.
- From repository root, `python -B -m compileall -q tests/peer/dmp_peer tests/peer/tests` — passed.
- From repository root, `git diff --check --ignore-submodules=all` — passed; only Git LF-to-CRLF working-copy notices were emitted.

## Review and acceptance

**P21D peer-host scope accepted on 2026-10-12** after final independent read-only review. The reviewer verified all 10 source/test SHA-256 hashes before and after analysis (0 mismatches), confirmed branch/HEAD, and found no actionable findings. The review checked the frozen main/SEC-1/SELECTIVE-32/P20 contracts and all six previously reported findings; it also ran P21D tests 46/46 and in-memory probes for fragmented-result TX rejection and `failed_unsent` cancellation. The primary implementation and primary C test/trace paths were not used.

The coordinator's local P21D tests pass 46/46, the complete peer suite passes 284/284, `compileall` passes, and `git diff --check --ignore-submodules=all` passes. The exact commands and final source/test hashes are recorded above.

## Remaining evidence boundaries

This acceptance is limited to the independent peer's host/simulation scope. It does not prove a named executable binding or complete scheduled return-slot envelope (P22), S10.11 mixed-binding interoperability or independent interoperability (P23), primary firmware behavior, MCU memory/runtime bounds, radio driver behavior, or physical transport acceptance. No commit or push is included.
