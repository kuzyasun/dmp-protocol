# P05/P06 independent review

Reviewer: `/root/codec_framing_review`, GPT-6 Astra xhigh, read-only.
Workers: `/root/p05_codec` and `/root/p06_framing`, GPT-6 Luna high,
disjoint exact source/test ownership; coordinator owns integration and acceptance.
No recursive delegation, test-only replacement protocol, Git mutation or hardware.

Confirmed findings were checked against actual source and normative bytes:

| Finding | Fix and regression | Result |
|---|---|---|
| Failed Stream L decoder ignored later timestamps, permitting reset into the past | `last_now` advances on valid calls even after latched failure; `test_restart_prefix_and_bad_lengths` checks failure, poll at 100, rejected reset at 2, allowed reset at 100 | Closed |
| Encoders could emit FRAG/ROUTE without SEQ or broadcast ACK_REQ that parser rejects | Shared preflight validates all three combinations before output; `test_encoder_required_identity_and_ttl` checks both encoders and unchanged destination | Closed; failing before-fix log retained |
| Encoder silently truncated TTL 16 to 0 | Reject TTL >15 as invalid API input before encoding; same sentinel test | Closed |
| default_service=0 bypassed canonical service and reserved STATUS checks | Validate for every configured default, including zero; `test_nested_error_offsets_and_zero_default` | Closed |
| Nested value-relative ULEB offsets were lost/double-interpreted | Add value start once; distinguish overflow, nonminimal, trailing and bounded truncation; exact offsets 5/13/4/6/6/7 tested | Closed |
| Header-boundary truncation contradicted broad API wording | Clarify enclosing header/TLV boundary versus packet truncation in header/interfaces, with tests; no wire revision | Closed |
| COBS/recovery coverage gaps | Zero before/after full blocks, malformed and decoded-oversize recovery, initial-prefix/reset cases and late feed tests | Closed |

Coordinator also caught draft worker issues before acceptance: minimal-header
encoding, header-only length placeholders, header-bounded SEQ, required SEQ,
raw extension tags, invalid literal fixture lengths and framing test canaries/
monotonic reset expectations. Tests execute the real library sources. The final
new malformed-header regression rejects unexplained header bytes.

Reviewer completed the fixed source pass with no open actionable findings.
Reviewed codec SHA256: `66a4de185782cb2660a12de866b79dca4a367b804f6abc41cd56ab11809783fa`.
Reviewed Stream source SHA256: `decb576cca75b60a21513acd2bffec4a52aa18037d673e540319f202fd730d04`.
These runtime sources stayed unchanged through acceptance. Later changes are
the extra unexplained-header test and documentary implementation-status comments;
final acceptance hashes are in checks.json. Coordinator reran Debug/Release
after those changes. Original review inspected Debug10/10, zero-warning builds,
tests-off archive and symbol dependency logs; Release10/10 is recorded separately.

Scope: host structural codec, CRC/COBS and framing only. This does not close
SEC-1 context/CID/control/association eligibility, authenticated acceptance,
relay behavior, endpoint delivery, sanitizer/fuzz or MCU qualification.

Final narrow evidence review also closed: reviewer checked the accepted Debug
and Release 10/10 logs, all recorded source/configuration/artifact/log hashes,
existing test-function links and the ledger's 23 passed primary + 10 partial
primary / 33 partial whole rows + 104 not-run counts. One wording overclaim was
corrected: published packets exercise Stream R round trips, while fault recovery
is covered by stream.framing. No open evidence finding or S10 pass remains.
