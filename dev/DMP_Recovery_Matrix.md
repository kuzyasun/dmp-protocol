# P19 recovery case-to-test matrix

Host simulation only. These runs are not physical transport evidence. P19 is not accepted. P12 stays running. S10 case 11 stays pending for P23.

Printed `tx_bytes` / `rx_bytes` inside one ctest process accumulate from `reset` at the start of that process. `retained_payload` is the high-water of live sender, result and assembly payload lengths scanned in the test. `provider_peak` is the high-water of the test allocator passed to `dmp_provider_setup`. `caller_node` is `sizeof` of one caller-owned endpoint node (63872). The provider peak in every passing run was 2826.

## Measured lines

| CTest | Printed line | Notes |
|---|---|---|
| scenarios.geometry | `tx_bytes=10870 rx_bytes=9356 retained_payload=2048 provider_peak=2826 outcome=direct-n16` | RADIO-1 64-byte service 2 is one unfragmented frame. 256/512/1024/993 still fragment. DIRECT-1 1024 and 961 completed. The extra tx bytes are the one-frame boundary probes (radio and direct), which are not delivered. |
| scenarios.r6 | `r6-2of8 tx_bytes=766 rx_bytes=708 retained_payload=512` | This line is that case only. Later r6 lines in the same process are cumulative. |
| scenarios.r6 | `r6-mtu tx_bytes=3813 rx_bytes=2088 retained_payload=512 provider_peak=2826` | End of the r6 process. |
| scenarios.r7 | `r7-conflict tx_bytes=10497 rx_bytes=1795 retained_payload=512 provider_peak=2826` | End of the r7 process. Tombstone pressure is inside this total. |
| scenarios.retry_all | `retry-all-expiry tx_bytes=1764 rx_bytes=1173 retained_payload=512 provider_peak=2826` | Loss line was `tx_bytes=1212 rx_bytes=1035`. |
| scenarios.relay_sample | `s10-06-relay tx_bytes=32 rx_bytes=0 retained_payload=0` and `sample1 tx_bytes=146 rx_bytes=114 retained_payload=34` | Relay cache was not delivered to an endpoint. |
| scenarios.feedback | `r7-determinism tx_bytes=2235 rx_bytes=1438 retained_payload=512 provider_peak=2826` | Seed `0x0d19` drops three indices. Repair indices, masks and wire bytes match. |
| scenarios.gaps | `gaps tx_bytes=8369 rx_bytes=6318 retained_payload=2048 provider_peak=2826` | End of the gaps process. Geometry and gaps assert `provider_peak <= 3*12288` and a nonzero retained peak inside the sender/result/assembly charges. |

## R6

| Case | Test | Outcome |
|---|---|---|
| sel-r6-2of8 | `scenarios.r6` mask `0x44`, repair indices 2 and 6 only, one REQUEST, bytes match | Pass |
| sel-r6-final-all-loss, final slice | `scenarios.r6` `r6-final-loss` | Pass. Probe index 7 completes the transfer. One acceptance. |
| sel-r6-final-all-loss, all initial | `scenarios.r6` `r6-all-loss` | Pass. Probe index 7 is the first admitted slice (`DMP_INCOMPLETE`). |
| sel-r6-status-loss | `scenarios.r6` `r6-status-loss` | Pass. Dropped status, duplicate probe, one later FRAG_STATUS. Both snapshots keep mask `0x44`. The second SEQ and PN differ from the first. Five extra polls add no status. |
| sel-r6-repair-loss | `scenarios.gaps` `lost-repair` | Pass. Index 2 is dropped, the repair is dropped, the later mask still has bit 2, then that repair completes once and the body matches. |
| sel-r6-final-ack-loss | `scenarios.gaps` `lost-ack` | Pass. The acceptance ACK is dropped. The probe draws one later ACK. `accepts` stays 1 and `unknowns` stays 0. |
| sel-r6-order | `scenarios.r6` inside `r6-2of8` | Pass. A fresh-PN FRAG_STATUS with SEQ 0 does not replace mask `0x44`. Replaying the real status frame returns `DMP_AUTHENTICATION_FAILURE`. |
| sel-r6-tombstone | `scenarios.r6` `r6-tombstone` | Pass. Expired tombstone, late slice `DMP_DEADLINE_EXPIRED`, `accepts` stays 0. |
| sel-r6-restart | `scenarios.r6` `r6-restart` | Pass. `dmp_hs_cancel` on both attempts. The next slice is `DMP_AUTHENTICATION_FAILURE`. No resume. |
| sel-r6-after-accept | `scenarios.feedback` `feedback-terminal` | Pass. After the ACK, a new FRAG_STATUS does not queue more slices. |
| sel-r6-mtu-return | `scenarios.r6` `r6-mtu` | Pass for admission: `return_mtu` 0 on a SELECTIVE-32 config is `DMP_UNSUPPORTED`. No live-transfer MTU shrink was available without a profile field. |

## R7

| Case | Test | Outcome |
|---|---|---|
| sel-r7-protected-vector | `fixtures.recovery`, `recovery.frag_status` | Pass. P18 fixtures. Not re-derived here. |
| sel-r7-type8 | `scenarios.r6` stale SEQ; `scenarios.feedback` `feedback-ineligible`; `scenarios.gaps` `negative-status` | Pass for zero, all-N (`ff 00 00 00` at N=8), out-of-range (`00 01 00 00`), wrong service, and payload length 3. Length 3 is refused by `dmp_hs_seal_logical` before a frame exists. The live sender mask does not change and no repair is queued. |
| sel-r7-determinism | `scenarios.feedback` `r7-determinism` | Pass. Seed `0x0d19` drives three distinct drops. Two runs compare dropped indices, repair indices, status frames and burst wire bytes. |
| sel-r7-profile | `scenarios.r6` `r6-mtu`; existing `identity.profile_admit` | Partial. Zero return MTU rejects. The rest of R3 admission stays with the existing admit tests. |
| sel-r7-full-loss | `scenarios.r6` `r6-all-loss` | Pass. All eight initial slices are lost; probe index 7 is admitted (`DMP_INCOMPLETE`), status mask `0x7f` repairs indices 0–6, the body is accepted once, and the ACK clears the sender without an unknown outcome. |
| sel-r7-delayed-status | `scenarios.async_radio` `async-radio-delayed-status` | Pass on the explicit asynchronous test profile. FRAG_STATUS arrives while an ordinary local completion is pending; the sender applies feedback after finishing the in-flight frame. |
| sel-r7-no-storm | `scenarios.r6` `r6-status-loss` | Pass for the extra-poll bound above. |
| sel-r7-tombstone-pressure | `scenarios.r7` | Pass. 16 expired tombstones, the 17th slice is `DMP_QUOTA_EXHAUSTED`, `accepts` stays 0. |
| sel-r7-result-race | — | Open. `synchronous_completion` is true, so a burst is finished before a status and a result can be in flight together. Needs the delayed-completion seam. Not invented here. |
| sel-r7-pn-seq | `scenarios.r6` replayed status | Partial. Old PN fails authentication. A PN near 2^24 and a SEQ wrap were not driven. |
| sel-r7-mismatch | `scenarios.gaps` `negative-status`, `status-wrong-association` | Partial. Wrong service does not schedule a repair. A status sealed to the initiator CID is `DMP_AUTHENTICATION_FAILURE` on the responder, and the replay is an old PN. A second association with different keys was not built: this fixture repeats the same PSK, CID and entropy. |
| sel-r7-relay-cooldown | `scenarios.relay_sample` | Partial. See S10 case 6. Cooldown on the sealed frame returns `DMP_BUSY`. |
| sel-r7-expiry | `scenarios.r7` `r7-expiry`; `scenarios.retry_all` expiry | Pass. After the result deadline the sender does not emit more frames. A late slice is `DMP_DEADLINE_EXPIRED`. |
| sel-r7-acl-freshness | `scenarios.r7` `r7-acl` | Partial. Service 2 submit without `DMP_ENDPOINT_PERMIT_REQ` is `DMP_UNSUPPORTED` and sends nothing. Freshness tokens are not implemented. |
| sel-r7-no-slot | — | Not run. The admitted binding completes synchronously, so a return slot cannot be removed while a status is due. |
| sel-r7-independent | — | Not run. Independent peer is P21D. |

## Other required rows

| Item | Test | Outcome |
|---|---|---|
| Service 2 opaque lengths | `workloads.opaque_len` | Pass for the length helper. 64 is no longer an N=2 transfer at MTU 256. |
| TEST-RADIO-N2, 64-byte service 2 | `scenarios.geometry` and `scenarios.async_radio` | Pass at the exact 119-byte path MTU, with a separate manifest digest. The protected encoder emits exactly indices 0 and 1 at 32 bytes each; both deliver one matching request. Async recovery also repairs missing index 0 with status mask `0x01`. RADIO-1 and retry-all manifests are unchanged. |
| RADIO-1 64-byte service 2 | `scenarios.geometry` | Pass. One frame, `index == 0xffffffff` (no FRAG), one acceptance, bytes match. |
| RADIO-1 intermediate N=8 and N=16 | `scenarios.geometry` | Pass. 256 bytes is 8 frames and the body matches. 512 bytes is 16 frames and the body matches. |
| RADIO-1 N=32 exact and short | `scenarios.geometry` | Pass. 1024 bytes and 993 bytes, 32 frames, both bodies match. A second submit while the first is live is `DMP_BUSY` or `DMP_QUOTA_EXHAUSTED`. |
| RADIO-1 N>32 | `scenarios.geometry` | Pass as refusal. 1025 bytes is `DMP_LIMIT_EXHAUSTED` before any frame. The admitted ceiling is 32×32. |
| DIRECT-1 small service 2 | `scenarios.geometry` | Pass. 16-byte REQ, one frame, one acceptance. |
| DIRECT-1 N=16 exact/short | `scenarios.geometry` | Pass. 1024 bytes and 961 bytes, 16 frames of 64, both bodies match. `DMP_HS_APP_PLAIN_MAX` is 240. |
| Large REQ fixture | the 256/512/993/1024 bodies above | Pass on RADIO-1, including byte compare of 512 and 1024. |
| Large result fixture | `scenarios.gaps` `large-result` | Pass. 512-byte service-2 result, 16 frames, one result callback, bytes match. |
| S7 grants | — | Not run. Service 2 on the radio manifest has `freshness` true and `lease_ms` 12000. libdmp has no freshness token table and `dmp_endpoint` has no grant-token field. Adding one needs `include/dmp/endpoint.h`. The radio service-2 accepts in this package did not carry a token. That is not an S7 pass. |
| SAMPLE-1 regression | `scenarios.relay_sample` `sample1` | Pass on RADIO-1 service 1 (freshness false). One READ. The 17 result bytes match `sample1_read_rsp` for epoch 1, index 2, value 300. |
| S10 case 6 relay state | `scenarios.relay_sample` | Partial pass. An endpoint TELEM frame is refused by `dmp_mesh_relay_forward` and the cache stays empty. A frame sealed by the live association with origin-explicit CONTEXT and TTL 2 occupies one relay slot while endpoint `accepts` stays 0. A second forward inside cooldown is `DMP_BUSY`. The endpoint encoder still does not emit ROUTE or CONTEXT. `dmp_config` has no TTL. `dmp_reliability_on_rx` still rejects `DMP_OPT_ROUTE`. End-to-end radio delivery is open. |
| S10 case 11 | — | Pending for P23. |
| TEST-RADIO-RETRY-ALL loss | `scenarios.retry_all` | Pass. Dropped index 3, no FRAG_STATUS, the timeout resends 8 slices, one acceptance, bytes match. |
| TEST-RADIO-RETRY-ALL expiry | `scenarios.retry_all` | Pass. Unknown local outcome, late slice does not assemble, no further send. |
| §22.8 fragment conflict | `scenarios.r7` `r7-conflict` | Pass. Same SEQ, fresh PN, different slice 0 is `DMP_MALFORMED`. `accepts` and `assembled` stay 0. |
| §22.8 no partial dispatch | `scenarios.r6` before the last slices | Pass. `accepts` stays 0 while the mask is incomplete. |
| AES-GCM FRAG_STATUS | — | Out of this suite, as in P18. |
| Physical transport | — | Not claimed. |

## Defect fixes proven by a P19 test

1. `src/endpoint/endpoint.c` `take_fragment`. A completed ACK_REQ REQ was only an `ASSEMBLED` notice. R4.4 requires the reliable acceptance path. `scenarios.r6` now sees one REQUEST and an ACK. `ASSEMBLED` is still emitted so the existing endpoint fragment tests keep their byte notice. The workload executes on REQUEST only.
2. `src/reliability/reliability.c` `arm_saved_fragments`. A secured payload above 32 bytes that still fits one protected frame is no longer forced into slices. The endpoint path fragments only when the exact non-FRAG encode does not fit `encoded_mtu`. A 64-byte RADIO-1 service-2 REQ is one frame. The fixed 48/73-byte margin is gone: a size probe must return `DMP_OK` or `DMP_LIMIT_EXHAUSTED`.
3. `src/reliability/reliability.c` `begin_send`. A seal or encode failure after admission frees the sender. `scenarios.gaps` `seal-after-admit` is the failing case: cancel the attempt, poll returns `DMP_AUTHENTICATION_FAILURE`, `wire.n` stays 0, and a later poll does not emit a frame.
4. `src/reassembly/reassembly.c` `accept_existing`. A duplicate of an accepted index at the deadline returned `DMP_DUPLICATE` and could arm collection. The deadline is checked first. `scenarios.gaps` `duplicate-after-deadline` reseals index 0 with a fresh PN and expects `DMP_DEADLINE_EXPIRED` with `collection_armed` still 0.
5. `src/reassembly/reassembly.c` `accept_existing`. A duplicate probe of an incomplete transfer did not arm the next collection, so a lost FRAG_STATUS produced no later status. `scenarios.r6` `r6-status-loss` is the failing case. An armed timer is not moved. A completed transfer is not re-armed.

## Added rows

| Item | Test | Outcome |
|---|---|---|
| R4.2 later slice does not move an armed due time | `scenarios.gaps` `duplicate-after-deadline` | Pass. Slice 1 at `now+10` leaves `collection_due` at `now+2072`. |
| R6 N=32 missing index 31 | `scenarios.gaps` `mask-n32-index31` | Pass. Mask `0x80000000`, bytes `00 00 00 80`. |
| R6 N=2 missing index 0 | `scenarios.async_radio` `async-radio-n2-index0-repair` | Pass on TEST-RADIO-N2: after index 0 is lost and index 1 arrives, mask `0x01` requests only index 0; completion accepts the exact 64-byte body once. |
| Replay / old PN FRAG_STATUS | `scenarios.gaps` `status-wrong-association`; `scenarios.r6` replayed status | Pass. The second delivery is `DMP_AUTHENTICATION_FAILURE` and queues nothing further. |
| Feedback silence for a wholly unheard transfer | `scenarios.gaps` `feedback-silence` | Pass. Eight dropped slices, receiver poll emits no FRAG_STATUS. |
| §22.8 out-of-order completion | `scenarios.gaps` `out-of-order` | Pass. Order 7,0,3,1,2,4,5,6. One acceptance, body matches. |
| §22.8 accepted duplicate, different payload | `scenarios.gaps` `duplicate-payload` | Pass. After acceptance, a fresh-PN slice 0 with different bytes does not raise `accepts` and the stored body is unchanged. |
| §18.2/§22.8 deadline before transmission | `scenarios.gaps` `deadline-before-tx` | Pass. One `DMP_ENDPOINT_LOCAL_UNSENT` carries the request key and an empty body. `unknowns` stays 0. No frame is queued and the sender is freed. |
| §18.2/§22.8 deadline while the attempt is not active | `scenarios.gaps` `deadline-before-activation` | Pass. A poll before the queue deadline keeps the admitted REQ and sends nothing (`DMP_BUSY` until activation). At the deadline the same request is one `LOCAL_UNSENT`, `unknowns` stays 0, and no frame was queued. |
| §22.8 deadline after a possibly transmitted fragment | `scenarios.r7` `r7-expiry` | Pass. `unknowns == 1`, `local_unsents == 0`, and a later poll adds no frame. |
| §22.8 quota exhaustion mid-transfer | `scenarios.r7` `r7-tombstone-pressure` | Pass. The 17th slice is `DMP_QUOTA_EXHAUSTED`. |
| §22.8 schedule gap inside the collection timer | `scenarios.gaps` due-time check | Pass for the admitted sum `burst_span+forward_delay+feedback_guard` (2048+20+4). A separate airtime gap injected into a live transfer was not added. |
| R1 DATA/EVENT with ACK_REQ | — | Open. Unfragmented DATA/EVENT is `DMP_UNSUPPORTED` in `take_frame`. There is no reliable DATA submit. Not one of the four owner decisions. |
| §22.8 TTL=0 / TTL=1 | — | Open. Endpoint does not emit ROUTE or TTL. Owner decision. |
| §22.8 CRC after a TTL change | — | Open. Same ROUTE/TTL decision. The relay recomputes CRC only when INTEGRITY is present; this path is not an endpoint-originated frame. |
| §22.8 narrower egress, refused transparent refragmentation, missing egress context | — | Open. Needs endpoint ROUTE/CONTEXT. `dmp_reliability_on_rx` still rejects `DMP_OPT_ROUTE`. |
| §22.8 immediate RSP, lost RSP, lost result ACK, duplicate REQ during processing and after result release, for a fragmented exchange | — | Open for the fragmented form. SAMPLE-1 covers one immediate 17-byte result. Lost acceptance ACK is `lost-ack`. The fragmented result/ACK/duplicate-REQ set was not isolated. |
| §22.8 result/status race and delayed status | `scenarios.async_radio` `async-radio-delayed-status` | Delayed status passes while one local TX completion is pending. The separate fragmented result/status overlap remains open. |
| S7 freshness for service 2 | — | Open. Needs a public header. Owner decision. |

## Review findings, 2026-10-05

1. Pre-activation REQ. Verified. `require_attempt` returns `DMP_BUSY` while the attempt is alive and not active, and `begin_send` keeps the sender. A terminal or cancelled attempt still frees the slot and returns `DMP_AUTHENTICATION_FAILURE` (`scenarios.gaps` `seal-after-admit`). `dmp_endpoint_poll` stays `DMP_OK` because `send_ready` does not surface `DMP_BUSY`. `endpoint.protected_activation` expects that `DMP_OK`, sends no frame before activation, and delivers the same request after activation.
2. FRAG margin. Fixed. The endpoint measures the exact non-FRAG header, payload, and 16-byte tag against `encoded_mtu`. `DMP_HS_APP_PLAIN_MAX` 240 stays the seal-buffer ceiling. The fixed 48/73-byte fallback is removed. A NULL size probe must return `DMP_OK` or `DMP_LIMIT_EXHAUSTED`; any other status frees the sender and sends nothing. `dmp_core_encode` itself cannot answer that probe. `scenarios.geometry` checks the largest service-2 body that is one frame and the next byte that fragments, for RADIO-1 and DIRECT-1.
3. Local unsent. Fixed. `DMP_ENDPOINT_LOCAL_UNSENT = 6` is the public event for a reliable REQ that ended before any byte of any attempt could have reached the peer. Empty body, own request key, no remote-cancellation claim. `DMP_ENDPOINT_UNKNOWN` stays possibly-sent. `deadline-before-tx` expects one `LOCAL_UNSENT` and `unknowns == 0`. `deadline-before-activation` is the same outcome when the queue deadline passes while the attempt is still not active. `r7-expiry` keeps `unknowns == 1` and `local_unsents == 0`.
4. Replay bitmap. Verified. `DMP_REPLAY_WINDOW_MAX` defaults to 1024 and can be overridden at compile time. The compilable ceiling is a power of two in [1024, 65536] because the default W of 1024 must fit. A configured W is a power of two in [64, ceiling]. The bitmap is `ceiling/8`. `W=0` still selects 1024. `W=64` and `W=ceiling` are accepted. `W=2*ceiling` is `DMP_HS_INVALID` when the ceiling is below 65536. `failed_aead_limit` is unchanged: zero still selects the hard ceiling 65536. Manifests were not edited.

Measured with gcc 15.2.0, before the ceiling change and after:

| Object | Before | After |
|---|---:|---:|
| `sizeof(dmp_replay_window)` | 8208 | 144 |
| one `hs_attempt` | 9832 | 1768 |
| `sizeof(dmp_hs)` | 39992 | 7736 |

## Commands

`cmake --build build/host` exit 0. `ctest --test-dir build/host --output-on-failure` 61/61 passed, 0 failed, including `harness.subprocess`. This count is from the run after the fixes above. `node dev/dmp_verify_security_vectors.cjs` exit 0 (4 fixtures, 64 packets, 44 mutations). `node dev/dmp_verify_recovery_vectors.cjs` exit 0 (26 cases, 8 mutations, cipher 1 only). gcc 15.2.0, cmake 3.28.1, Node v24.11.1. `build/host` was not deleted.
