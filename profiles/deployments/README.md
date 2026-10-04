# Frozen host development deployments

P03 instances of [test manifest contract 2](../../docs/DMP_Test_Manifest_Contract.md).
These are complete configuration inputs for the future real library and its
independent peer, not endpoint implementations or physical bindings. The six JSON
manifests are authoritative files; changes require review and an explicit update
of `digests.json`. Hash original bytes, without parsing/reserializing them.
Deployment instance owner is `DMP-test`, name is the manifest basename without
`.json`, and instance revision is 1. This instance name is distinct from the
reference-family identity inside the file. `digests.json` pins the exact
configuration for each name; SEC-1 binds those configuration bytes, not a filename.

| Files (suffix `-nnpsk0.json` or `-xx.json`) | Identity | Path | Recovery |
|---|---|---|---|
| `direct` | DMP-reference/DIRECT-1/4 | SIM-STREAM-R/1, nodes 10/20 | retry-all |
| `radio` | DMP-reference/RADIO-1/4 | SIM-PACKET/1, 10/30/40/20 | selective-32 |
| `test-radio-retry-all` | DMP-test/TEST-RADIO-RETRY-ALL/1 | same packet path | retry-all |

Each security mode has separate exact manifest bytes and PROFILE_HASH. Cipher 1
is ChaChaPoly. Credentials are separately provisioned; these files contain no
PSK, private key or implicit trust decision. NNpsk0 uses a pairwise PSK; XX needs
authenticated OOB verification. One pending, one active and one draining
association are admitted per pair, with one crypto slot. Capacity exhaustion
refuses new work; it never evicts live work or protected history.

SAMPLE-1/2 on default service 1 is unchanged. Service 2 is the contract's opaque,
idempotent test workload, with up to 1024 request/result bytes. Only radio enables
its S7 freshness requirement (12-second lease); SAMPLE-1 has no freshness token.
Groups, AESGCM, dynamic routes, lower segmentation and physical/mixed bindings
are outside these instances. Mixed-path support remains P22 before P23.

## Comparable simulated schedules

Both radio families use exactly the same identities/ACLs, security policy,
payload ceilings, 256-byte core/packet MTU, 32-byte fragment chunk, two relays,
32-fragment ceiling, freshness, buffers, memory/flash and deadline bounds. Only
the profile identity, service recovery enum, and selective probe/status counters
differ. No runtime switch or rebranding a RADIO-1 association is permitted.

At 64 ms per superframe, each direction reserves a complete forward path and two
return control paths. The return window is 42 ms; each path has a 20 ms delivery
bound plus 1 ms origin transmission. This deliberately conservative model
includes authentication in delivery delay. The injector must honor the per-hop
arrival/duplicate bounds, and admission must reject reservations that cannot fit.
It is not a prediction of LoRa, ESP-NOW, BLE or UART performance.

| Parameter | Direct | Both radio families |
|---|---:|---:|
| Message / chunk bytes | 1024 / 64 | 1024 / 32 |
| Maximum application fragments | 16 | 32 |
| Maximum bootstrap fragments (60-byte chunks) | 2 | 2 |
| Core MTU / encoded capacity bytes | 256 / 263 | 256 / 256 |
| Burst span / response wait ms | 1024 / 1280 | 2048 / 2304 |
| Three burst starts ms | 0, 2304, 4608 | 0, 4352, 8704 |
| Absolute send horizon ms | 5632 | 10752 |
| Result deadline / correlation ms | 12000 / 12288 | 22000 / 23040 |

Radio selective response floor is `2*20+2048+4+110+20 = 2222 ms`.
Retry-all retains the same 2304 ms wait despite its lower required floor.
Freshness reaches final new-command admission at most
`100+64+10752+20 = 10936 ms` after grant issue, within 12000 ms.
These allowances reserve worst-case full repair bursts, not optimistic masks.

Both modes use the same conservative 20-second attempt / 41-second two-attempt
episode, 1856 ms cached-flight retry and 512 ms confirmation slot. NNpsk0 reserves
14 establishment frames and 11804 ms; XX reserves 22 and 15516 ms, including
cached flight-3 retries while awaiting READY. Separate episode/work/wire/ingress
caps remain mandatory. Expiry and reservation rejection still permit bounded
failure; these parameters do not promise delivery under arbitrary faults.

## Resource decisions and evidence

All numbers below are **portable host development design reserves**. They are
not the small/medium/large target qualification envelopes in the historical
provider experiment manifest. The separate 128 KiB endpoint / 64 KiB relay
ceilings let implementation proceed with explicit accounting; choosing them
does not raise or pass any MCU target budget. Smaller budgets, including the
historical 64 KiB aggregate envelope, need actual library measurement and an
explicit profile revision rather than silently dropping charges.

| Per-device template | RAM reserved / limit | Linked flash reserved / limit |
|---|---:|---:|
| Direct endpoint | 78720 / 131072 | 262144 / 524288 |
| Radio endpoint (either recovery) | 83584 / 131072 | 262144 / 524288 |
| Each relay | 29441 / 65536 | 65536 / 131072 |

Endpoint reserves apply to each endpoint separately; relay reserves to each of
the two relays. They are not pooled across devices. The `RAM` region promises no
specific address, DMA capability, external memory or MCU placement. Flash is the
attributable library plus selected provider/backend; SDK/application firmware is
outside this development envelope and must be accounted separately at P01C.

Provider inputs are pinned by path/hash in `resource-inputs.json`:

Those auxiliary source-text hashes normalize CRLF to LF so Git checkout newline
policy cannot break the evidence link on another host. No other transformation
is allowed. Original checkout byte hashes remain in P03 evidence. This rule
does **not** apply to manifests: PROFILE_HASH always hashes their original bytes.

- MEM-02 reports host NN constructor 1136 bytes / XX 1488 charged bytes, a 3424
  byte two-endpoint live peak, and **8192 backing + 2112 allocator metadata**.
  Live charged bytes must not replace the physical reservation.
- MEM-03 reports active/draining/pending owner lifetimes (single endpoint host
  peaks 1872 NN / 2224 XX bytes), using **32768 backing + 2112 metadata**;
  owner records, scratch, stacks and backend globals are outside that number.
- MCU-01 attributes **38856 flash bytes and 143 static DIRAM bytes** to the
  selected Noise/backend link. This is one selected target build, not an ABI
  independent upper bound for the whole endpoint.
- Existing MCU-02 physical evidence used a **12288-byte task stack**, with
  observed consumption 2192 S3 / 1712 C3 bytes and a 32768-byte arena. It does
  not qualify future DMP stacks or non-Espressif targets.

The endpoint `provider_retained` charge is 3 x 12288 = 36864 bytes: a combined
reservation covering the 32768 backing, 2112 host allocator metadata and 143
observed backend globals, with 1841 bytes of margin. Three charge slots are
accounting units for pending/active/draining, **not** a promised physical pool
layout or measured per-owner quota. P01B must explicitly partition the actual
backing/metadata/globals and prove simultaneous ownership fits. A separate 4096
bytes covers crypto scratch; 3 x 512 association bytes cover future owner
records, replay/counter and lifecycle metadata. Stack reserve remains 12288.
The 262144-byte flash reserve includes the observed 38856-byte provider
contribution, leaving 223288 bytes for unmeasured library/backend growth.

All non-provider module sizes are unmeasured implementation reservations:

- 1536-byte sender/assembly/result/application-queue slots include a complete
  1024-byte message and 512 bytes for metadata; counts are simultaneous, with
  extra result/correlation/history slots for two radio freshness grants.
  Endpoint assembly admission validators enforce the assembly slot's full
  message plus 512-byte metadata reserve.
- Bootstrap reserves 512 bytes; control and adapter slots reserve 512 bytes
  each, including encoded frame storage and future ownership metadata.
- History/correlation records reserve 128 bytes each, freshness records 64.
  Admission refuses new work when protected retained records fill these pools.
- Each endpoint reserves 16 expiry-tombstone records of 48 bytes per peer;
  exhausted pools refuse new fragmented message identities until the context
  is retired. Tombstones contain no payload or application data.
- Relay cache is 192 x 96 bytes, exceeding the common worst XX selective
  requirement `4*(32+2)+3+3+22*2 = 186` records. Each relay also reserves four
  512-byte control and adapter slots, 4096 stack bytes and 256 bytes for each
  remaining module. The one-byte assembly-tombstone charge is an explicit
  unused relay reserve; relay charges do not claim end-to-end reassembly state
  or traffic keys.

No reserve is a measurement or a guarantee of a sufficient C layout. P04/P08/
P12/P15/P19 must compare actual layouts, queues, retained owners and linked size
against these numbers; overruns require explicit re-budgeting and new hashes.
P01C separately measures target maps, memory regions, scratch, stack, concurrency,
entropy and the whole integrated image. No heap fallback or hidden pool sharing.

## Validation and traceability

```text
python tools/validate_profile.py profiles/deployments/radio-xx.json
python -m unittest discover -s tests/profiles -p "test_*.py" -v
```

Use `--expect-sha256` with the corresponding `digests.json` value when checking
provisioning agreement. The [case ledger](../../dev/DMP_Normative_Cases.md)
assigns future implementation tests; configuration validation does not pass
those endpoint cases. [P03 evidence](../../dev/evidence/profile-freeze-20260927/README.md)
records acceptance and its limits.
