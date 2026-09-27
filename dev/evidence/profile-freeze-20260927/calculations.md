# Coordinator cross-check of independently stated expectations

These calculations were checked against the manifest contract and actual six
instances, not inferred from a passing validator exit. The Luna test worker
authored `tests/profiles/deployment_expected.json`; the coordinator inspected the
test source, corrected its return-MTU test name (118 rejects the 119-byte largest
application frame, not the smaller control frame), and reran CTest successfully.
The coordinator also found that historical input documents mix CRLF and LF:
portable resource-source hash assertions now explicitly normalize only CRLF to
LF. Their original byte hashes are preserved in `resource-input-raw.json`.
Manifest digest assertions remain exact-byte and unchanged. The affected profile
suite is rerun after this portability correction; historical evidence is unedited.

## Frame sizes

The maximum compact protected base is 18 bytes. Radio adds ROUTE=3 and
CONTEXT=11, making 32. Fragment metadata is 4 bytes (index 1, chunk 1, length 2).
Service 2 has a 3-byte service extension. Including conservative reply/status
extensions and the tag:

- Direct application: `18+7+7+3+4+64+16 = 119`.
- Radio fresh application: `32+7+7+3+18+4+32+16 = 119`.
- Direct/radio status: `(18 or 32)+7+3+4+16 = 48 or 62`.
- Bootstrap: `5+11+3+3+60+4 = 86` in either binding.
- Stream R capacity: `256+4+floor((256+4)/254)+2 = 263`; packet is 256.

Application fragment counts are 1024/64=16 and 1024/32=32; bootstrap is
ceil(120/60)=2. The admitted worst Stream R partial candidate timer is
`1+20+5 = 26 ms` (future P06 runtime check, not exercised by these validator tests).

## Timing and wire accounting

Radio selective floor: `2*20+2048+4+110+20 = 2222 ms`; ordinary receipt floor:
`20+110+20 = 150 ms`. Tests isolate rejection at 2221 and acceptance at 2222.
Radio freshness: `100+64+10752+20 = 10936 ms`; 10935 fails and 10936 passes.
The token-record value remains sufficient in both cases, so it does not mask the
lease comparison. Direct reports the unused zero-grant expression 5716 ms;
direct freshness remains disabled.

Transfer frame reserves are direct `3*(16+2)+3 = 57`, radio selective
`3*(32+2)+3+3 = 108`, and radio retry-all `3*(32+2)+3 = 105`.
Common airtime/resource ceilings remain equal across the radio comparison.

Bootstrap flight span is 2*64=128 ms. NNpsk0 establishment reserves
`(2*2+1)*2+2*2 = 14` frames and `5*1856+2*512+500+1000 = 11804 ms`.
XX reserves `(3*2+1+2)*2+2*2 = 22` frames and
`7*1856+2*512+500+1000 = 15516 ms`. Multiply by 263 for direct wire reserves
(3682/5786 bytes), or 256 for packet (3584/5632 bytes). These include the XX
cached-flight-3 allowance; all fit the common 20000 ms / 8192 byte attempt.

## Resource totals and comparison

Endpoint fixed/common charges sum to 69760 bytes before result/history/
correlation pools. Direct adds `4*1536+8*128+4*128 = 7680` for 77440 bytes;
radio adds `6*1536+12*128+6*128 = 11520` for 81280 bytes. The endpoint limit
is 131072. The aggregate-negative test sets 81279; the independent sender
buffer-negative test sets 1023 rather than the required 1024 bytes.

Relay charges: `192*96+4*512+4*512+4096+11*256 = 29440`, below 65536.
The maximum required XX selective cache count is 186, leaving six records.
The README distinguishes actual historical provider backing/metadata/link
evidence from all unmeasured module reserves and excludes physical-fit claims.

Recursive radio comparison permits exactly seven differing paths: three
profile identity fields, two service recovery enums and two probe/status caps.
Everything else, including NN/XX-specific credentials, MTU, both directions,
relay policy, payload ceilings, freshness, timing and resources, must match for
the corresponding security mode. Rebranding retry-all as RADIO-1 is rejected.

## Review boundary

The mandatory early independent Astra contract/vector review is recorded in
`early-review.md`. An additional final reviewer follow-up and same-model fresh
spawn both returned `agent thread limit reached`; no fallback model or separate
user task was launched. The coordinator owns final deployment/test/ledger
acceptance. Do not describe this additional final pass as independently run.
