# DMP — Device Messaging Protocol

DMP is a compact, transport-independent device messaging protocol under development. It carries opaque payloads over explicitly specified bindings, with optional routing, reliability, fragmentation and pairwise end-to-end encryption.

**Current contract:** manifest format 1.0, document revision 10, SEC-1 profile revision 5, BOOT_VERSION 2, SELECTIVE-32 recovery revision 1. Wire major version remains 2; peers must agree on the exact profile and manifest bytes. The portable C11 `libdmp` now includes bounded endpoint, peer-owned SEC-1 association lifecycle, reliability, reassembly, Stream L/R framing, transparent relay, profile admission, and an application-side SAMPLE-1 epoch owner. The latest RBO host gate passed 134/134 native CTests, excluding the Cortex-M ABI probe and seven dependent `memory.*.layout` checks; those ARM cases remain deferred. ESP-IDF 6.1 compile/link probes passed for ESP32-S3 and ESP32-C3. Target runtime and physical qualification remain open. This is host/simulation progress, not a product release claim. DIRECT-1 uses a 256-byte decoded Core frame ceiling and a 263-byte encoded Stream R ceiling.

The public API is under [include/dmp/](include/dmp/); implementation layers live in `src/`, including the payload-agnostic endpoint/security core and the separate [SAMPLE-1 application component](src/application/). Tests link the same C sources. Host CTest and the independent Python peer cover scoped protocol, security lifecycle, profile, and interop behavior. See the [multi-peer continuation contract](dev/DMP_Multi_Peer_Contract_2026-10-13.md) and the [P25 host/simulation report](dev/DMP_P25_Host_Simulation_Report.md) for current acceptance boundaries.

```text
cmake -S . -B build/host -DDMP_BUILD_TESTS=ON
cmake --build build/host
ctest --test-dir build/host --output-on-failure
```

Tests require Python 3.10+ and Node; C++ header tests run when a C++ compiler is
available. Use `-DDMP_BUILD_TESTS=OFF` for the C-only archive without those tools.
Use `-DDMP_FUZZ=ON` with Clang's GNU-style driver for the bounded ASan/UBSan and
libFuzzer checks described in [the fuzz workflow](tests/fuzz/README.md).

## Introduction and motivation

DMP grew out of DTrack, an embedded project where devices and clients exchange live telemetry, configuration, commands and results over different communication channels. DTrack separates logical ports from their transport and protocol: the same application may need a wired device connection, a Bluetooth client and a network connection. Similar needs in other projects motivated extracting DMP into a reusable device messaging protocol, including deployments with small raw-radio packets and expensive airtime, such as LoRa links.

The early TLV approach kept application messages compact, but evolving payloads and communication requirements called for more flexibility. MessagePack became a practical basis for DTrack's structured messages. As fragmentation, delivery guarantees and optional encryption became necessary, the design grew beyond payload serialization. In this specification, MessagePack is one possible payload encoding; an application can instead define another encoding or carry opaque binary data without changing the core messaging rules.

The problem DMP aims to solve is keeping one consistent message and delivery model as the connection changes: from a direct wire to a constrained wireless link, or to a path through transparent relays. Building a separate application protocol for each path would repeat framing, correlation, retry, fragmentation and security work. DMP puts those rules into a common core, with explicitly configured bindings and deployment profiles for the differences that matter.

The current design brings together:

- **Transport and payload independence.** Stream and packet bindings define boundaries, MTU and buffer ownership; applications define their own services and payload schemas. The core requires neither IP nor a central broker.
- **Different delivery needs.** Live telemetry can discard obsolete samples, while requests and results use bounded reliable exchange. Message receipt and application completion have distinct meanings.
- **Recovery matched to transmission cost.** Simple links can retry a whole fragmented message. The optional SELECTIVE-32 mode requests missing fragments on expensive links, within fixed memory, timing and feedback limits. Recovery policy is agreed in the profile, not guessed or switched after a timeout.
- **Security across relays.** Optional SEC-1 defines pairwise end-to-end protection with pre-shared keys or authenticated pairing. A transparent relay forwards the protected payload without receiving endpoint traffic keys. The DIRECT-1 and RADIO-1 reference families require SEC-1.
- **Explicit resource limits.** Profiles declare memory, frame sizes, queues, retries and lifetimes, so constrained implementations can provision bounded state and preserve capacity for protocol control.

Existing protocols cover many of these needs. [MQTT 5.0](https://docs.oasis-open.org/mqtt/mqtt/v5.0/os/mqtt-v5.0-os.html) defines client/server publish-subscribe messaging over an ordered, lossless connection. [CoAP](https://www.rfc-editor.org/rfc/rfc7252.html) provides a resource-oriented request/response model for constrained systems, and [OSCORE](https://www.rfc-editor.org/rfc/rfc8613.html) adds end-to-end protection through proxies. Their capabilities overlap with DMP; encryption, compact messages and reliability are not unique DMP features. DMP explores a particular combination for direct device messaging across stream and raw-packet links, without requiring a broker, a resource/URI model or a particular payload codec. The [design tradeoffs](docs/DMP_v2_Design_Tradeoffs.md) document the approaches borrowed from existing work.

Compactness, low memory use and reduced airtime are design goals. Whether this combination is simpler or more efficient than an established stack remains to be demonstrated by implementations, independent interoperability tests and equivalent-workload measurements. DTrack's earlier DMP implementation is the project's origin, not an implementation of this standalone revision. The “v2” name marks an evolution during development, not a claim of a previous stable release.

## Read first

| Document | Purpose |
|---|---|
| [Protocol specification](docs/DMP_v2_Device_Messaging_Protocol_Specification.md) | Core wire format, identity, delivery, routing, fragmentation and API boundaries |
| [SEC-1 security](docs/DMP_v2_Security_Profile.md) | PSK/pairing, AEAD, replay, authorization, freshness and key lifecycle |
| [SELECTIVE-32](docs/DMP_v2_Selective_Recovery.md) | Authenticated missing-fragment feedback and bounded recovery on expensive links |
| [Deployment profiles](docs/DMP_v2_Deployment_Profiles.md) | DIRECT-1 and RADIO-1 choices, ceilings and mandatory site-specific parameters |
| [Reference application](docs/DMP_v2_Reference_Application.md) | Exact small SAMPLE-1 telemetry/read/status schema |
| [Test manifest format](docs/DMP_Test_Manifest_Contract.md) | Single format 1.0 configuration bytes, schema, offline constraints and independent-peer input boundary |
| [Design tradeoffs](docs/DMP_v2_Design_Tradeoffs.md) | Rationale, prior art and measurement boundaries |
| [Implementation and tooling plan](dev/DMP_Implementation_Plan.md) | Portable core, profile validator, simulator, decoder, benchmarks and release gates |
| [Agent workflow](AGENTS.md) | Coordinator, bounded worker assignments, ownership and review rules |
| [Implementation work packages](dev/DMP_Work_Packages.md) | Dependency board, package acceptance and restartable execution |
| [Noise decision record](dev/DMP_Noise_ADR.md) and [source survey](dev/DMP_Noise_Provider_Survey.md) | Abort-first, controlled-core research, separate backend assessment and pending provider experiments |

`docs/` is the normative source where a document says so. `dev/` contains planning, fixture helpers and historical reviews. [Revision 7 review](dev/dmp-revision-7-review.md) and [comparative critique](dev/dmp-comparative-critique.md) describe their dated snapshots, not a review of the current revision. [Revision 8 review](dev/dmp-revision-8-review.md) records the historical extraction review and its limits.

## Existing fixture checks

Run from this repository root with Node.js:

```text
node dev/dmp_verify_security_vectors.cjs
```

To regenerate [public SEC-1 fixtures](docs/DMP_v2_Security_Test_Vectors.json), use Python with `cryptography` and the upstream Cacophony vector file identified by the source URL and SHA-256 in that JSON:

```text
python dev/dmp_generate_security_vectors.py --upstream <verified-cacophony.txt>
node dev/dmp_verify_security_vectors.cjs
```

The upstream file is an external input, not bundled here. Its recorded SHA-256 is `3bde7c09a6f349ee11c825c50fcc02649f8f02a47c857a459206b357f9386cae`. Review regenerated output and provenance before replacing vectors. Public deterministic keys are test-only. The generator and Node verifier validate public fixtures; they do not replace the linked endpoint, recovery or interoperability tests, and they do not prove physical binding timing or production security.

The implementation has progressed beyond the original codec scaffold. P00 and P02-P11 are accepted for their recorded scopes; P13-P20, P21 and P22-P24 have recorded host/simulation acceptance, with P21 retaining its documented historical provenance limitation. The approved P12 continuation code has passed its focused and full non-ARM host gates, including four-peer admission/lifecycle, the two-attempt SAMPLE-1 profile, rejection of a different authenticated sender, handshake transport composition and the application-side epoch owner. P12 remains open while the six partial SAMPLE-1 ledger rows are reconciled and production target storage/lifecycle adapters remain unqualified. P01 remains an umbrella gate for provider evidence and final target qualification; P25 remains pending. The owner scheduled hardware qualification at the end for ESP32-S3 and ESP32-C3; non-Espressif physical qualification remains explicitly deferred. See the [work package board](dev/DMP_Work_Packages.md), [owner decisions](dev/DMP_Continuation_Decisions_2026-10-13.md), and [P25 report](dev/DMP_P25_Host_Simulation_Report.md).

## Offline profile validation

Python 3.10 or later, standard library only:

```text
python tools/validate_profile.py profiles/deployments/direct-nnpsk0.json
python tools/validate_profile.py profiles/deployments/radio-xx.json
python -m unittest discover -s tests/profiles -p "test_*.py" -v
```

The CLI returns the SHA256 of the exact original manifest bytes and conservative
derived bounds. `--expect-sha256 HEX` additionally checks provisioning agreement.
The [schema](profiles/schema/manifest-v1.schema.json) and
[written contract](docs/DMP_Test_Manifest_Contract.md) define the selected
format 1.0. Corpus files are not physical/product profiles.
[P03 deployment instances](profiles/deployments/README.md) are frozen, including a
separately identified radio retry-all comparison. P09 implements startup
enforcement in libdmp. The [137-case ledger](dev/DMP_Normative_Cases.md) now
records concrete test references and separate whole-row, primary, peer, profile
and interop evidence: 74 passed, 62 partial and 1 not run for whole-row status.
A 2026-10-14 source audit checked all 510 linked file/symbol references with no
missing entries; this verifies the crosswalk, not each row's result. Those counts
do not include physical S3/C3 qualification or convert P21 provenance limitations
into independent-proof claims.
See [P02 evidence](dev/evidence/profile-validator-20260927/README.md) for actual
checks and limits, and [P03 evidence](dev/evidence/profile-freeze-20260927/README.md)
for the six profiles, resource rationale and early independent review. Simulator
and benchmark CLIs remain planned.

## License

See [LICENSE](LICENSE). The existing repository license is preserved; external dependencies and upstream fixtures retain their own provenance and require review before distribution.
