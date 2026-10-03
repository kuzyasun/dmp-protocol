# DMP — Device Messaging Protocol

DMP is a compact, transport-independent device messaging protocol under development. It carries opaque payloads over explicitly specified bindings, with optional routing, reliability, fragmentation and pairwise end-to-end encryption.

**Current contract:** document revision 10, SEC-1 profile revision 5, BOOT_VERSION 2, SELECTIVE-32 recovery revision 1. Wire major version remains 2; peers must agree on exact profile/manifests. The portable C11 `libdmp` implements the foundation, structural codec, CRC32C and Stream L/R framing, alongside offline manifest validation and provider experiments. It is **not yet an endpoint library**.

The library sources are [base.c](src/core/base.c), [codec.c](src/core/codec.c),
[crc32c.c](src/integrity/crc32c.c) and [stream.c](src/stream/stream.c), with
[public headers](include/dmp/core.h) and linked tests under `tests/core/` and
`tests/stream/`. P04 supplies checked views/time/generations; P05/P06 implement
canonical headers/extensions, structural role checks and bounded stream codecs.
Tests exercise these same library objects, including 64 published packet bytes;
parsing does not authenticate ciphertext or admit messages. See
[interface scope](dev/DMP_Core_Interfaces.md) and
[P05/P06 evidence](dev/evidence/codec-framing-20260927/README.md).

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
| [Test manifest contract](docs/DMP_Test_Manifest_Contract.md) | Versioned configuration bytes, schema, offline constraints and independent-peer input boundary |
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

The upstream file is an external input, not bundled here. Its recorded SHA-256 is `3bde7c09a6f349ee11c825c50fcc02649f8f02a47c857a459206b357f9386cae`. Review regenerated output and provenance before replacing vectors. Public deterministic keys are test-only. The generator is not production cryptographic code, and the verifier is a fixture parser, not the future library parser. Existing checks do not implement the SELECTIVE-32 state machine or prove endpoint interoperability, BLE/radio timing or production security.

P00 preparation is accepted: the host scaffold, declared MCU configurations and finite experimental resource envelopes are recorded. P01 has accepted bounded PN-01 receive, DH-01 strict X25519 and RNG-01 post-initialization entropy-failure host checks using the [fork submodule and opt-in probes](tests/provider/README.md). [INIT-01](dev/evidence/noise-init-20260927/README.md) fixes returned initialization errors and reproduces the original backend's abort on OS entropy failure. [BINIT-01](dev/evidence/noise-backend-init-20260927/README.md) accepts a separate checked backend's serialized host startup: entropy failures return, partial canary bytes are erased and an explicit later call can retry. [MEM-01](dev/evidence/noise-memory-20260927/README.md) fixes a dangling output on partial constructor failure and verifies allocation errors and owned-heap cleanup in ordinary and optimized host builds. [MEM-02](dev/evidence/noise-arena-20260927/README.md) accepts the host bounded-storage port and selected compile-only layouts after independent review. [MCU-01](dev/evidence/noise-mcu-20260927/README.md) accepts complete selected Cortex-M4 archives and an isolated ESP-IDF test-image link, with map/symbol evidence. [MEM-03](dev/evidence/noise-owners-20260927/README.md) accepts serialized multi-owner host quota/OOM/reuse checks after independent review. [MCU-02](dev/evidence/noise-mcu-console-20260927/physical/README.md), [MCU-03](dev/evidence/noise-mcu-pressure-20260927/README.md) and [MCU-04](dev/evidence/noise-mcu-parallel-20260927/README.md) accept bounded physical S3/C3 provider operation, heap/stack/timing, quota pressure and two independent concurrent workers. Entropy quality, non-Espressif runtime, Cortex board linking, complete secret-copy cleanup and aggregate resource gates remain open. The owner-approved [implementation transition](dev/evidence/implementation-transition-20260927/README.md) now assigns these checks to actual library work: P01A development feasibility, P01B provider adapter, P13/P15 SEC-1 behavior and P01C target qualification. P01 remains open; P02 is accepted as an offline validator and P03 has accepted six development manifests and the normative case ledger. P04-P06 implement the portable archive, structural codec and framing; their tests link the library sources. P07 supplies the next deterministic harness; P01B will connect the provider to the library. The unvalidated BOUNDARY-01 draft remains excluded from builds. No endpoint or production crypto provider is accepted. The offline profile validator now exists; simulator and benchmark commands remain proposed interfaces. No DTrack firmware, web UI or mobile client is moved here.

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
two-endpoint simulation scope. Corpus files are not physical/product profiles.
[P03 deployment instances](profiles/deployments/README.md) are frozen, including a
separately identified radio retry-all comparison. P09 implements startup
enforcement in libdmp; the [137-case ledger](dev/DMP_Normative_Cases.md) tracks
future implementation checks, all initially not run.
See [P02 evidence](dev/evidence/profile-validator-20260927/README.md) for actual
checks and limits, and [P03 evidence](dev/evidence/profile-freeze-20260927/README.md)
for the six profiles, resource rationale and early independent review. Simulator
and benchmark CLIs remain planned.

## License

See [LICENSE](LICENSE). The existing repository license is preserved; external dependencies and upstream fixtures retain their own provenance and require review before distribution.
