# ESP-NOW DMP Qualification Application

Hardware-only qualification target and host orchestration tools for testing the
authenticated DMP endpoint over ESP-NOW on ESP32-S3 and ESP32-C3 microcontrollers.

## 1. Overview and Architecture

This application tests the production DMP endpoint and cryptographic transport on actual
silicon, exercising:
- Real production `dmp_endpoint` state machine (`src/endpoint/`).
- Real production SEC-1 Noise `dmp_hs` and `dmp_hs_tx` transport (`src/security/`).
- Real production SAMPLE-1 NVS epoch storage adapter (`src/application/sample1_epoch_anchor_nvs.c`).
- Pure packet transport over native ESP-NOW on ESP-IDF v6.1.
- Controllable roles via line-oriented JSON serial commands (`ROLE controller` vs `ROLE peer`).

> [!CAUTION]
> **Test-Only Credentials**: The pre-shared key (PSK) and profile hashes compiled into
> this qualification target are fixed and public. They are strictly for automated test
> validation and MUST NOT be used in production firmware.

## 2. Partition Layout (4 MiB Flash)

The partition table (`partitions.csv`) is calibrated to fit both ESP32-S3 and ESP32-C3
boards with standard 4 MiB flash chips:

| Partition | Type | SubType | Offset | Size | Purpose |
|:---|:---|:---|:---|:---|:---|
| `nvs` | data | nvs | `0x9000` | 24 KiB | WiFi calibration & test NVS epoch store |
| `phy_init` | data | phy | `0xf000` | 4 KiB | Radio PHY initialization data |
| `factory` | app | factory | `0x10000` | 3008 KiB | DMP qualification application firmware |
| `coredump` | data | coredump | `0x300000` | 1024 KiB | Post-mortem ELF coredump partition |

Total partition span: `0x400000` (4,194,304 bytes = 4 MiB).

## 3. Protocol MTU Boundaries and ESP-NOW v2 Probe

The firmware and test runners distinguish and validate four distinct MTU layers:
1. **Decoded Core MTU**: `256` bytes (maximum uncompressed core payload before encoding).
2. **Stream R Encoded MTU**: `263` bytes (includes byte-stuffing and framing overhead).
3. **ESP-NOW v1 Payload MTU**: `250` bytes (`ESP_NOW_MAX_DATA_LEN`).
4. **ESP-NOW v2 Payload MTU**: `1470` bytes (`ESP_NOW_MAX_DATA_LEN_V2`).

> [!WARNING]
> **ESP-IDF v6.1 API note**:
> In ESP-IDF v6.1, `esp_now.h` declares `ESP_NOW_MAX_DATA_LEN_V2` (1470) and `esp_now_get_version(&version)`.
> However, the Doxygen function comment for `esp_now_send()` still states:
> `* @param len length of data, cannot be greater than ESP_NOW_MAX_DATA_LEN`.
>
> The qualification target requires `esp_now_get_version() >= 2`. Its DMP transport admits
> Stream R frames up to 263 encoded bytes; this is not a v1-compatible 250-byte transport cap.
> The pair runner separately sends a 256-byte decoded / greater-than-250-byte encoded raw v2
> capability probe. That probe is unauthenticated and is reported separately from DMP traffic.
> Pair mode uses the `retry-2` profile's 64-byte chunks and 1024-byte message bound. The
> multi-peer profile used by `four_serial` and `four_parallel` uses 128-byte chunks and a
> 4096-byte message bound. Each observed encoded frame size is recorded in evidence.
> Decoded Core MTU and encoded Stream R MTU are separate limits and must not be conflated.

## 4. Workload Geometry: Pair Mode

The S3/C3 pair runner uses the two-attempt `retry-2` profile:
- Message body: up to `1024` bytes.
- Chunk size: `64` bytes.
- Maximum fragments: `16` fragments.
- The runner rejects larger payloads before opening a serial port.

## 5. Workload Geometry: Multi-Peer Service-2 4096-Byte Transfers

The `four_serial` and `four_parallel` runners exercise high-volume protected data transfers
using the accepted multi-peer DMP profile geometry:
- Message body: `4096` bytes (deterministic pseudo-random test pattern).
- Chunk size: `128` bytes.
- Total fragments: `32` fragments.
- Over-the-wire frame: `~168` bytes per fragment (DMP header + 128B chunk + Poly1305 AEAD tag).
- Each fragment easily fits within the ESP-NOW 250-byte limit without application-level re-segmentation.

The `three_peer_serial` mode uses the same multi-peer profile with exactly three authenticated
C3 peers attached to one S3 endpoint. It reserves one producer epoch, performs one protected
SAMPLE-1 initialization READ from each peer, then transfers Service-2 data to each peer. It is a
four-board integration smoke and does not qualify the four-peer resource or lifecycle acceptance
cases.

## 6. SAMPLE-1 NVS Monotonic Epoch Check

To qualify persistent replay defense and crash recovery:
- Namespace: `"dmp_test_nvs"`.
- The `retry-2` profile uses epoch/anchor keys `"s1_epoch_test"` and `"s1_anch_test"`;
  `multi-peer` uses `"s1_epoch_mp"` and `"s1_anch_mp"`. Each pair binds durable state to its
  controller principal so changing test profiles does not mix principals or reset their epochs.
- The test command `NVS_CHECK` initializes `dmp_sample1_nvs_epoch_store` and calls `dmp_sample1_nvs_reserve_next`.
- It verifies that the reserved epoch strictly increments (`reserved_epoch > previous_epoch` when previous exists).
- It fails closed immediately if NVS returns a storage error or monotonicity violation.

## 7. Serial Control Interface

The qualification firmware responds to line-oriented ASCII commands over USB Serial/JTAG or UART0:
- `INFO`: Emit target specifications, MAC, and MTU bounds as a JSON `ready` event.
- `SESSION <16-hex-chars>`: Lock in a 64-bit session token for subsequent commands.
- `ROLE <controller|peer> <profile> <local_node_id> <handshake_scratch_slots>`: Select role,
  profile, node identity, and bounded handshake scratch capacity before initializing the endpoint.
  `retry-2` uses one slot; `multi-peer` uses one for `four_serial` and two for `four_parallel`
  on the S3 controller. Each C3 peer uses one slot.
- `PEER <mac> [node_id]`: Register a peer station MAC address and node ID.
- `NVS_CHECK`: Execute the SAMPLE-1 NVS monotonic epoch reservation test.
- `SAMPLE_ROTATE <sample_value>`: Qualification-only S3 command that starts the existing
  production SAMPLE-1 epoch transition, fences prior peer records, and publishes a sample
  under the newly reserved epoch. It does not add a wire command or alter the manifest.
- `HANDSHAKE <peer_handle>`: Start a SEC-1 Noise handshake with the given peer.
- `SAMPLE_READ <peer_handle>`: Submit an authenticated SAMPLE-1 initialization READ request.
- `TRANSFER <peer_handle> <bytes>`: Initiate a fragmented Service-2 transfer within the active
  profile bound (`retry-2`: up to 1024 bytes; `multi-peer`: up to 4096 bytes).
- `STATS`: Emit frame and transfer assembly statistics.
- `CORE_DUMP_TEST`: Emit an intentional-abort event and panic so the hardware-only coredump
  runner can verify flash coredump capture and reboot. This command is destructive to the
  current in-memory test session and must only be sent by the physical qualification runner.

The Python runners own repeat counts and serial/parallel transfer scheduling by issuing
`TRANSFER` commands. Firmware rejects the reserved `RUN_*` command names because those
commands do not implement the runner's full scheduling and repeat-count contract.
The default per-operation timeout is 25 seconds for pair mode and 60 seconds for four-peer
mode, covering the respective 20-second and 50-second single-attempt handshake deadlines.

The `serial_dmp_epoch_transition.py` hardware runner consumes a passing pair evidence directory
while both endpoints are still running that session. It records preflight boot IDs, rotates the
S3 SAMPLE-1 epoch, submits one READ over the old C3 association, watches for the full retry-2
initialization deadline from the active manifest, then software-reboots both boards and checks
the next S3 owner/NVS reservations. The runner reports decoded Core MTU and encoded Stream R MTU
as separate values. Prepare the live pair with NVS_CHECK omitted so the owner remains at the
latest durable epoch, then pass that run's directory to the transition runner:

```powershell
python tests/embedded/espnow_dmp/serial_dmp_pair.py `
  --s3-port COM37 --c3-port COM40 --transfer-bytes 1024 --timeout 70 `
  --skip-nvs-check-for-epoch-transition `
  --evidence-dir dev/evidence/p12-p01c-physical

python tests/embedded/espnow_dmp/serial_dmp_epoch_transition.py `
  --s3-port COM37 --c3-port COM40 `
  --previous-pair-dir dev/evidence/p12-p01c-physical/PAIR_RUN_DIRECTORY `
  --evidence-dir dev/evidence/p12-p01c-physical
```

This runner is physical-hardware-only and is not part of host CI. The host suite tests its event
validation using stubs; the hardware result remains separate evidence.

## 8. CI vs Hardware Separation

- **Host Tests & CI (No COM ports / No hardware required)**:
  - Located in `tests/host/espnow_dmp/`.
  - Executed via `python -m unittest discover -s tests/host/espnow_dmp -p 'test_*.py' -v` or CTest.
  - Interacts exclusively with in-memory stubs; will never attempt to open serial ports or flash chips.
- **Physical Hardware Execution**:
  - Pair mode requires one physical ESP32-S3 and one ESP32-C3. Either four-peer mode requires
    one S3 plus four C3 boards (five distinct serial ports).
  - `three_peer_serial` requires one S3 plus exactly three C3 boards (four distinct serial ports).
  - Executed manually by the operator:
    ```bash
    python tests/embedded/espnow_dmp/serial_dmp_pair.py --s3-port S3_PORT --c3-port C3_PORT --count 2
    python tests/embedded/espnow_dmp/serial_dmp_four.py --s3-port S3_PORT --c3-ports C3_NODE10 C3_NODE35 C3_NODE34 --mode three_peer_serial --bytes-per-peer 1024
    python tests/embedded/espnow_dmp/serial_dmp_four.py --s3-port S3_PORT --c3-ports C3_NODE10 C3_NODE35 C3_NODE34 C3_NODE36 --mode four_serial --count-per-peer 2
    ```
