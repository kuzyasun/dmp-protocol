# Bounded peer command-line tools

These tools are host-test utilities. They do not change
`tests/harness/PROTOCOL.md` v1 or the in-process `DMP-PEER-TEST/1` records.

## Endpoint process bridge

Run from `tests/peer/`:

```text
python -m dmp_peer.process_bridge --manifest <frozen-manifest-path> --node-id <u32>
```

The process reads one UTF-8 JSON object per line and writes one response object
per accepted request. Requests use the closed shape
`{"interface":"DMP-PEER-TEST/1","input":{...}}`. Each input object has an
`op` from `open`, `receive`, `advance`, `tx_admit`, `tx_terminal`, `disconnect`,
`restart`, `application_request`, or `publish_sample`; fields match the existing
immutable event records. Binary fields use canonical base64 with `_b64` names.
The process bridge does not parse or reinterpret DMP frame contents.

Responses retain the same interface version and return ordered endpoint events.
`tx_submit.bytes` and `application_event.payload` remain machine API data,
base64 encoded on stdout; they are never copied to stderr diagnostics. EOF with
unsettled accepted submissions exits with `E_TERMINAL`. Input/configuration
failures use only the fixed stderr codes `E_INPUT`, `E_CONFIG`, `E_LIMIT`, and
`E_TERMINAL`; input text, JSON fragments, credentials, frames and payloads are
never echoed.

Bounds are 1 MiB per request line, 65,536 decoded input bytes per event, 10,000
requests per process, 4,096 output events per request, 1 MiB summed event byte
fields, 2 MiB per response line, and 16 nested JSON containers. Duplicate JSON
members, unknown members, non-finite numbers and noncanonical base64 are
rejected. The endpoint's own manifest, monotonic-time, event and generation
checks remain authoritative.

Credentials are injected only through the process environment:
`DMP_PEER_TEST_PSK_HEX`, `DMP_PEER_TEST_STATIC_PRIVATE_HEX`,
`DMP_PEER_TEST_PEER_PIN_HEX`, and `DMP_PEER_TEST_KEY_HINT`. They are never
included in process output. These variables are for public test fixtures only;
the tool does not provide production provisioning or deployment behavior.

## Redacted decoder

Run either bounded mode from `tests/peer/`:

```text
python -m dmp_peer.decoder_cli --mode core
python -m dmp_peer.decoder_cli --mode stream
```

Each input line has exactly `bytes_b64` and `at_ms`. Core mode accepts one frame
up to 256 bytes. Stream mode accepts ordered chunks up to 65,536 bytes, uses the
frozen 256/263-byte Stream R caps and the 26 ms candidate timeout, and reports
only complete decoded frames or bounded discard statuses. It does not decrypt
SEC-1 or interpret application payloads.

Default output is allowlisted to `event`, `at_ms`, `size`, `message_type`,
`protected`, `fragmented`, `route_present`, and the fixed discard reasons
`malformed`, `candidate-bound`, or `candidate-timeout`. It never prints frame
bytes, ciphertext, plaintext, CONTEXT values, sequence numbers, tokens, keys,
credential hints, or handshake transcript bytes. Passing `--include-identity`
adds only available `namespace`, `origin`, `destination`, `epoch`, `sequence`,
and `fragment_index` fields under an `identity` object. It does not enable any
other output fields.

Both modes cap input at 4,096 lines and emitted records at 4,096. Invalid input
uses fixed stderr codes only; diagnostics never echo the input or parser error
text.
