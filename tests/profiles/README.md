# P02 manifest validator tests

Run the standard-library suite from the repository root:

```sh
python -m unittest discover -s tests/profiles -p 'test_*.py' -v
```

`invalid.json` is a frozen negative corpus. Each mutation is applied to a named
checked-in fixture and asserts the stable `ProfileError` category and path.
Its raw cases exercise byte decoding, JSON syntax, bounded parsing and exact
input-size rules. `expected.json` pins exact source-byte SHA256 digests and
independently hand-calculated successful derivations; it is not generated from
the validator.

The baseline fixtures use return period `P=64 ms`, width `W=42 ms`, delays
`F=R=20 ms`, burst span `B=256 ms`, application fragments `N=4`, bootstrap
fragments `N=2`, bootstrap chunk 60 bytes, forward/return MTU 256 bytes,
response timeout 448 ms and source starts `[0, 704]`. Each protected base header is 18 bytes direct or 32 bytes
routed. The service-2 application header adds reply, status, service, freshness
and fragment reserves: 38 bytes direct and 70 routed; adding the 16-byte chunk
and tag gives 70 and 102 bytes. Status frames are 48 and 62 bytes. Bootstrap
uses a 22-byte header, 60-byte chunk and 4-byte CRC32C for an 86-byte frame.
Stream R encodes the direct 256-byte path to `256 + 4 + floor(260/254) + 2 = 263` bytes.

The retry-all response floor is `F + receipt + R = 20 + 110 + 20 = 150 ms`.
Selective recovery raises it to `max(150, 2F + burst + guard + feedback + R,
2R + burst + guard + feedback + F) = 430 ms`. Freshness must last through
grant delivery age, queue, send horizon and worst directional delay:
`100 + 64 + 960 + 20 = 1144 ms` for routed manifests and 1044 ms for direct.
The serialized transfer reserves `bursts * (application fragments + bootstrap
fragments) + statuses + receipts`: 14 frames for retry-all, 16 selective.

NNpsk0 establishment reserves `(2 flights * 2 attempts + 1 duplicate) * 2`
bootstrap frames plus four confirmation frames = 14 frames. At 263 or 256
encoded bytes that is 3682 or 3584 bytes. Duration is `(4 + 1) * 1856 +
2 * 320 + 500 + 1000 = 11420 ms`. Bootstrap flight span is `2 * 64 = 128 ms`.
XX reserves two additional bootstrap-sized cached-flight-three responses,
giving 22 frames and 5786 bytes for the valid direct-mode variant. Its two
confirmation intervals use 448 ms each, and the total attempt budget is
`(6 + 1) * 1856 + 2 * 448 + 500 + 1000 = 15388 ms`.
Radio relay cache capacity is `4 operations * (4 application + 2 bootstrap)
+ 2 statuses + 2 receipts + 14 establishment frames * 2 episode attempts = 56`
records (54 for retry-all). The 32-byte records use 1792 bytes (1728 for
retry-all); 13 one-byte component reservations add 13 bytes, and control plus
adapter buffers add `2 * 256 = 512` bytes, for 2317 bytes total (2253 for
retry-all). The checked-in totals are in `expected.json`.

The suite checks only the offline validator contract. It does not simulate a
protocol, prove a physical link's delay promises, or establish embedded RAM
usage on a target.
