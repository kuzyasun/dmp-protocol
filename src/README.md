# Portable implementation sources

`core/base.c` is the P04 foundation compiled into `libdmp` (`dmp::dmp`). It owns
checked byte views, absolute deadline arithmetic, nonwrapping generations and
local status names. Tests link that archive; no duplicate implementation lives
in a test runner.

P05 implements the structural codec in `core/codec.c`; P06 supplies CRC32C in
`integrity/crc32c.c`, shared private canonical COBS in `stream/cobs.c` and the
bounded Stream L/R state machine in `stream/stream.c`. All are linked into
`libdmp`. `transport.h` describes the injected adapter interface, not a platform
driver. Crypto, endpoint acceptance, reliability, reassembly and runtime profile
enforcement remain separate unfinished modules.

P05 owns `src/core/codec.c` and dedicated `tests/core/` codec files. P06 owns
`src/integrity/crc32c.c`, `src/stream/stream.c` and dedicated `tests/stream/`.
P07 owns `tests/harness/` for clock/fault/transport injection; protocol behavior
must stay in this library. Public headers and root CMake remain coordinator-owned.
