"""Verify NONE archives and their link probe contain no security symbols."""

import subprocess
import sys


FORBIDDEN_PREFIXES = (
    "dmp_hs_", "dmp_provider_", "dmp_replay_window_", "dmp_sodium_entropy_",
    "noise_", "sodium_", "crypto_", "randombytes_",
)
REQUIRED_LINK_SYMBOLS = {
    "dmp_endpoint_init",
    "dmp_none_boot_epoch_generate",
    "dmp_sample1_endpoint_init_with_peer_storage",
}


def read_symbols(nm, path):
    result = subprocess.run([nm, path], check=True, capture_output=True, text=True)
    symbols = set()
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) >= 2 and len(fields[-2]) == 1:
            name = fields[-1].removeprefix("__imp_").lstrip("_")
            symbols.add(name.split("@", 1)[0])
    return symbols


def main():
    arguments = sys.argv[1:]
    packet = arguments[0] == "--packet"
    if packet:
        arguments = arguments[1:]
    nm, probe, *archives = arguments
    required = REQUIRED_LINK_SYMBOLS
    forbidden_prefixes = FORBIDDEN_PREFIXES
    if packet:
        required = {"dmp_endpoint_init", "dmp_endpoint_rx_packet_from", "dmp_crc32c"}
        forbidden_prefixes += ("dmp_stream_", "dmp_cobs_")
    for path in (probe, *archives):
        symbols = read_symbols(nm, path)
        forbidden = sorted(name for name in symbols if name.startswith(forbidden_prefixes))
        if forbidden:
            print(f"{path}: forbidden security symbols: {', '.join(forbidden)}", file=sys.stderr)
            return 1
        if path == probe and (missing := required - symbols):
            print(f"{path}: missing entry symbols: {', '.join(sorted(missing))}", file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
