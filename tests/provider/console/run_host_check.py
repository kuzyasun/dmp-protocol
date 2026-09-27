"""CTest bridge: keep a unique replayable trace from two real provider processes."""
import argparse
from pathlib import Path
import time

import serial_bench


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--exe', required=True)
    parser.add_argument('--output-dir', required=True)
    args = parser.parse_args()
    directory = Path(args.output_dir)
    directory.mkdir(parents=True, exist_ok=True)
    output = directory / f'console-{time.time_ns()}.jsonl'
    return serial_bench.main(['--host-exe', args.exe, '--output', str(output),
                              '--cycles', '2', '--mode', 'both'])


if __name__ == '__main__':
    raise SystemExit(main())
