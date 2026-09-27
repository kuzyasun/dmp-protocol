"""Negative command/parser tests against the actual compiled provider process."""
import argparse
import json
import subprocess


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--exe', required=True)
    args = parser.parse_args()
    lines = [
        'DMPBENCH 1 1 HELLO', 'DMPBENCH 1 1 INIT',
        'DMPBENCH 2 2 INIT', 'DMPBENCH 1 2 STATS',
        'DMPBENCH 1 3 NEW 0 unknown i random', 'DMPBENCH 1 4 RESET 0',
        'DMPBENCH 1 5 INIT', 'DMPBENCH 1 6 NEW 0 nn i fixed',
        'DMPBENCH 1 7 STATS', 'DMPBENCH 1 8 RESET 32768',
        'DMPBENCH 1 9 NEW 0 nn i fixed', 'DMPBENCH 1 10 RESET 32768',
        'DMPBENCH 1 11 CLOSE 0', 'DMPBENCH 1 12 STATS',
        'DMPBENCH 1 13 ALLOCFAIL 1', 'DMPBENCH 1 14 NEW 0 xx i fixed',
        'DMPBENCH 1 15 NEW 0 nn i random', 'DMPBENCH 1 16 RNGFAIL 1',
        'DMPBENCH 1 17 WRITE 0 -', 'DMPBENCH 1 18 WRITE 0 -',
        'DMPBENCH 1 19 CLOSE 0', 'DMPBENCH 1 20 STATS',
        'x' * 4000, 'DMPBENCH 1 21 STATS',
        'DMPBENCH 1 22 NEW 0 nn i fixed\x00', 'DMPBENCH 1 22 STATS',
        'DMPBENCH 1 23 NEW 0 nn i fixed trailing',
        'DMPBENCH 1 24 RESET -1', 'DMPBENCH 1 25 RESET 32769',
        'DMPBENCH 1 26 NEW 0 nn i fixed', 'DMPBENCH 1 27 WRITE 0 0g',
        'DMPBENCH 1 28 SPLIT 0', 'DMPBENCH 1 29 CLOSE 0',
        'DMPBENCH 1 30 STATS',
        'DMPBENCH 1 0 HELLO', 'DMPBENCH 1 0 RESET 0', 'DMPBENCH 1 31 STATS',
    ]
    expected = [0, -2, -2, 0, -1, 0, 0, 17665, 0, 0, 0, 17676, 0, 0,
                0, 17665, 0, 0, 17670, 17676, 0, 0, -2, 0, -2, 0,
                -1, -1, -1, 0, -1, 17676, 0, 0, 0, -2, 0]
    result = subprocess.run([args.exe], input=('\n'.join(lines) + '\n').encode(),
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20, check=True)
    replies = [json.loads(line[9:]) for line in result.stdout.splitlines()
               if line.startswith(b'DMPBENCH ')]
    assert len(replies) == len(expected), (len(replies), result.stdout, result.stderr)
    for index, (reply, code) in enumerate(zip(replies, expected)):
        assert reply['rc'] == code, (index, lines[index], reply)
        assert reply['data'] == '', (index, reply)
        assert reply['stats']['wipe_errors'] == 0, (index, reply)
        assert reply['boot'] == replies[0]['boot'] and len(reply['boot']) == 16
        assert reply['build'] == replies[0]['build'] and len(reply['build']) == 64
    stats = replies[-1]['stats']
    # Invalid payload / premature SPLIT leave the live handshake at WRITE.
    assert replies[30]['action'] == replies[31]['action'] == 16641
    assert replies[18]['action'] == replies[19]['action'] == 16643
    assert replies[-3]['last_id'] == replies[-2]['last_id'] == 30
    assert replies[-1]['last_id'] == 31
    assert stats['arena_live'] == stats['blocks'] == 0
    assert stats['allocs'] == stats['frees']
    print(f'console core: {len(replies)} real-process parser/lifetime/fault checks PASS')


if __name__ == '__main__':
    main()
