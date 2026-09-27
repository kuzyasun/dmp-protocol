"""Derive physical evidence from the retained serial traces; no device access."""
import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path
from statistics import median


ROOT = Path(__file__).resolve().parent
BUILD = '71e3a2d6f1a77ce124ea402eded20bcb44aee34c6a23de5007bd41e67a791086'


def distribution(values):
    return {'count': len(values), 'min': min(values), 'median': median(values),
            'max': max(values)}


def main():
    targets = defaultdict(list)
    timings = defaultdict(list)
    handshakes = defaultdict(list)
    runs = []
    for name in ('short', 'repeat', 'reverse'):
        path = ROOT / (name + '.jsonl')
        rows = [json.loads(line) for line in path.read_text().splitlines()]
        assert not any(row['event'] in {'failure', 'timeout', 'run_failed',
                                       'malformed_response'} for row in rows), name
        summaries = [row for row in rows if row['event'] == 'summary']
        assert len(summaries) == 2 and all(row['success'] for row in summaries)
        expected_pairs = 8 * summaries[0]['cycles']
        assert all(len(row['scenarios']) == expected_pairs for row in summaries)
        pending, owners = {}, {}
        run_responses = 0
        for row in rows:
            peer = row.get('peer')
            if row['event'] in {'command', 'synchronize'}:
                pending[peer] = row
            elif row['event'] == 'response':
                response = row['response']
                command = pending.pop(peer)
                assert response['id'] == command['id']
                assert response['build'] == BUILD and response['idf'] == 'v6.1'
                assert response['target'] in {'esp32s3', 'esp32c3'}
                assert response['stats']['wipe_errors'] == 0
                target = response['target']
                targets[target].append(response)
                run_responses += 1
                op, args = command['op'], command.get('args', [])
                if op == 'NEW' and response['rc'] == 0:
                    owners[(peer, args[0])] = {'pattern': args[1], 'role': args[2],
                                              'flavor': args[3], 'us': 0}
                owner = owners.get((peer, args[0])) if args else None
                if owner and response['rc'] == 0:
                    key = (target, owner['pattern'], owner['role'], owner['flavor'])
                    timings[key + (op,)].append(response['us'])
                    if op in {'NEW', 'WRITE', 'READ', 'SPLIT'}:
                        owner['us'] += response['us']
                    if op == 'SPLIT':
                        handshakes[key].append(owner['us'])
                    if op == 'CLOSE':
                        del owners[(peer, args[0])]
        assert not pending and not owners, name
        runs.append({'name': name, 'cycles': summaries[0]['cycles'],
                     'handshake_pairs': expected_pairs, 'responses': run_responses,
                     'trace_sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
                     'duration_seconds': (rows[-1]['time_unix_ms'] - rows[0]['time_unix_ms']) / 1000})
    devices = {}
    for target, replies in targets.items():
        assert len({r['boot'] for r in replies}) == 1, target
        stats = [r['stats'] for r in replies]
        closed = [s for s in stats if s['arena_live'] == 0 and s['blocks'] == 0]
        assert all(s['allocs'] == s['frees'] for s in closed)
        assert replies[-1]['stats'] in closed
        devices[target] = {
            'boot': replies[0]['boot'], 'build': BUILD, 'configured_cpu_mhz': 160,
            'response_count': len(replies), 'result_codes': dict(Counter(r['rc'] for r in replies)),
            'arena_peak_bytes': max(s['arena_peak'] for s in stats),
            'arena_backing_bytes': stats[0]['backing'], 'arena_metadata_bytes': stats[0]['metadata'],
            'owner_table_bytes': stats[0]['owners'], 'shared_scratch_bytes': stats[0]['scratch'],
            'heap_free_bytes': distribution([s['heap_free'] for s in stats]),
            'heap_free_when_arena_empty_bytes': distribution([s['heap_free'] for s in closed]),
            'heap_lifetime_min_bytes': min(s['heap_min'] for s in stats),
            'heap_largest_block_min_bytes': min(s['heap_largest'] for s in stats),
            'task_stack_reserved_bytes': 12288,
            'task_stack_min_remaining_bytes': min(s['stack_free_min'] for s in stats),
            'task_stack_observed_high_water_bytes': 12288 - min(s['stack_free_min'] for s in stats),
            'final_stats': stats[-1],
        }
    result = {'scope': 'physical provider bench, UART forwarded by Python; no DMP/radio claim',
              'timing_scope': 'sum of successful NEW/WRITE/READ/SPLIT command us per local endpoint; excludes peer, UART wait and reply formatting; includes parser/provider work',
              'runs': runs, 'devices': devices,
              'handshake_command_us': {'/'.join(k): distribution(v) for k, v in sorted(handshakes.items())},
              'operation_us': {'/'.join(k): distribution(v) for k, v in sorted(timings.items())}}
    (ROOT / 'results.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'runs': runs, 'devices': devices}, indent=2))


if __name__ == '__main__':
    main()
