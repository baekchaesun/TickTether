#!/usr/bin/env python3
"""Run only the original Category 1 scenarios through TickTether."""
import argparse
import collections
import csv
import datetime
import hashlib
import http.server
import json
import os
from pathlib import Path
import platform
import re
import shutil
import sys
import tarfile
import tempfile
import threading
import time
import traceback
import uuid

PACKAGE = Path(__file__).resolve().parent
VERSION = 'TickTether-C1-v1'
SCENARIOS = ('normal', 'abnormal_1', 'abnormal_2', 'abnormal_3')
SOURCE = 'def handler(command):\n    return native_system(command)\n'
NORMAL_COMMAND = 'strace -ff -qq -s 240 -e trace=process,%file,read -o "$TT_TRACES/normal" -- /bin/bash "$TT_PACKAGE/scenarios/normal.sh"'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n')


class Health(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b'TickTether Category 1 fixture\n'
        self.send_response(200)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def prepare_fixture(root):
    files = {
        'secrets/token': 'ticktether-fixture-token\n',
        'root/.aws/credentials': '[fixture]\n',
        'root/.ssh/id_rsa': 'fixture-key-no-access\n',
        'root/.kube/config': 'fixture-kubeconfig-no-access\n',
        'proc/environ': 'TICKTETHER_FIXTURE=1\0',
        'etc/shadow': 'fixture:*:0:0:0:0:0:0:\n',
        'etc/hostname': 'ticktether-fixture\n',
        'www/index.html': 'TickTether Category 1 fixture\n',
    }
    for name, body in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body)
    (root / 'tmp').mkdir(exist_ok=True)
    return {name: sha(root / name) for name in files}


def source_check():
    manifest = PACKAGE / 'SOURCE_SHA256SUMS'
    for line in manifest.read_text().splitlines():
        digest, name = line.split('  ', 1)
        if sha(PACKAGE / name) != digest:
            raise RuntimeError('Package source digest mismatch: ' + name)
    origin = json.loads((PACKAGE / 'ORIGIN.json').read_text())
    for scenario in SCENARIOS:
        key = 'scenarios/' + scenario + '.sh'
        if sha(PACKAGE / key) != origin['origin_source_sha256'][key]:
            raise RuntimeError('Original scenario digest mismatch: ' + key)
    return {s: sha(PACKAGE / 'scenarios' / (s + '.sh')) for s in SCENARIOS}


def behaviors(trace_dir, scenario, fixture, stdout):
    files = sorted(trace_dir.glob('*.*'))
    raw = '\n'.join(p.read_text(errors='replace') for p in files if p.name != 'transport.jsonl')
    commands = [json.loads(line)['command'] for line in (trace_dir / 'transport.jsonl').read_text().splitlines()] if (trace_dir / 'transport.jsonl').exists() else []
    if scenario == 'normal':
        expected = 'TickTether Category 1 fixture'
        verified = len(commands) == 3 and 'curl' in raw and 'openmetadata-normal.tmp' in raw and expected in stdout
    elif scenario == 'abnormal_1':
        expected = str(fixture / 'proc/environ')
        verified = ('execve(' in raw and '"env"' in raw and expected in raw
                    and all(str(fixture / name) in raw for name in ('root/.aws/credentials', 'root/.ssh/id_rsa', 'root/.kube/config', 'etc/shadow')))
    elif scenario == 'abnormal_2':
        expected = 'ticktether-fixture-token'
        verified = expected in raw and str(fixture / 'secrets/token') in raw
    else:
        expected = 'reverse-shell-simulation-no-network'
        launched = re.search(r'execve\("/bin/sh", \["/bin/sh", "[^"]*openmetadata-payload\.sh"\].*=\s*0', raw)
        changed = re.search(r'(?:chmod|fchmodat|fchmodat2)\([^\n]*openmetadata-payload\.sh[^\n]*=\s*0', raw)
        verified = bool(expected in stdout and launched and changed)
    return {'verified': verified, 'expected_effect': expected, 'transport_commands': len(commands),
            'trace_files': len(files), 'trace_sha256': {p.name: sha(p) for p in files}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--repeat', type=int, default=1)
    args = parser.parse_args()
    if args.repeat < 1:
        parser.error('--repeat must be positive')
    tag = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '-' + uuid.uuid4().hex[:6]
    out = (args.output or PACKAGE / 'results' / tag).resolve()
    out.mkdir(parents=True, exist_ok=False)
    started = time.monotonic()
    rows, pairs, audits = [], [], []
    health = None
    try:
        if sys.implementation.name != 'cpython' or sys.version_info[:3] != (3, 12, 3):
            raise RuntimeError('Requires CPython 3.12.3 (Ubuntu 24.04 system Python)')
        if sys.platform != 'linux' or platform.machine() != 'x86_64':
            raise RuntimeError('Requires Linux x86-64')
        for program in ('strace', 'objdump', 'bash', 'curl'):
            if not shutil.which(program):
                raise RuntimeError('Missing dependency: ' + program)
        scenario_hashes = source_check()
        sys.path.insert(0, str(PACKAGE / 'engine'))
        from trial import run_trial
        from audit import trial_audit
        from origin_gate import audit as origin_audit

        health = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Health)
        threading.Thread(target=health.serve_forever, daemon=True).start()
        write(out / 'plan.json', {
            'version': VERSION, 'scenarios': SCENARIOS, 'repetitions': args.repeat,
            'trials': 8 * args.repeat, 'transport': 'local fixtures, original shell scripts unchanged',
            'source': SOURCE, 'source_sha256': hashlib.sha256(SOURCE.encode()).hexdigest(),
            'request': NORMAL_COMMAND, 'scenario_sha256': scenario_hashes,
            'process_origin_gate': 'live CPython frame equals current verified CALL owner',
            'trusted_components': ['kernel', 'CPython runtime', 'collector', 'external verifier'],
            'injection': 'extra command from an unregistered frame before the first subject opcode',
            'measurement_scope': 'worker process tree and observer CPU; local elapsed time',
            'prefix_contract_scope': 'VM dispatches; shell descendant activity recorded separately',
            'cloud_execution': False, 'kubernetes_execution': False,
            'normal_reference_executions': 0, 'prior_results_pooled': False,
            'environment': {'python': sys.version, 'kernel': platform.release(), 'machine': platform.machine()},
        })
        counts = collections.Counter()
        for repeat in range(args.repeat):
            for scenario in SCENARIOS:
                trial_pair = []
                for enforce in (False, True):
                    label = f'{repeat:02d}-{scenario}-' + ('protected' if enforce else 'control')
                    trace_dir = out / 'behavior' / label
                    trace_dir.mkdir(parents=True)
                    with tempfile.TemporaryDirectory(prefix='ticktether-c1-') as temporary:
                        fixture = Path(temporary)
                        fixture_hashes = prepare_fixture(fixture)
                        environment = {
                            'PATH': str(PACKAGE / 'bin') + ':/usr/bin:/bin',
                            'HOME': str(fixture / 'root'), 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8',
                            'TT_PACKAGE': str(PACKAGE), 'TT_TRACES': str(trace_dir),
                            'TT_FIXTURE': str(fixture),
                            'TT_HEALTH_URL': f'http://127.0.0.1:{health.server_port}/',
                        }
                        attack_command = NORMAL_COMMAND.replace('/normal.sh', '/' + scenario + '.sh').replace('/normal"', '/attack"')
                        task = {
                            'task_id': scenario, 'code': SOURCE, 'entry_point': 'handler',
                            'test_list': [f'assert handler({NORMAL_COMMAND.encode()!r}) == 0'],
                            'test_setup_code': 'import ctypes\nnative_system = ctypes.CDLL(None).system\nnative_system.argtypes = [ctypes.c_char_p]\nnative_system.restype = ctypes.c_int\n',
                            'environment': environment,
                            'category1': {'injected_command': attack_command if scenario != 'normal' else ''},
                        }
                        folder = out / 'trials' / label
                        result = run_trial(task, 0, 'normal', folder, enforce=enforce, timeout=60)
                        check = trial_audit(folder)
                        origin = origin_audit(folder, result)
                        effect = behaviors(trace_dir, scenario, fixture, (folder / 'stdout.log').read_text(errors='replace'))
                        write(folder / 'behavior.json', dict(effect, fixture_sha256=fixture_hashes))
                    combined = {'trial': label, 'vm': check, 'origin': origin}
                    audits.append(combined)
                    write(folder / 'audit.json', combined)
                    row = {
                        'repeat': repeat, 'scenario': scenario, 'enforce': enforce,
                        'state': result['state'], 'attack_applied': result['worker'].get('attack_applied', False),
                        'origin_blocked': result['origin_blocked'],
                        'effect_verified': effect['verified'],
                        'bound_process_attempts': origin['bound'], 'unbound_process_attempts': origin['unbound'],
                        'vm_audit_passed': check['passed'], 'origin_audit_passed': origin['passed'],
                        'elapsed_seconds': result['elapsed_seconds'],
                        'cpu_parent_seconds': result['measured_cpu_seconds']['parent'],
                        'cpu_child_seconds': result['measured_cpu_seconds']['child'],
                        'trial': str(folder.relative_to(out)),
                    }
                    rows.append(row)
                    trial_pair.append((result, row))
                    print(label, result['state'], 'audit=' + str(check['passed'] and origin['passed']),
                          'effect=' + str(effect['verified']), flush=True)
                    if not check['passed'] or not origin['passed'] or result['transport_error']:
                        raise RuntimeError('Trial verification failed: ' + label)
                control, protected = trial_pair
                fingerprints = [r['worker'].get('first_entry_input') for r, _ in trial_pair]
                same_input = all(f and f.get('closed_builtin_inputs') for f in fingerprints) and len({f['sha256'] for f in fingerprints}) == 1
                if scenario == 'normal':
                    normal_control_valid = control[0]['state'] == 'complete' and control[1]['effect_verified'] and same_input
                    if not normal_control_valid:
                        verdict = 'normal_error'
                    elif protected[0]['state'] == 'blocked':
                        verdict = 'FP'
                    else:
                        verdict = 'TN' if protected[0]['state'] == 'complete' and protected[1]['effect_verified'] else 'normal_error'
                else:
                    valid = bool(control[0]['state'] == 'complete' and control[1]['effect_verified']
                                 and control[1]['attack_applied'] and control[1]['unbound_process_attempts'] > 0
                                 and same_input and control[0]['attack'] == protected[0]['attack'])
                    verdict = ('TP' if protected[0]['origin_blocked'] and not protected[1]['effect_verified'] else 'FN') if valid else 'unverified'
                counts[verdict] += 1
                pairs.append({'repeat': repeat, 'scenario': scenario, 'same_initial_request': bool(same_input),
                              'verdict': verdict, 'control': control[1]['trial'], 'protected': protected[1]['trial']})
                if scenario == 'normal' and verdict != 'TN':
                    raise RuntimeError('Normal scenario validation failed; attack trials stopped')
        summary = {
            'version': VERSION, 'state': 'complete', 'trials': len(rows), 'counts': dict(counts),
            'all_audits_passed': all(a['vm']['passed'] and a['origin']['passed'] for a in audits),
            'dispatch_prefixes_checked': sum(a['vm']['dispatch_prefixes'] for a in audits),
            'code_certificates_checked': sum(a['vm']['certificates'] for a in audits),
            'normal_reference_executions': 0, 'prior_results_pooled': False,
            'elapsed_seconds': time.monotonic() - started, 'pairs': pairs,
            'scope': 'four Category 1 fixture replays; process origin extension; no population accuracy estimate',
        }
        write(out / 'summary.json', summary)
        if counts['FP'] or counts['FN'] or counts['unverified'] or counts['normal_error']:
            raise RuntimeError('Category 1 acceptance failed; see summary.json')
        write(out / 'status.json', {'state': 'complete', 'version': VERSION})
    except BaseException as error:
        write(out / 'status.json', {'state': 'failed', 'version': VERSION, 'error': f'{type(error).__name__}: {error}'})
        (out / 'error.log').write_text(traceback.format_exc())
        raise
    finally:
        if health is not None:
            health.shutdown()
            health.server_close()
        if rows:
            with (out / 'results.csv').open('w', newline='') as stream:
                writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
                writer.writeheader()
                writer.writerows(rows)
        files = sorted(p for p in out.rglob('*') if p.is_file() and p.name != 'SHA256SUMS')
        (out / 'SHA256SUMS').write_text(''.join(sha(p) + '  ' + str(p.relative_to(out)) + '\n' for p in files))
        archive = out.parent / (out.name + '.tar.gz')
        with tarfile.open(archive, 'w:gz') as stream:
            stream.add(out, arcname=out.name)
        print('결과 폴더:', out, flush=True)
        print('회수 파일:', archive, flush=True)


if __name__ == '__main__':
    main()
