"""Bind a worker's process-creation attempt to its live verified CALL frame.

The decision reads neither the scenario name nor a command/path allowlist.
Descendant shell activity is recorded separately; this gate controls the root
process creation from the observed CPython worker.
"""
import ctypes
import json
import struct
import native_trace as nt

SPAWN = {56: 'clone', 57: 'fork', 58: 'vfork', 59: 'execve', 322: 'execveat', 435: 'clone3'}


class SyscallInfo(ctypes.Structure):
    _fields_ = [('op', ctypes.c_ubyte), ('pad', ctypes.c_ubyte * 3),
                ('arch', ctypes.c_uint32), ('ip', ctypes.c_uint64),
                ('sp', ctypes.c_uint64), ('data', ctypes.c_uint64 * 8)]


class OriginBlocked(RuntimeError):
    def __init__(self, alarm):
        super().__init__(alarm['reason'])
        self.alarm = alarm


def allowed(record):
    return bool(record['active_frame'] and record['active_frame'] == record['lease_owner']
                and record['lease_kind'] == 'opcode' and record['opcode'] == 'CALL')


class Gate:
    def __init__(self, path, enforce):
        self.stream = path.open('w')
        self.enforce = enforce
        self.records = []

    def observe(self, native, wire_events):
        info = SyscallInfo()
        nt.ptrace(0x420e, native.pid, ctypes.sizeof(info), ctypes.addressof(info))
        if info.op != 1 or info.data[0] not in SPAWN:
            return
        if info.arch != 0xc000003e:
            raise RuntimeError('TickTether process gate requires x86-64 syscall ABI')
        def word(address):
            return struct.unpack('<Q', nt.read(native.pid, address, 8))[0]
        cframe = word(native.tstate + 56) if native.tstate else 0
        active = word(cframe) if cframe else 0
        lease = native.lease
        opcode = None
        if lease.get('kind') == 'opcode':
            f = native.monitor.frames[lease['frame_id']]
            opcode = native.monitor.codes[f['code']]['ops'][lease['offset']]['name']
        record = dict(kind='process_origin', after_events=wire_events,
                      syscall=SPAWN[info.data[0]], syscall_number=int(info.data[0]),
                      syscall_ip=int(info.ip), thread_state=native.tstate,
                      cframe=cframe, active_frame=active, lease_owner=native.owner,
                      lease_kind=lease.get('kind'), frame_id=lease.get('frame_id'),
                      offset=lease.get('offset'), opcode=opcode)
        record['bound_to_verified_call'] = allowed(record)
        record['decision'] = 'allow' if record['bound_to_verified_call'] else 'block' if self.enforce else 'observe'
        self.records.append(record)
        self.stream.write(json.dumps(record, separators=(',', ':')) + '\n')
        self.stream.flush()
        if record['decision'] == 'block':
            raise OriginBlocked(dict(reason='unbound_process_creation', event='syscall',
                                     syscall=record['syscall'], active_frame=active,
                                     expected_frame=native.owner, after_events=wire_events))

    def close(self):
        self.stream.close()


def audit(folder, result):
    import gzip
    import hashlib
    path = folder / 'process_origin.jsonl'
    rows = [json.loads(s) for s in path.read_text().splitlines()]
    errors = []
    if hashlib.sha256(path.read_bytes()).hexdigest() != result['process_origin_sha256']:
        errors.append('process origin digest')
    by_index = {}
    with gzip.open(folder / 'witnesses.jsonl.gz', 'rt') as stream:
        counter = 0
        owner = 0
        last = {}
        codes, frames = {}, {}
        for line in stream:
            raw = json.loads(line)
            if 'event' not in raw:
                continue
            event = raw['event']
            counter += 1
            if event['kind'] == 'register':
                codes[event['code_id']] = event['description']
            if event['kind'] == 'frame':
                frames[event['frame_id']] = event['code_id']
            if event.get('native_stop'):
                owner, last = event.get('native_owner', 0), event
            op = None
            if last.get('kind') == 'opcode':
                code = codes[frames[last['frame_id']]]
                op = code['ops'][str(last['offset'])]['name']
            by_index[counter] = (owner, last.get('kind'), last.get('frame_id'), last.get('offset'), op)
    for row in rows:
        expected = by_index.get(row['after_events'])
        actual = (row['lease_owner'], row['lease_kind'], row['frame_id'], row['offset'], row['opcode'])
        if expected != actual:
            errors.append('origin lease does not match verified event prefix')
        bound = bool(row['active_frame'] and row['active_frame'] == row['lease_owner']
                     and row['lease_kind'] == 'opcode' and row['opcode'] == 'CALL')
        decision = 'allow' if bound else 'block' if result['enforce'] else 'observe'
        if bound != row['bound_to_verified_call'] or decision != row['decision']:
            errors.append('origin decision mismatch')
    blocked = [row for row in rows if row['decision'] == 'block']
    if result.get('origin_blocked') != bool(blocked):
        errors.append('origin block result mismatch')
    return dict(passed=not errors, records=len(rows), bound=sum(r['bound_to_verified_call'] for r in rows),
                unbound=sum(not r['bound_to_verified_call'] for r in rows), violations=errors,
                source_reexecutions=0)
