"""Host helper scoped to one frozen study function cgroup and direct children.

No Knative/global config writes, code patching, system-wide events, or arbitrary PID API.
"""
import array
import ctypes
import hashlib
import json
import os
from pathlib import Path
import socket
import sys
import time

ROOT=Path(__file__).resolve().parent
cgroup=Path(sys.argv[1]);pod_uid=sys.argv[2];container_id=sys.argv[3]
assert pod_uid.replace('-','_') in str(cgroup) or pod_uid in str(cgroup)
assert container_id in str(cgroup) and cgroup.name.endswith(container_id+'.scope')
inode=cgroup.stat().st_ino
symbols=json.loads((ROOT/'symbols.json').read_text())
expected_worker_sha=hashlib.sha256((ROOT/'worker').read_bytes()).hexdigest()
lib=ctypes.CDLL(str(ROOT/'perf_bridge.so'),use_errno=True)
lib.ce_perf_open.argtypes=(ctypes.c_int,ctypes.c_uint64,ctypes.c_uint64)
lib.ce_validate_owned_pidfd.argtypes=(ctypes.c_int,ctypes.c_char_p,ctypes.c_uint64,ctypes.c_int,ctypes.c_int)

def identities():
    assert cgroup.stat().st_ino==inode
    rows=[]
    for pid in map(int,(cgroup/'cgroup.procs').read_text().split()):
        try:
            status=dict(row.split(':',1) for row in Path(f'/proc/{pid}/status').read_text().splitlines() if ':' in row)
            rows.append((pid,status))
        except FileNotFoundError:continue
    return rows

parents=[]
for pid,status in identities():
    args=Path(f'/proc/{pid}/cmdline').read_bytes().split(b'\0')
    if b'/code/app.py' in args:parents.append(pid)
assert len(parents)==1,parents
parent=parents[0]
endpoint='/channel/ce-perf.sock'  # exact owned Pod's emptyDir, read-only bind
connection=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
for _ in range(100):
    try:connection.connect(endpoint);break
    except (FileNotFoundError,ConnectionRefusedError):time.sleep(.05)
else:raise RuntimeError('function-local perf FD socket unavailable')
assert connection.recv(6)==b'ready\n','owned function FD connection handshake'
print(json.dumps({'ready':True,'parent_host_pid':parent,'pod_uid':pod_uid,'container_id':container_id,'cgroup_inode':inode}),flush=True)
selftested=False
while True:
    line,ancillary,flags,address=connection.recvmsg(4096,socket.CMSG_SPACE(4))
    if not line:break
    received=array.array('i')
    for level,kind,payload in ancillary:
        if level==socket.SOL_SOCKET and kind==socket.SCM_RIGHTS:received.frombytes(payload[:len(payload)-(len(payload)%received.itemsize)])
    # Serialized request, one bounded JSON line. Handle stream fragmentation.
    while not line.endswith(b'\n'):
        more=connection.recv(4096-len(line))
        if not more:raise RuntimeError('incomplete broker request')
        line+=more
        if len(line)>=4096:raise RuntimeError('oversized broker request')
    fd=-1
    try:
        began=time.process_time_ns();wall_began=time.monotonic_ns();job=json.loads(line)
        assert set(job)==({'child_local_pid','period','pidfd'} if job.get('pidfd') else {'child_local_pid','period'})
        assert 0<=job['period']<=2048
        if job.get('pidfd'):
            assert len(received)==1 and job['pidfd'] is True
            pid=lib.ce_validate_owned_pidfd(received[0],os.fsencode(cgroup),inode,parent,job['child_local_pid'])
            if pid<=0:raise OSError(ctypes.get_errno(),f'owned pidfd validation stage {pid}')
            if '--self-test' in sys.argv and not selftested:
                matches=[(p,s) for p,s in identities() if int(s['PPid'])==parent and int(s['NSpid'].split()[-1])==job['child_local_pid']]
                assert len(matches)==1 and matches[0][0]==pid
                st=matches[0][1]
                assert st['State'].strip().startswith('t') and int(st['Threads'])==1 and int(st['CapEff'].strip(),16)==0
                assert int(st['TracerPid']) in {int(t.name) for t in Path(f'/proc/{parent}/task').iterdir()}
                args=Path(f'/proc/{pid}/cmdline').read_bytes().split(b'\0');exe=Path(args[0].decode())
                assert exe.name=='worker' and exe.parent.parent==Path('/code') and exe.parent.name.startswith('..20')
                tests={}
                for label,fdarg,cgarg,inoarg,pparg,localarg in [
                    ('wrong_inode',received[0],os.fsencode(cgroup),inode+1,parent,job['child_local_pid']),
                    ('wrong_parent',received[0],os.fsencode(cgroup),inode,parent+1,job['child_local_pid']),
                    ('wrong_local_pid',received[0],os.fsencode(cgroup),inode,parent,job['child_local_pid']+1),
                    ('non_pidfd',-1,os.fsencode(cgroup),inode,parent,job['child_local_pid']),
                    ('wrong_cgroup',received[0],b'/sys/fs/cgroup',inode,parent,job['child_local_pid'])]:
                    value=lib.ce_validate_owned_pidfd(fdarg,cgarg,inoarg,pparg,localarg);assert value<0;tests[label]=value
                print(json.dumps({'validation_selftest':True,'same_pid_as_original':pid,'rejected':tests}),file=sys.stderr,flush=True)
                selftested=True
        else:
            assert len(received)==0
            children=[(pid,status) for pid,status in identities() if int(status['PPid'])==parent and int(status['NSpid'].split()[-1])==job['child_local_pid']]
            assert len(children)==1,children
            pid,status=children[0]
        if not job.get('pidfd'):
            assert status['State'].strip().startswith('t'),status['State']
            assert int(status['Threads'])==1 and int(status['CapEff'].strip(),16)==0
            args=Path(f'/proc/{pid}/cmdline').read_bytes().split(b'\0')
            tracer_threads={int(t.name) for t in Path(f'/proc/{parent}/task').iterdir()}
            executable=Path(args[0].decode())
            assert executable.name=='worker' and executable.parent.parent==Path('/code') and executable.parent.name.startswith('..20'),'owned child executable argv differs'
            assert int(status['TracerPid']) in tracer_threads,'tracer is not an owned supervisor thread'
        validated=time.monotonic_ns()
        fd=lib.ce_perf_open(pid,symbols['ce_body'],job['period'])
        if fd<0:raise OSError(ctypes.get_errno(),'owned cgroup child perf open')
        result={'parent_host_pid':parent,'child_host_pid':pid,'child_local_pid':job['child_local_pid'],
                'pod_uid':pod_uid,'container_id':container_id,'cgroup_inode':inode,
                'worker_sha256':expected_worker_sha,'event_address':symbols['ce_body'],'broker_cpu_ns':time.process_time_ns()-began}
        result['validation_backend']='native_pidfd' if job.get('pidfd') else 'python_cgroup_scan'
        result['broker_stages_ns']={'validation':validated-wall_began,'perf_open':time.monotonic_ns()-validated}
        result['identity_basis']='immutable experiment ConfigMap and argv, direct parent, TracerPid, exact Pod/container cgroup; no external process-memory read'
        connection.sendmsg([json.dumps(result).encode()],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',[fd]))])
    except Exception as e:
        print(json.dumps({'error':str(e),'type':type(e).__name__}),file=sys.stderr,flush=True)
        connection.sendall(json.dumps({'error':str(e)}).encode())
    finally:
        if fd>=0:os.close(fd)
        for received_fd in received:os.close(received_fd)
