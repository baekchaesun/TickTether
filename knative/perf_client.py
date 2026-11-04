"""Receive a single owned-worker perf FD; function gets no perf capability."""
import array
import json
import os
import socket
import threading

LOCK=threading.Lock()
READY=threading.Event()
CONNECTION=None
SOCKET_PATH='/tmp/ce-perf.sock'

def _listen():
    global CONNECTION
    listener=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
    listener.bind(SOCKET_PATH);os.chmod(SOCKET_PATH,0o600);listener.listen(1)
    while True:
        connection,_=listener.accept()
        with LOCK:
            if CONNECTION is not None:CONNECTION.close()
            CONNECTION=connection;READY.set();CONNECTION.sendall(b'ready\n')

if os.environ.get('CE_EXTERNAL_PERF')=='1':
    threading.Thread(target=_listen,daemon=True).start()

def open_owned(pid,period,fast=False):
    if not READY.wait(10):raise RuntimeError('owned-worker host perf broker not connected')
    with LOCK:
        job={'child_local_pid':pid,'period':period}
        if fast:
            pidfd=os.pidfd_open(pid,0)
            try:
                job['pidfd']=True
                CONNECTION.sendmsg([(json.dumps(job)+'\n').encode()],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',[pidfd]))])
            finally:os.close(pidfd)
        else:CONNECTION.sendall((json.dumps(job)+'\n').encode())
        data,ancillary,flags,address=CONNECTION.recvmsg(4096,socket.CMSG_SPACE(4))
        result=json.loads(data)
        if 'error' in result:raise RuntimeError(result['error'])
        fds=array.array('i')
        for level,kind,payload in ancillary:
            if level==socket.SOL_SOCKET and kind==socket.SCM_RIGHTS:fds.frombytes(payload[:len(payload)-(len(payload)%fds.itemsize)])
        if len(fds)!=1:raise RuntimeError('exactly one owned-worker event FD required')
        os.set_inheritable(fds[0],False)
        return fds[0],result

# Separate channel lets the exact previous kernel coexist with the new native
# broker in the same Pod/revision; both helper cgroups are metered on every call.
import struct
FAST_LOCK=threading.Lock()
FAST_READY=threading.Event()
FAST_CONNECTION=None
FAST_META=None

def _listen_fast():
    global FAST_CONNECTION,FAST_META
    listener=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
    listener.bind('/tmp/ce-fast.sock');os.chmod('/tmp/ce-fast.sock',0o600);listener.listen(1)
    while True:
        connection,_=listener.accept();connection.settimeout(10)
        with FAST_LOCK:
            if FAST_CONNECTION is not None:FAST_CONNECTION.close()
            connection.sendall(b'ready\n')
            data=b''
            while not data.endswith(b'\n'):
                block=connection.recv(4096-len(data))
                if not block:raise RuntimeError('native metadata handshake EOF')
                data+=block
                if len(data)>=4096:raise RuntimeError('native metadata too large')
            meta=json.loads(data);assert meta['ready']
            FAST_CONNECTION=connection;FAST_META=meta;FAST_READY.set()

class PendingFast:
    def __init__(self,pid):self.pid=pid;self.finished=False;self.committed=False
    def commit(self):
        if not self.committed:
            FAST_CONNECTION.sendall(b'C');self.committed=True
    def finish(self):
        if self.finished:raise RuntimeError('native reply already consumed')
        fds=array.array('i')
        try:
            self.commit()
            data,ancillary,flags,_=FAST_CONNECTION.recvmsg(64,socket.CMSG_SPACE(12),socket.MSG_CMSG_CLOEXEC)
            for level,kind,payload in ancillary:
                if level==socket.SOL_SOCKET and kind==socket.SCM_RIGHTS:fds.frombytes(payload[:len(payload)-(len(payload)%fds.itemsize)])
            if flags&socket.MSG_CTRUNC:raise RuntimeError('native FD truncated')
            while len(data)<64:
                block=FAST_CONNECTION.recv(64-len(data))
                if not block:raise RuntimeError('native reply EOF')
                data+=block
            error,pid,validation,opened,cpu,reserved,commit_wait,registration_setup=struct.unpack('<8q',data)
            if error:raise OSError(-error,'native owned-child broker')
            if len(fds)!=3 or reserved!=0:raise RuntimeError('native reply invalid')
            result={**FAST_META,'child_host_pid':pid,'child_local_pid':self.pid,'broker_cpu_ns':cpu,
                    'broker_stages_ns':{'validation':validation,'perf_open':opened,'waiting_commit':commit_wait,'self_registration_setup':registration_setup},
                    'identity_basis':'pidfd kernel PID/cgroup ID; same stopped direct child, NSpid, zero capabilities, one thread, owned tracer and fixed code path'}
            returned=list(fds);fds=array.array('i');return returned[0],result,returned[1:]
        finally:
            for fd in fds:os.close(fd)
            self.finished=True;FAST_LOCK.release()
    def close(self):
        if not self.finished:
            try:
                fd,_,extras=self.finish();os.close(fd)
                for extra in extras:os.close(extra)
            except Exception:pass

def begin_fast(pid,period):
    if not FAST_READY.wait(10):raise RuntimeError('native owned-child broker not ready')
    FAST_LOCK.acquire()
    try:
        pidfd=os.pidfd_open(pid,0)
        try:
            sent=FAST_CONNECTION.sendmsg([struct.pack('<3Q',pid,period,1)],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',[pidfd]))])
            if sent!=24:raise RuntimeError('native request truncated')
        finally:os.close(pidfd)
        return PendingFast(pid)
    except Exception:
        FAST_LOCK.release();raise

if os.environ.get('CE_EXTERNAL_PERF')=='1':threading.Thread(target=_listen_fast,daemon=True).start()
