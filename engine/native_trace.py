"""Own-child x86-64 synchronous store witnesses. No application computation."""
import ctypes
import errno
import os
import signal
import struct

libc=ctypes.CDLL(None,use_errno=True)
libc.ptrace.argtypes=(ctypes.c_uint,ctypes.c_int,ctypes.c_void_p,ctypes.c_void_p);libc.ptrace.restype=ctypes.c_long
TRACEME=0;PEEKDATA=2;PEEKUSER=3;POKEUSER=6;CONT=7;GETREGS=12;GETSIGINFO=0x4202;SETOPTIONS=0x4200
DR_OFFSET=848;WALL=0x40000000
TRACE_SYSCALLS=False

class IOVec(ctypes.Structure):
    _fields_=[('base',ctypes.c_void_p),('length',ctypes.c_size_t)]
libc.process_vm_readv.argtypes=(ctypes.c_int,ctypes.POINTER(IOVec),ctypes.c_ulong,ctypes.POINTER(IOVec),ctypes.c_ulong,ctypes.c_ulong)
libc.process_vm_readv.restype=ctypes.c_ssize_t


def ptrace(request,pid,address=0,data=0):
    ctypes.set_errno(0)
    value=libc.ptrace(request,pid,ctypes.c_void_p(address),ctypes.c_void_p(data))
    e=ctypes.get_errno()
    if value==-1 and e:raise OSError(e,os.strerror(e))
    return value


READ_CAPTURE=None

def mark_object(pointer):
    if READ_CAPTURE is not None:READ_CAPTURE['objects'].add(pointer)

def read(pid,address,length):
    if length==0:return b''
    buf=ctypes.create_string_buffer(length);local=IOVec(ctypes.addressof(buf),length);remote=IOVec(address,length)
    n=libc.process_vm_readv(pid,ctypes.byref(local),1,ctypes.byref(remote),1,0)
    if n!=length:raise OSError(ctypes.get_errno(),f'remote read {address:x}: {n}/{length}')
    raw=buf.raw
    if READ_CAPTURE is not None:READ_CAPTURE['reads'].append((address,raw))
    return raw


def registers(pid):
    regs=(ctypes.c_ulonglong*27)();ptrace(GETREGS,pid,0,ctypes.addressof(regs));return dict(rip=regs[16],rsp=regs[19],rax=regs[10])


def info(pid):
    buf=ctypes.create_string_buffer(128);ptrace(GETSIGINFO,pid,0,ctypes.addressof(buf));signo,err,code=struct.unpack('<iii',buf.raw[:12]);return dict(signal=signo,code=code)


def arm(pid,addresses):
    if len(addresses)>3:raise ValueError('three hardware slots maximum')
    ptrace(POKEUSER,pid,DR_OFFSET+7*8,0)
    for i in range(3):ptrace(POKEUSER,pid,DR_OFFSET+i*8,addresses[i] if i<len(addresses) else 0)
    ptrace(POKEUSER,pid,DR_OFFSET+6*8,0)
    control=sum((1<<(2*i)) | (9<<(16+4*i)) for i in range(len(addresses)))
    ptrace(POKEUSER,pid,DR_OFFSET+7*8,control)


def traceme_stop():
    ptrace(TRACEME,0);os.kill(os.getpid(),signal.SIGSTOP)


def resume(pid,signum=0):ptrace(24 if TRACE_SYSCALLS else CONT,pid,0,signum)

if __name__=='__main__':
    import json
    r,w=os.pipe();pid=os.fork()
    if pid==0:
        os.close(r);cell=ctypes.c_ulonglong(0);os.write(w,str(ctypes.addressof(cell)).encode()+b'\n');os.close(w)
        traceme_stop();cell.value=123456;os._exit(0)
    os.close(w);address=int(os.read(r,128));os.close(r);_,status=os.waitpid(pid,0)
    assert os.WIFSTOPPED(status);arm(pid,[address]);resume(pid)
    _,status=os.waitpid(pid,0);assert os.WIFSTOPPED(status) and os.WSTOPSIG(status)==signal.SIGTRAP
    record=dict(address=address,value=struct.unpack('<Q',read(pid,address,8))[0],registers=registers(pid),siginfo=info(pid))
    arm(pid,[]);resume(pid);_,status=os.waitpid(pid,0);assert os.WIFEXITED(status)
    print(json.dumps(record,indent=2))
