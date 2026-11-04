"""Owned-child debugger and kernel-breakpoint observers; no global event."""
import ctypes
import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import signal
import struct
import subprocess
import time

from detector import bounds, verdicts

ROOT=Path(__file__).resolve().parent
SYMBOLS=json.loads((ROOT/'symbols.json').read_text())
MASK=(1<<64)-1
LIB=ctypes.CDLL(None,use_errno=True)
LIB.ptrace.argtypes=(ctypes.c_uint,ctypes.c_uint,ctypes.c_void_p,ctypes.c_void_p)
LIB.ptrace.restype=ctypes.c_long
PERF=ctypes.CDLL(str(ROOT/'perf_bridge.so'),use_errno=True)
PERF.ce_perf_open.argtypes=(ctypes.c_int,ctypes.c_uint64,ctypes.c_uint64)
PERF.ce_perf_period.argtypes=(ctypes.c_int,ctypes.c_uint64)
REG_NAMES='r15 r14 r13 r12 rbp rbx r11 r10 r9 r8 rax rcx rdx rsi rdi orig_rax rip cs eflags rsp ss fs_base gs_base ds es fs gs'.split()
class Registers(ctypes.Structure):_fields_=[(n,ctypes.c_uint64) for n in REG_NAMES]

class FastContext(ctypes.Structure):
    _fields_=[('key',ctypes.c_ubyte*32),('request',ctypes.c_uint64*7),('numerator',ctypes.c_uint64),('next_tick',ctypes.c_uint64),('period',ctypes.c_uint64),('updates',ctypes.c_uint64),('skips',ctypes.c_uint64),('base',ctypes.c_void_p),('work',ctypes.c_void_p)]
class FastRecord(ctypes.Structure):
    _fields_=[('kind',ctypes.c_uint64),('value',ctypes.c_uint64*5),('rip',ctypes.c_uint64),('body',ctypes.c_uint64*3),('relative_ns',ctypes.c_uint64),('flags',ctypes.c_uint64),('control',ctypes.c_uint64*3)]

class FastSample(ctypes.Structure):
    _fields_=[('snapshot',ctypes.c_uint64*5)]+[(n,ctypes.c_uint64) for n in ('rip','counter','enabled','running','relative_ns','flags')]
FAST=ctypes.CDLL(str(ROOT/'sample_fast.so'),use_errno=True)
FAST.ce_run_until_control.argtypes=(ctypes.c_int,ctypes.c_int,ctypes.c_uint64,ctypes.c_uint64,ctypes.c_uint64,ctypes.POINTER(FastContext),ctypes.POINTER(Registers),ctypes.POINTER(FastSample),ctypes.POINTER(ctypes.c_uint64))
FAST.ce_run_fused.argtypes=(ctypes.c_int,ctypes.c_int,ctypes.c_int,ctypes.c_uint64,ctypes.c_uint64,ctypes.c_uint64,ctypes.c_uint64,ctypes.c_uint64,ctypes.POINTER(FastContext),ctypes.POINTER(Registers),ctypes.POINTER(FastRecord),ctypes.POINTER(ctypes.c_uint64))
FAST.ce_draw.argtypes=(ctypes.c_void_p,ctypes.c_uint64,ctypes.POINTER(ctypes.c_uint64))
FAST.ce_cached_draw.argtypes=(ctypes.POINTER(FastContext),ctypes.c_uint64,ctypes.POINTER(ctypes.c_uint64))
FAST.ce_sampler_prepare.argtypes=(ctypes.POINTER(FastContext),)
FAST.ce_sampler_free.argtypes=(ctypes.POINTER(FastContext),)
FAST.ce_sampler_next.argtypes=(ctypes.POINTER(FastContext),ctypes.c_uint64)

def ptrace(op,pid,address=0,data=0):
    ctypes.set_errno(0);result=LIB.ptrace(op,pid,address,data)
    if result==-1 and ctypes.get_errno():raise OSError(ctypes.get_errno(),f'ptrace {op} owned {pid}')
    return result

def peek(pid,address,size):
    return b''.join((ptrace(2,pid,address+k)&MASK).to_bytes(8,'little') for k in range(0,size,8))[:size]

class IOVec(ctypes.Structure):
    _fields_=[('base',ctypes.c_void_p),('length',ctypes.c_size_t)]
LIB.process_vm_readv.argtypes=(ctypes.c_int,ctypes.POINTER(IOVec),ctypes.c_ulong,ctypes.POINTER(IOVec),ctypes.c_ulong,ctypes.c_ulong)
LIB.process_vm_readv.restype=ctypes.c_ssize_t

def read_memory(pid,address,size):
    # Same stopped owned child and bytes as PEEKDATA, one syscall. Fail closed.
    buf=ctypes.create_string_buffer(size)
    local=IOVec(ctypes.addressof(buf),size);remote=IOVec(address,size)
    ctypes.set_errno(0)
    n=LIB.process_vm_readv(pid,ctypes.byref(local),1,ctypes.byref(remote),1,0)
    if n!=size:raise OSError(ctypes.get_errno(),f'owned child read {n}/{size}')
    return buf.raw

def poke(pid,address,payload):
    assert len(payload)%8==0
    for k in range(0,len(payload),8):ptrace(5,pid,address+k,int.from_bytes(payload[k:k+8],'little'))

def registers(pid):
    r=Registers();ptrace(12,pid,data=ctypes.addressof(r));return r

def stopped(pid,expected=None):
    _,s=os.waitpid(pid,0)
    if not os.WIFSTOPPED(s):raise RuntimeError(f'expected owned child stop: {s}')
    sig=os.WSTOPSIG(s)
    if expected is not None and sig!=expected:raise RuntimeError(f'expected signal {expected}, got {sig}')
    return sig

def sample_draw(key,tick):
    return int.from_bytes(hmac.new(key,b'body'+tick.to_bytes(8,'little'),hashlib.sha256).digest()[:8],'little')

def next_selected(key,start,threshold):
    return next((t for t in range(start,512) if sample_draw(key,t)<threshold),start+1024)

def counter(fd):
    data=os.read(fd,24)
    if len(data)!=24:raise RuntimeError('perf read length')
    return struct.unpack('<3Q',data)

def set_period(fd,period):
    ctypes.set_errno(0)
    if PERF.ce_perf_period(fd,period):raise OSError(ctypes.get_errno(),'perf period')

class Injector:
    def __init__(self,scenario,request,path):
        self.scenario=scenario;self.left=scenario['extra'] if scenario else 0
        bs=bounds(request,path);self.task=(len(bs)-1 if scenario and scenario['position']=='late' else 0)
        self.limit=bs[self.task];self.active=False;self.finished=False
        self.past_selected=False

    def head(self,state):
        out=list(state)
        if not self.scenario or state[0]!=self.task or self.finished:return out
        if self.scenario['family']=='rewind':
            if self.scenario.get('adaptive')=='past_sample_stop' and self.active and self.past_selected:
                self.finished=True;return out
            if state[1]==1 and self.left:
                if not self.active:self.active=True;self.past_selected=False
                out[1]=0;self.left-=1
                if not self.left:self.finished=True
        elif self.scenario['family']=='inflate_bound':
            if not self.active and state[1]==self.limit:
                self.active=True;out[2]=self.limit+1;self.left-=1
            elif self.active and state[1]==self.limit+1:
                out[1]=self.limit
                if self.left:self.left-=1
                else:out[2]=self.limit;self.finished=True
        else:raise ValueError('unknown lab fault')
        return out

def execute(request,scenario=None,backend='kernel',p_numerator=95,cpu=19,audit=True,recover=False):
    """Sampler input: public request + selected state only. Injector is lab-only."""
    if backend=='untraced' and scenario:raise ValueError('untraced injection not implemented')
    if backend not in ('kernel','debugger','boundary','count_end','untraced'):raise ValueError('backend')
    request={k:request[k] for k in ('workload','passes','seed','values','runtime_paths','wait_ms')}
    row={'request':request,'scenario':scenario,'backend':backend,'p_numerator':p_numerator,
         'events':[],'samples':[],'alarms':{},'audit':audit,'terminated':False}
    wall_start=time.monotonic_ns();parent_start=time.thread_time_ns()
    key=secrets.token_bytes(32) if backend in ('kernel','debugger') else None
    threshold=(p_numerator*(1<<64))//100
    next_tick=None
    row['sample_key_hex']=key.hex() if key is not None else None;row['sample_threshold']=str(threshold)
    if backend=='kernel':
        native=FastContext();native.key[:]=key
        native.request[:]=[request['workload'],request['passes'],request['seed'],*request['values'],request['runtime_paths'],request['wait_ms']]
        native.numerator=p_numerator
        native_regs=Registers();native_samples=(FastRecord*64)();native_used=ctypes.c_uint64()
        if FAST.ce_sampler_prepare(ctypes.byref(native)):raise OSError(ctypes.get_errno(),'native HMAC setup')
        next_tick=native.next_tick
    command=[str(ROOT/'worker'),str(int(backend!='untraced')),str(cpu),str(request['workload']),
             str(request['passes']),str(request['seed']),*map(str,request['values']),
             str(request['runtime_paths']),str(request['wait_ms'])]
    try:process=subprocess.Popen(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    except Exception:
        if backend=='kernel':FAST.ce_sampler_free(ctypes.byref(native))
        raise
    row['owned_pid']=process.pid
    fd=-1;boundary_fds=[];pending=None;programmed_period=None;tick=0;index=0;bp={};finished=False;waited=False
    try:
        if backend=='kernel' and os.environ.get('CE_EXTERNAL_PERF')=='1':
            from perf_client import begin_fast
            pending=begin_fast(process.pid,next_tick+1)
            row['broker_request_started_before_startup_stop']=True
            row['perf_open_waits_for_startup_stop']=True
        if backend!='untraced':
            stopped(process.pid,signal.SIGSTOP);ptrace(0x4200,process.pid,data=0x100000)
            if pending is not None:pending.commit()
            expected=struct.pack('<7Q',request['workload'],request['passes'],request['seed'],*request['values'],request['runtime_paths'],request['wait_ms'])
            header=read_memory(process.pid,SYMBOLS['ce_request'],56)
            if header!=expected:raise RuntimeError('original request mismatch')
            row['header_hex']=header.hex()
            initial=list(struct.unpack('<5Q',read_memory(process.pid,SYMBOLS['ce_state'],40)))
            row['initial_state']=initial
            injector=Injector(scenario,request,initial[4])
            names=[] if backend=='kernel' else ['ce_done','ce_taskdone']
            if audit or scenario:names.append('ce_head')
            if backend=='debugger':names.append('ce_body')
            assert all(abs(SYMBOLS[a]-SYMBOLS[b])>=8 for i,a in enumerate(names) for b in names[i+1:])
            for name in names:
                addr=SYMBOLS[name];current=int.from_bytes(peek(process.pid,addr,8),'little')
                bp[addr]=(name,current)
                ptrace(4,process.pid,addr,(current&~255)|0xcc)
            if backend in ('kernel','count_end'):
                period=next_tick+1 if backend=='kernel' else 0
                if os.environ.get('CE_EXTERNAL_PERF')=='1':
                    if pending is not None:fd,row['perf_broker'],boundary_fds=pending.finish()
                    else:
                        from perf_client import open_owned
                        fd,row['perf_broker']=open_owned(process.pid,period,fast=True)
                else:fd=PERF.ce_perf_open(process.pid,SYMBOLS['ce_body'],period)
                if fd<0:raise OSError(ctypes.get_errno(),'owned child perf breakpoint')
                if not (backend=='kernel' and row['perf_broker'].get('events_pre_enabled')):
                    if PERF.ce_perf_enable(fd):raise OSError(ctypes.get_errno(),'perf enable')
                programmed_period=period
                if backend=='kernel' and boundary_fds:
                    assert row['perf_broker']['boundary_event_addresses']==[SYMBOLS['ce_taskdone'],SYMBOLS['ce_done']]
                    for extra in boundary_fds:
                        if not row['perf_broker'].get('events_pre_enabled') and PERF.ce_perf_enable(extra):raise OSError(ctypes.get_errno(),'hardware control enable')
            ptrace(7,process.pid)
            while not finished:
                if backend=='kernel':
                    native.next_tick=next_tick;native.period=programmed_period
                    before_updates,before_skips=native.updates,native.skips
                    ctypes.set_errno(0)
                    code=FAST.ce_run_fused(process.pid,fd,boundary_fds[0],SYMBOLS['ce_body'],SYMBOLS['ce_taskdone'],SYMBOLS['ce_done'],SYMBOLS['ce_state'],wall_start,ctypes.byref(native),ctypes.byref(native_regs),native_samples,ctypes.byref(native_used))
                    if code<0:raise OSError(ctypes.get_errno(),f'native sampling loop stage {code}')
                    next_tick=native.next_tick;programmed_period=native.period
                    row['period_updates']=row.get('period_updates',0)+native.updates-before_updates
                    row['period_updates_skipped']=row.get('period_updates_skipped',0)+native.skips-before_skips
                    row['native_control_returns']=row.get('native_control_returns',0)+1
                    if native_used.value:
                        injector.past_selected|=any(native_samples[i].kind==0 for i in range(native_used.value))
                        size=native_used.value*ctypes.sizeof(FastRecord)
                        row.setdefault('native_record_chunks',[]).append({'before_control_event':len(row['events']),'data_b64':base64.b64encode(ctypes.string_at(native_samples,size)).decode()})
                        row['native_record_count']=row.get('native_record_count',0)+native_used.value
                        row['native_record_encoding']='ce-record-15u64-le-v1'
                    if code==1:
                        assert native_used.value
                        record=native_samples[native_used.value-1]
                        current_tick=record.value[4]
                        assert record.flags
                        for bit,method in enumerate(('variables','clock','combined')):
                            if record.flags&(1<<bit) and method not in row['alarms']:row['alarms'][method]={'tick':current_tick,'relative_ns':record.relative_ns}
                        if recover and record.flags&4:
                            row['terminated']=True;tick=current_tick;process.kill();finished=True;break
                        if FAST.ce_sampler_next(ctypes.byref(native),current_tick+1):raise OSError(ctypes.get_errno(),'native HMAC next')
                        next_tick=native.next_tick
                        new_period=next_tick-current_tick
                        if new_period!=programmed_period:
                            set_period(fd,new_period);programmed_period=new_period
                            row['period_updates']+=1
                        else:row['period_updates_skipped']+=1
                        ptrace(7,process.pid)
                        continue
                    if code==3:
                        ptrace(7,process.pid)
                        continue
                    if code==2:
                        record=native_samples[native_used.value-1]
                        assert record.kind==1 and record.flags
                        if 'boundary' not in row['alarms']:row['alarms']['boundary']={'tick':record.body[0],'relative_ns':record.relative_ns}
                        ptrace(7,process.pid)
                        continue
                    assert code==0
                    r=native_regs
                else:
                    sig=stopped(process.pid,signal.SIGTRAP)
                    r=registers(process.pid)
                hardware_control=backend=='kernel' and r.rip in (SYMBOLS['ce_taskdone'],SYMBOLS['ce_done'])
                if hardware_control:
                    name='ce_taskdone' if r.rip==SYMBOLS['ce_taskdone'] else 'ce_done'
                    addr=r.rip;original=None
                    control_fd=boundary_fds[0 if name=='ce_taskdone' else 1]
                    control_counter=counter(control_fd)
                    if control_counter[1]!=control_counter[2]:raise RuntimeError('hardware control multiplexed')
                    row['hardware_control_stops']=row.get('hardware_control_stops',0)+1
                else:
                    addr=r.rip-1
                    if addr not in bp:raise RuntimeError(f'unexpected trap ip {r.rip:x}')
                    name,original=bp[addr]
                    ptrace(4,process.pid,addr,original)
                    r.rip=addr;ptrace(13,process.pid,data=ctypes.addressof(r))
                if fd>=0:
                    final_counter=counter(fd);hits=final_counter[0]
                else:hits=tick
                selected=sample_draw(key,tick)<threshold if name=='ce_body' else False
                state=list(struct.unpack('<5Q',read_memory(process.pid,SYMBOLS['ce_state'],40))) if name!='ce_body' or audit or selected else None
                if name=='ce_head':
                    changed=injector.head(state)
                    if changed!=state:poke(process.pid,SYMBOLS['ce_state'],struct.pack('<5Q',*changed))
                    row['events'].append({'kind':'head','before':state,'after':changed,'counter':hits,'relative_ns':time.monotonic_ns()-wall_start})
                elif name=='ce_body':
                    snapshot=state[:3]+[state[4],tick] if state is not None else None
                    if audit:row['events'].append({'kind':'body','snapshot':snapshot,'selected':selected,'raw_rip':addr+1})
                    if selected:
                        injector.past_selected=True
                        row['samples'].append(snapshot)
                        for method,bad in verdicts(request,snapshot).items():
                            if bad and method not in row['alarms']:row['alarms'][method]={'tick':tick,'relative_ns':time.monotonic_ns()-wall_start}
                        if recover and verdicts(request,snapshot)['combined']:
                            row['terminated']=True;process.kill();finished=True;break
                    tick+=1
                elif name=='ce_taskdone':
                    bs=bounds(request,state[4]);bad=state[0]>=len(bs) or state[1]!=bs[state[0]] or state[2]!=bs[state[0]]
                    row['events'].append({'kind':'boundary','state':state,'counter':hits,'bad':bad,**({'hook_kind':'hardware','raw_rip':r.rip,'control_counter':list(control_counter)} if hardware_control else {})})
                    if hardware_control and control_counter[0]!=state[0]+1:raise RuntimeError('hardware task count differs')
                    if bad and 'boundary' not in row['alarms']:row['alarms']['boundary']={'tick':hits,'relative_ns':time.monotonic_ns()-wall_start}
                else:
                    if hardware_control:
                        if control_counter[0]!=1:raise RuntimeError('terminal hardware count differs')
                        row['terminal_hook']={'raw_rip':r.rip,'counter':list(control_counter)}
                    row['done_state']=list(state);row['final_header_hex']=read_memory(process.pid,SYMBOLS['ce_request'],56).hex()
                    if row['final_header_hex']!=row['header_hex']:raise RuntimeError('request modified')
                    if fd>=0:row['perf_final']=list(final_counter);tick=row['perf_final'][0]
                    if backend=='count_end' and tick!=sum(bounds(request,state[4])):
                        row['alarms']['count_end']={'tick':tick,'relative_ns':time.monotonic_ns()-wall_start}
                    finished=True
                if hardware_control:
                    ptrace(7,process.pid)
                    continue
                if name=='ce_done':
                    # One-shot terminal hook: restore and resume the original instruction.
                    # It is never reached again in this immutable worker.
                    ptrace(7,process.pid)
                    row['terminal_single_step_skipped']=True
                    continue
                ptrace(9,process.pid);stopped(process.pid,signal.SIGTRAP)
                ptrace(4,process.pid,addr,(original&~255)|0xcc)
                row['single_steps']=row.get('single_steps',0)+1
                ptrace(7,process.pid)
                if time.monotonic_ns()-wall_start>25_000_000_000 or hits>500:raise RuntimeError('bounded fixture limit')
        _,status,usage=os.wait4(process.pid,0);waited=True
        process.returncode=os.waitstatus_to_exitcode(status)
        output=process.stdout.read().decode();stderr=process.stderr.read().decode()
        row['exitcode']=process.returncode;row['stderr']=stderr
        row['worker_cpu_ns']=round((usage.ru_utime+usage.ru_stime)*1e9)
        row['worker_maxrss_kib']=usage.ru_maxrss
        row['body_count']=tick
        if not row['terminated']:
            if process.returncode!=0:raise RuntimeError(f'worker exit {process.returncode} {stderr}')
            row['reply']=json.loads(output)
        else:
            if process.returncode!=-signal.SIGKILL:raise RuntimeError('termination did not complete')
            row['reply']=None
    finally:
        if backend=='kernel':FAST.ce_sampler_free(ctypes.byref(native))
        if pending is not None:pending.close()
        if fd>=0:os.close(fd)
        for extra in boundary_fds:os.close(extra)
        if not waited:
            try:process.kill()
            except ProcessLookupError:pass
            process.wait()
        process.stdout.close();process.stderr.close()
    row['wall_ns']=time.monotonic_ns()-wall_start
    row['controller_cpu_ns']=time.thread_time_ns()-parent_start
    row['owned_pid_absent']=not Path(f'/proc/{process.pid}').exists()
    return row
