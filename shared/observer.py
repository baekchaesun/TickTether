"""SP1: own-child software breakpoints; no perf, broker, Kubernetes or cloud."""
import ctypes,hashlib,hmac,json,os,secrets,signal,struct,subprocess,time
from pathlib import Path
try:
    from .detector import bounds,verdicts
except ImportError:
    from detector import bounds,verdicts
ROOT=Path(__file__).resolve().parent
ALLOWED_CPUS=os.sched_getaffinity(0)
MASK=(1<<64)-1
LIB=ctypes.CDLL(None,use_errno=True)
LIB.ptrace.argtypes=(ctypes.c_uint,ctypes.c_uint,ctypes.c_void_p,ctypes.c_void_p)
LIB.ptrace.restype=ctypes.c_long
REG_NAMES='r15 r14 r13 r12 rbp rbx r11 r10 r9 r8 rax rcx rdx rsi rdi orig_rax rip cs eflags rsp ss fs_base gs_base ds es fs gs'.split()
class Registers(ctypes.Structure):_fields_=[(n,ctypes.c_uint64) for n in REG_NAMES]

def ptrace(op,pid,address=0,data=0):
    ctypes.set_errno(0);result=LIB.ptrace(op,pid,address,data)
    if result==-1 and ctypes.get_errno():raise OSError(ctypes.get_errno(),f'ptrace {op} owned {pid}')
    return result

def peek(pid,address,size):
    return b''.join((ptrace(2,pid,address+k)&MASK).to_bytes(8,'little') for k in range(0,size,8))[:size]

class IOVec(ctypes.Structure):
    _fields_=[('base',ctypes.c_void_p),('length',ctypes.c_size_t)]

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

def sample_draw(key,tick):
    return int.from_bytes(hmac.new(key,b'body'+tick.to_bytes(8,'little'),hashlib.sha256).digest()[:8],'little')

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
LIB.process_vm_readv.argtypes=(ctypes.c_int,ctypes.POINTER(IOVec),ctypes.c_ulong,ctypes.POINTER(IOVec),ctypes.c_ulong,ctypes.c_ulong)
LIB.process_vm_readv.restype=ctypes.c_ssize_t

class ObservationError(RuntimeError):
    def __init__(self, row):
        super().__init__(row.get('error', 'observation failed'))
        self.row = row

def validate_request(q):
    if set(q) != {'workload','passes','seed','values','runtime_paths','wait_ms'}:
        raise ValueError('request keys')
    if any(type(q[k]) is not int for k in ('workload','passes','seed','runtime_paths','wait_ms')):
        raise ValueError('integer request required')
    if not (0 <= q['workload'] <= 4 and 1 <= q['passes'] <= 2 and 0 <= q['seed'] < 2**63):
        raise ValueError('request range')
    if not isinstance(q['values'],list) or len(q['values'])!=2 or any(type(v) is not int or not 1<=v<=12 for v in q['values']):
        raise ValueError('bound range')
    if q['runtime_paths'] not in (0,1) or not 0<=q['wait_ms']<=100:
        raise ValueError('path/wait range')

def execute(request, scenario=None, backend='SP1', p=95, cpu=None, audit=True,
            recover=False, key_hex=None, path=None, legacy=False, asset_size='small'):
    """A trusted supervisor owns only its Popen child. Fault metadata is lab-only.

    The detector is the unchanged detector.verdicts(request, snapshot). It receives
    neither scenario nor completion ledger. All failures are errors, never TP.
    """
    validate_request(request)
    if backend not in ('SP1','O1','I1'): raise ValueError('backend')
    if legacy and (backend!='SP1' or request['workload']>2): raise ValueError('legacy scope')
    if type(p) is not int or not 0<=p<=100: raise ValueError('sampling percent')
    if path is not None and (type(path) is not int or not 0<=path<16): raise ValueError('normal path')
    if scenario:
        if set(scenario)-{'family','extra','position'}: raise ValueError('unsupported lab fault field')
        if scenario['family'] not in ('rewind','inflate_bound') or scenario['position'] not in ('early','late'):
            raise ValueError('fault family/position')
        if type(scenario['extra']) is not int or not 1<=scenario['extra']<=32: raise ValueError('bounded fault')
    allowed=ALLOWED_CPUS
    cpu=min(allowed) if cpu is None else cpu
    if cpu not in allowed: raise ValueError('CPU outside allowed affinity')
    if asset_size not in ('small','large'): raise ValueError('asset size')
    binary=ROOT/'build'/('worker_legacy' if legacy else 'worker_sp1')
    symbols=json.loads(binary.with_suffix('.symbols.json').read_text())
    key=bytes.fromhex(key_hex) if key_hex else secrets.token_bytes(32)
    if len(key)!=32: raise ValueError('32-byte sampler key')
    threshold=p*2**64//100
    row=dict(version='SP1-school-v1',request=request,scenario=scenario,backend='debugger' if legacy else backend,
             legacy=legacy,p_numerator=p,audit=audit,events=[],samples=[],alarms={},terminated=False,
             sample_key_hex=key.hex(),sample_threshold=str(threshold),asset_size=asset_size,
             worker_cpu_ns=0,worker_reaped=False,owned_pid_absent=False,trap_count=0,single_steps=0)
    wall=time.monotonic_ns();parent=time.process_time_ns();deadline=wall+25_000_000_000
    command=[str(binary),str(int(backend!='I1')),str(cpu),str(request['workload']),str(request['passes']),
             str(request['seed']),*map(str,request['values']),str(request['runtime_paths']),str(request['wait_ms'])]
    if not legacy:
        command += [str({'rewind':1,'inflate_bound':2}.get((scenario or {}).get('family'),0)),
                    str((scenario or {}).get('extra',0)),str(int((scenario or {}).get('position')=='late')),
                    str(path if path is not None else -1),str(int(audit)),str(ROOT/'assets'/asset_size)]
    # Output goes to a private regular file: an audited trace cannot deadlock a pipe.
    import tempfile
    proc=None;reaped=False;tick=0;bp={}
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        try:
            proc=subprocess.Popen(command,stdout=out,stderr=err,close_fds=True)
            row['owned_pid']=proc.pid
            def wait_stop(expected):
                nonlocal reaped
                _,status,usage=os.wait4(proc.pid,0)
                if os.WIFEXITED(status) or os.WIFSIGNALED(status):
                    reaped=True;proc.returncode=os.waitstatus_to_exitcode(status)
                    row['exitcode']=proc.returncode;row['worker_cpu_ns']=round((usage.ru_utime+usage.ru_stime)*1e9)
                if not os.WIFSTOPPED(status) or os.WSTOPSIG(status)!=expected:
                    raise RuntimeError('unexpected child status '+str(status))
                if time.monotonic_ns()>deadline: raise TimeoutError('observer deadline')
                return status
            if backend!='I1':
                wait_stop(signal.SIGSTOP)
                ptrace(0x4200,proc.pid,data=0x100000) # PTRACE_O_EXITKILL
                if Path(f'/proc/{proc.pid}/exe').resolve()!=binary.resolve(): raise RuntimeError('child executable identity')
                status=Path(f'/proc/{proc.pid}/status').read_text()
                fields=dict(line.split(':',1) for line in status.splitlines() if ':' in line)
                if int(fields['PPid'])!=os.getpid() or int(fields['TracerPid'])!=os.getpid(): raise RuntimeError('child ownership')
                if int(fields['Threads'])!=1 or int(fields['CapEff'].strip(),16): raise RuntimeError('worker trust scope')
                header=read_memory(proc.pid,symbols['ce_request'],56)
                expected=struct.pack('<7Q',request['workload'],request['passes'],request['seed'],*request['values'],request['runtime_paths'],request['wait_ms'])
                if header!=expected: raise RuntimeError('original request mismatch')
                row['header_hex']=header.hex()
                if legacy and path is not None:
                    row['original_random_path']=int.from_bytes(read_memory(proc.pid,symbols['ce_state']+32,8),'little')
                    poke(proc.pid,symbols['ce_state']+32,struct.pack('<Q',path))
                initial=list(struct.unpack('<5Q',read_memory(proc.pid,symbols['ce_state'],40)))
                row['initial_state']=initial
                injector=Injector(scenario,request,initial[4]) if legacy else None
                names=['ce_body','ce_taskdone','ce_done']
                if legacy: names.append('ce_head')
                if any(abs(symbols[a]-symbols[b])<8 for i,a in enumerate(names) for b in names[i+1:]):
                    raise RuntimeError('overlapping breakpoint words')
                for name in names:
                    addr=symbols[name];original=int.from_bytes(peek(proc.pid,addr,8),'little')
                    bp[addr]=(name,original);ptrace(4,proc.pid,addr,(original&~255)|0xcc)
                ptrace(7,proc.pid)
                while True:
                    wait_stop(signal.SIGTRAP);row['trap_count']+=1
                    regs=registers(proc.pid);addr=regs.rip-1
                    if addr not in bp: raise RuntimeError('unexpected instruction trap')
                    name,original=bp[addr];ptrace(4,proc.pid,addr,original)
                    regs.rip=addr;ptrace(13,proc.pid,data=ctypes.addressof(regs))
                    selected=name=='ce_body' and backend=='SP1' and sample_draw(key,tick)<threshold
                    need_state=name!='ce_body' or audit or selected
                    state=list(struct.unpack('<5Q',read_memory(proc.pid,symbols['ce_state'],40))) if need_state else None
                    if name=='ce_head':
                        changed=injector.head(state)
                        if changed!=state: poke(proc.pid,symbols['ce_state'],struct.pack('<5Q',*changed))
                        row['events'].append(dict(kind='head',before=state,after=changed,counter=tick))
                    elif name=='ce_body':
                        snapshot=state[:3]+[state[4],tick] if state else None
                        if audit: row['events'].append(dict(kind='body',snapshot=snapshot,selected=selected,raw_rip=addr+1))
                        bad={}
                        if selected:
                            if injector: injector.past_selected=True
                            row['samples'].append(snapshot);bad=verdicts(request,snapshot)
                        elif backend=='O1':
                            bad={'online_count':tick>=sum(bounds(request,initial[4]))}
                        for method,value in bad.items():
                            if value and method not in row['alarms']:
                                row['alarms'][method]=dict(tick=tick,relative_ns=time.monotonic_ns()-wall)
                        if recover and bad.get('combined' if backend=='SP1' else 'online_count',False):
                            row['terminated']=True;proc.kill();break
                        tick+=1
                    elif name=='ce_taskdone':
                        bs=bounds(request,state[4]);bad=state[0]>=len(bs) or state[1]!=bs[state[0]] or state[2]!=bs[state[0]]
                        row['events'].append(dict(kind='boundary',state=state,counter=tick,bad=bad))
                        if bad and 'boundary' not in row['alarms']:
                            row['alarms']['boundary']=dict(tick=tick,relative_ns=time.monotonic_ns()-wall)
                    else:
                        row['done_state']=state
                        row['final_header_hex']=read_memory(proc.pid,symbols['ce_request'],56).hex()
                        if row['final_header_hex']!=row['header_hex']: raise RuntimeError('request changed')
                        ptrace(7,proc.pid);break
                    ptrace(9,proc.pid);wait_stop(signal.SIGTRAP)
                    row['single_steps']+=1;row['trap_count']+=1
                    ptrace(4,proc.pid,addr,(original&~255)|0xcc);ptrace(7,proc.pid)
                    if tick>256: raise RuntimeError('bounded execution exceeded')
            _,status,usage=os.wait4(proc.pid,0);reaped=True
            proc.returncode=os.waitstatus_to_exitcode(status)
            row['exitcode']=proc.returncode
            row['worker_cpu_ns']=round((usage.ru_utime+usage.ru_stime)*1e9)
            row['worker_maxrss_kib']=usage.ru_maxrss
            out.seek(0);err.seek(0);output=out.read().decode();row['stderr']=err.read().decode()
            if row['terminated']:
                if proc.returncode!=-signal.SIGKILL: raise RuntimeError('termination failed')
                row['reply']=None
            else:
                if proc.returncode!=0: raise RuntimeError('worker exit '+str(proc.returncode))
                row['reply']=json.loads(output)
            row['body_count']=tick if backend!='I1' else row['reply']['completed']
        except BaseException as exc:
            row['error']=type(exc).__name__+': '+str(exc)
        finally:
            if proc is not None and not reaped:
                try: proc.kill()
                except ProcessLookupError: pass
                try:
                    _,status,usage=os.wait4(proc.pid,0);reaped=True
                    proc.returncode=os.waitstatus_to_exitcode(status)
                    row['exitcode']=proc.returncode;row['worker_cpu_ns']=round((usage.ru_utime+usage.ru_stime)*1e9)
                except ChildProcessError: pass
            row['worker_reaped']=reaped
            row['owned_pid_absent']=proc is not None and not Path(f'/proc/{proc.pid}').exists()
            if 'error' in row:
                err.seek(0);row['stderr']=err.read().decode(errors='replace')
            row['wall_ns']=time.monotonic_ns()-wall
            row['controller_cpu_ns']=time.process_time_ns()-parent
    if 'error' in row: raise ObservationError(row)
    return row
