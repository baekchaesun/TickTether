"""External first-execution native-result receipts; no source or arithmetic replay."""
import collections
import gzip
import hashlib
import json
import multiprocessing.connection
import os
from pathlib import Path
import signal
import resource
import struct
import subprocess
import sys
import time
import zlib
from monitor import Monitor
import native_trace as nt
from value_decode import value
from native_store import pointer_store_ends
from heap_invariant import certificate as heap_certificate,snapshot as heap_snapshot,UnsupportedGraph
from heap_invariant import SAFE
from effects import MUTATORS,READ_METHODS,DISPATCH
from creation import ListAppendLease
from retirement import RetirementLease
from readplan import capture_snapshot
from origin_gate import Gate,OriginBlocked

HERE=Path(__file__).resolve().parent

def u64(pid,p):return struct.unpack('<Q',nt.read(pid,p,8))[0]

class SufficientExtraWork(RuntimeError):pass

class NativeReceipts:
    def __init__(self,pid,monitor,log):
        self.pid=pid;self.monitor=monitor;self.log=log;self.types={};self.tstate=0
        self.seals={};self.frames={};self.targets=[];self.owner=0;self.lease={}
        self.pending=[];self.counts=collections.Counter();self.gaps=collections.Counter()
        self.runtime_ranges=[];self.leases={};self.last_lease={};self.current_lease=None;self.store_sites=None;self.readonly={};self.cell_expected={};self.pure=set()
        executable=os.readlink(f'/proc/{pid}/exe')
        self.executable=executable
        self.runtime_sha256=hashlib.sha256(Path(executable).read_bytes()).hexdigest()
        for line in Path(f'/proc/{pid}/maps').read_text().splitlines():
            fields=line.split()
            if len(fields)>=6 and 'x' in fields[1] and fields[-1]==executable:
                self.runtime_ranges.append(tuple(int(v,16) for v in fields[0].split('-')))
    def record(self,e):self.log.write(json.dumps(e,ensure_ascii=False,separators=(',',':'))+'\n')
    def revoke(self,frame,reason):
        if frame in self.readonly:
            self.readonly.pop(frame);self.gaps['unsupported_heap_effect_frontier']+=1
            self.record(dict(kind='heap_revocation',frame_id=frame,reason=reason))
    def commit(self,frame,reason):
        if frame not in self.readonly:return
        guard=self.readonly[frame]
        try:raw,digest,plan=capture_snapshot(self.pid,guard['roots'],self.types)
        except (UnsupportedGraph,OSError,RecursionError,ValueError):self.revoke(frame,'unsupported committed graph');return
        guard.update(expected=raw,digest=digest,nodes=set(json.loads(raw)[1]),plan=plan);self.counts['heap_effect_commits']+=1
        self.record(dict(kind='heap_commit',frame_id=frame,reason=reason,state_zlib=zlib.compress(raw,1).hex(),state_sha256=digest,read_plan=plan.record()))
    def adopt(self,frame,pointer,token):
        guard=self.readonly.get(frame)
        if guard is None or token is None or token[0]!='object' or token[1] not in {self.types[k] for k in ('list','tuple','dict','set')} or str(pointer) in guard['nodes']:return
        try:
            if not guard['plan'].matches(self.pid):
                old,old_digest,old_plan=capture_snapshot(self.pid,guard['roots'],self.types)
                if old!=guard['expected']:
                    self.record(dict(kind='heap_creation_rejected',frame_id=frame,state_sha256=old_digest,state_zlib=zlib.compress(old,1).hex(),read_plan=old_plan.record()))
                    self.pending.append(dict(reason='heap_changed_before_creation',frame=frame));return
            roots=guard['roots']+[pointer];raw,digest,plan=capture_snapshot(self.pid,roots,self.types)
        except (UnsupportedGraph,OSError,RecursionError,ValueError):
            self.gaps['unadopted_native_container']+=1;return
        self.record(dict(kind='heap_creation',frame_id=frame,pointer=pointer,previous_sha256=guard['digest'],state_zlib=zlib.compress(raw,1).hex(),state_sha256=digest,read_plan=plan.record()))
        guard.update(roots=roots,expected=raw,digest=digest,nodes=set(json.loads(raw)[1]),plan=plan);self.counts['native_container_adoptions']+=1
    def trap(self):
        regs=nt.registers(self.pid);sig=nt.info(self.pid)
        dr6=nt.ptrace(nt.PEEKUSER,self.pid,nt.DR_OFFSET+6*8)&15
        nt.ptrace(nt.POKEUSER,self.pid,nt.DR_OFFSET+6*8,0)
        cframe=u64(self.pid,self.tstate+56);active=u64(self.pid,cframe) if cframe else 0
        # CPython trusted runtime metadata identifies the actual executing frame.
        # Merely writing from a Python image address or a C API is insufficient.
        trusted_text=any(a<=regs['rip']<b for a,b in self.runtime_ranges)
        native=active==self.owner and self.owner!=0 and trusted_text
        current=self.leases.get(self.current_lease)
        if current and current.get('append_state'):
            state=current['append_state'];complete=False
            for i,address in enumerate(list(self.targets)):
                if not dr6&(1<<i):continue
                word=u64(self.pid,address)
                self.record(dict(kind='native_heap_effect',address=address,word=word,rip=regs['rip'],active_frame=active,lease_owner=self.owner,authenticated=native,trusted_runtime_text=trusted_text,siginfo=sig))
                self.counts['hardware_effect_stores']+=1
                if not native:self.pending.append(dict(reason='foreign_heap_effect_producer',address=address));continue
                self.counts['authenticated_effect_stores']+=1
                try:complete=state.consume(address,word)
                except ValueError as error:self.pending.append(dict(reason='invalid_heap_effect',detail=str(error)))
            if complete:self.commit(current['frame'],'authenticated list append completion')
            self.targets=state.targets();nt.arm(self.pid,self.targets);return
        rearm=False
        for i,address in enumerate(list(self.targets)):
            if not dr6&(1<<i):continue
            retirement=current.get('retirement') if current else None
            if retirement is not None and address==retirement.marker:
                word=u64(self.pid,address);new_offset=retirement.offset+word-retirement.initial_word
                completed=False
                if native:new_offset,completed=retirement.observe(word)
                self.record(dict(kind='native_retirement',address=address,word=word,new_offset=new_offset,completed=completed,
                    rip=regs['rip'],active_frame=active,lease_owner=self.owner,authenticated=native,trusted_runtime_text=trusted_text,siginfo=sig))
                self.counts['hardware_retirement_stores']+=1
                if not native:self.pending.append(dict(reason='foreign_instruction_frontier',address=address))
                else:
                    self.counts['authenticated_retirement_stores']+=1
                    if completed:
                        self.counts['effect_retirements']+=1;self.commit(current['frame'],'native instruction retirement')
                        self.targets=[a for a in self.targets if a!=address];rearm=True
                continue
            pointer=u64(self.pid,address);token=value(self.pid,pointer,self.types) if native else None
            e=dict(kind='native_producer',address=address,pointer=pointer,token=token,
                rip=regs['rip'],active_frame=active,lease_owner=self.owner,
                authenticated=native,trusted_runtime_text=trusted_text,lease=self.lease,siginfo=sig)
            lease=self.leases.get(self.current_lease)
            if native and lease and lease.get('cell_birth'):
                birth=lease['cell_birth'];cell_value=u64(self.pid,pointer+16)
                e['cell_birth']=dict(birth,pointer=pointer,value=value(self.pid,cell_value,self.types) if cell_value else None)
            self.record(e);self.counts['hardware_stores']+=1
            if native:
                self.seals[address]=dict(pointer=pointer,token=token,owner=self.owner)
                self.counts['authenticated_stores']+=1
                if token is None:self.gaps['oversized_primitive']+=1
                lease=self.leases.get(self.current_lease)
                if lease and lease.get('cell_birth'):
                    birth=lease['cell_birth'];self.cell_expected[birth['frame']][birth['name']]=pointer
                    cell_value=u64(self.pid,pointer+16)
                    if cell_value:self.monitor.values[f'cell:{pointer}']=value(self.pid,cell_value,self.types)
                if lease and lease.get('commit_frame') is not None:self.commit(lease['commit_frame'],'native typed-effect completion')
                if lease:self.adopt(lease['frame'],pointer,token)
                if lease and lease['wide']:
                    if regs['rip'] not in self.store_sites:raise RuntimeError('wide producer is not a verified 64-bit pointer store')
                    remaining=lease['remaining']
                    if lease['direction'] is None:
                        if address==remaining[0]:lease['direction']=1
                        elif address==remaining[-1]:lease['direction']=-1
                        else:raise RuntimeError('wide producer did not start at an endpoint')
                    expected=remaining[0] if lease['direction']==1 else remaining[-1]
                    if address!=expected:raise RuntimeError('nonmonotone wide producer')
                    remaining.remove(address);self.counts['wide_authenticated_outputs']+=1
            else:
                self.counts['foreign_stores']+=1
                self.pending.append(dict(reason='foreign_native_producer',address=address,rip=regs['rip'],active_frame=active,expected_frame=self.owner))
        if rearm:nt.arm(self.pid,self.targets)
        if not dr6:self.gaps['nonhardware_sigtrap']+=1
        lease=self.leases.get(self.current_lease)
        if lease and lease['wide']:
            rest=lease['remaining']
            if lease['direction'] is None:self.targets=list(dict.fromkeys([rest[0],rest[-1],rest[1]])) if len(rest)>2 else rest
            else:self.targets=rest[:3] if lease['direction']==1 else list(reversed(rest[-3:]))
            nt.arm(self.pid,self.targets)
    def handle(self,e):
        if e['kind']=='boot':self.types=e['types'];self.tstate=e['thread_state'];self.pure=set(e.get('pure_builtin_ids',[]))
        if e['kind']=='opcode':
            previous=self.leases.get(self.last_lease.get(e['frame_id']),{})
            retirement=previous.get('retirement')
            if retirement is not None and not retirement.completed:
                self.gaps['incomplete_retirement_receipt']+=1
                raise RuntimeError('native effect completion was not witnessed before consumer')
            effect=previous.get('append_state')
            if effect is not None and effect.pending() and not previous.get('cancelled'):
                self.gaps['incomplete_heap_effect_receipt']+=1
                raise RuntimeError('incomplete native list effect before consumer')
        admit=False
        if e['kind']=='frame':
            for frame in list(self.readonly):self.revoke(frame,'nested execution frontier')
            self.cell_expected[e['frame_id']]=e.get('cell_slots',{})
            policy=heap_certificate(self.monitor.codes[e['code_id']]);containers={self.types[k] for k in ('list','tuple','dict','set')}
            tokens=[pair[1] for pair in e['locals'].values()]
            roots=[v[2] for v in tokens if v[0]=='object' and v[1] in containers]
            exact=all(v[0]!='object' or v[1] in containers or len(v)>3 for v in tokens)
            if policy['eligible'] and exact:
                try:raw,digest,plan=capture_snapshot(self.pid,roots,self.types)
                except (UnsupportedGraph,OSError,RecursionError,ValueError) as error:self.gaps['heap_admission_unsupported']+=1
                else:
                    self.readonly[e['frame_id']]=dict(roots=roots,expected=raw,digest=digest,nodes=set(json.loads(raw)[1]),plan=plan);admit=True
                    self.counts['heap_invariant_activations']+=1
                    self.record(dict(kind='heap_admission',frame_id=e['frame_id'],code_id=e['code_id'],roots=roots,policy=policy,
                        state_zlib=zlib.compress(raw,1).hex(),state_sha256=digest,read_plan=plan.record()))
        if e['kind']=='opcode' and e['frame_id'] in self.readonly:
            guard=self.readonly[e['frame_id']];self.counts['heap_invariant_checks']+=1;read_error=None;fast=False
            try:
                if guard['plan'].matches(self.pid):
                    raw=guard['expected'];digest=guard['digest'];fast=True;self.counts['heap_fast_equalities']+=1
                else:
                    raw,digest,plan=capture_snapshot(self.pid,guard['roots'],self.types)
                    if raw==guard['expected']:
                        guard['plan']=plan
                        self.record(dict(kind='heap_readplan_update',frame_id=e['frame_id'],state_sha256=digest,read_plan=plan.record()))
            except (UnsupportedGraph,OSError,RecursionError,ValueError) as error:
                raw=None;digest=None;read_error=type(error).__name__;self.pending.append(dict(reason='readonly_heap_unreadable',frame=e['frame_id'],error=read_error))
            else:
                if raw!=guard['expected']:self.pending.append(dict(reason='readonly_heap_changed',frame=e['frame_id'],expected_sha256=guard['digest'],observed_sha256=digest))
            self.record(dict(kind='heap_check',frame_id=e['frame_id'],state_zlib=zlib.compress(raw,1).hex() if raw is not None and not fast else None,
                state_sha256=digest,read_error=read_error,same_expected=fast,read_plan_sha256=guard['plan'].sha256))
            op=self.monitor.codes[self.monitor.frames[e['frame_id']]['code']]['ops'][e['offset']]
            frame=e['frame_id'];name=op['name'];commit=False
            if name=='CALL':
                info=e.get('call_info') or {};receiver=info.get('receiver');kind=info.get('receiver_kind');method=info.get('name')
                action='unknown'
                if info.get('function') in self.pure:action='read'
                elif method in READ_METHODS.get(kind,set()):action='read'
                elif method in MUTATORS.get(kind,set()):action='mutate'
                if action!='unknown':
                    try:heap_snapshot(self.pid,info.get('arguments',[])+([receiver] if receiver else []),self.types)
                    except (UnsupportedGraph,OSError,RecursionError,ValueError):action='unknown'
                if action=='unknown':self.revoke(frame,'unmodeled call effect')
                elif action=='mutate' and str(receiver) in guard['nodes']:commit=True
            elif name in ('STORE_SUBSCR','DELETE_SUBSCR','STORE_SLICE','LIST_APPEND','LIST_EXTEND','SET_ADD','SET_UPDATE','MAP_ADD','DICT_UPDATE','DICT_MERGE'):
                if name in ('LIST_APPEND','LIST_EXTEND','SET_ADD','SET_UPDATE','DICT_UPDATE','DICT_MERGE'):
                    target=e['stack'][-(op['arg']+1)]['pointer'];args=[e['stack'][-1]['pointer']]
                elif name=='MAP_ADD':target=e['stack'][-(op['arg']+2)]['pointer'];args=[x['pointer'] for x in e['stack'][-2:]]
                elif name=='STORE_SUBSCR':target=e['stack'][-2]['pointer'];args=[e['stack'][-3]['pointer'],e['stack'][-1]['pointer']]
                elif name=='DELETE_SUBSCR':target=e['stack'][-2]['pointer'];args=[e['stack'][-1]['pointer']]
                else:target=e['stack'][-3]['pointer'];args=[x['pointer'] for x in (e['stack'][-4],e['stack'][-2],e['stack'][-1])]
                if str(target) in guard['nodes']:
                    try:heap_snapshot(self.pid,args,self.types)
                    except (UnsupportedGraph,OSError,RecursionError,ValueError):self.revoke(frame,'opaque native effect arguments')
                    else:
                        marker=e['native_owner']+56
                        info=dict(marker=marker,initial_word=u64(self.pid,marker),offset=e['offset'],allowed=[self.monitor.codes[self.monitor.frames[frame]['code']]['next'][e['offset']]])
                        e['native_lease']['retire_effect']=info;e['native_targets']=list(dict.fromkeys(e['native_targets']+[marker]))
                        if len(e['native_targets'])>3:raise RuntimeError('retirement lease exceeded hardware budget')
            elif name=='BINARY_OP' and op['arg']>=13 and len(e['stack'])>=2:
                left=e['stack'][-2]
                if left['token'][0]=='object' and left['token'][1] in {self.types[k] for k in ('list','dict','set')}:commit=str(left['pointer']) in guard['nodes']
            elif name in ('LOAD_GLOBAL','LOAD_NAME','LOAD_ATTR','STORE_GLOBAL','STORE_NAME','DELETE_GLOBAL','DELETE_NAME'):
                if name=='LOAD_ATTR' and e['stack']:
                    obj=e['stack'][-1]['token']
                    if obj[0]=='object' and obj[1] not in {self.types[k] for k in ('list','dict','set','tuple','range')}:self.revoke(frame,'opaque attribute effect')
                if name in ('STORE_GLOBAL','DELETE_GLOBAL'):self.revoke(frame,'global binding effect')
            elif name not in SAFE:self.revoke(frame,'unmodeled opcode effect: '+name)
            if commit and frame in self.readonly:e['native_lease']['commit_frame']=frame
        if e['kind']=='opcode':
            frame=e['frame_id'];observed=e.get('cell_slots',{});expected=self.cell_expected.get(frame,{})
            if observed!=expected:self.pending.append(dict(reason='cell_slot_identity',frame=frame,expected=dict(expected),observed=observed))
            op=self.monitor.codes[self.monitor.frames[frame]['code']]['ops'][e['offset']];name=op['argval']
            if name in expected:
                if op['name']=='LOAD_FAST_AND_CLEAR':expected[name]=0
                if op['name']=='STORE_FAST':expected[name]=e['stack'][-1]['pointer']
        if e['kind']=='exception':
            previous=self.last_lease.get(e['frame_id'])
            if previous in self.leases and self.leases[previous].get('commit_frame') is not None:self.commit(e['frame_id'],'typed-effect exceptional completion')
            if previous in self.leases:self.leases[previous]['cancelled']=True
            prior=self.leases.get(previous,{})
            retirement=prior.get('retirement')
            if retirement is not None and not retirement.completed:
                code=self.monitor.codes[self.monitor.frames[e['frame_id']]['code']]
                handlers=[h for h in code['handlers'] if h['start']<=e['offset']<h['end']]
                if handlers:
                    retirement.allowed.add(handlers[0]['target'])
                    descriptor=dict(prior['descriptor']);descriptor['retire_effect']=dict(descriptor['retire_effect'],allowed=sorted(retirement.allowed))
                    e['native_lease']=descriptor;e['native_targets']=list(dict.fromkeys(e['native_targets']+[retirement.marker]))
            owner=e['native_owner'];cut=e['stack_base']+8*e['invalidate_from']
            for address in list(self.seals):
                if self.seals[address]['owner']==owner and address>=cut:self.seals.pop(address)
        if e['kind']=='opcode':
            base=e['stack_base'];owner=e['native_owner'];frame=e['frame_id']
            previous=self.last_lease.get(frame)
            if previous in self.leases:
                p=self.leases[previous]
                if p['wide'] and p['remaining'] and not p.get('cancelled'):raise RuntimeError('incomplete wide output receipts before consumer')
            if frame not in self.frames:
                self.frames[frame]=owner
                for address in list(self.seals):
                    if self.seals[address]['owner']==owner:self.seals.pop(address)
            for item in e['stack']:
                seal=self.seals.get(item['address'])
                if seal is None:
                    self.counts['unsealed_operands']+=1;continue
                self.counts['operand_checks']+=1
                if item['pointer']!=seal['pointer'] or (seal['token'] is not None and item['token']!=seal['token']):
                    self.pending.append(dict(reason='native_result_mismatch',address=item['address'],expected=seal,observed=item))
            cut=base+8*e['destination_plan']['invalidate_from']
            for address in list(self.seals):
                if self.seals[address]['owner']==owner and address>=cut:self.seals.pop(address)
            if not e['destination_plan']['known']:self.gaps['unknown_opcode']+=1
            if e['destination_plan']['hardware_overflow']:self.gaps['more_than_three_outputs']+=1
        answer=self.monitor.handle(e)
        if admit:answer['heap_guard_admitted']=True
        if self.pending:
            details=self.pending.pop(0);self.pending.clear()
            answer=self.monitor.fail(details.pop('reason'),e['kind'],**details)
        if e.get('native_stop'):
            self.targets=e.get('native_targets',[]);self.owner=e.get('native_owner',0)
            lease=e.get('native_lease');self.current_lease=lease['id'] if lease else None
            if lease:
                if lease['id'] not in self.leases:
                    self.leases[lease['id']]=dict(wide=lease['wide'],remaining=list(lease['outputs']),direction=None,
                        frame=int(lease['id'].split(':')[0]),descriptor=dict(lease),retirement=RetirementLease(**lease['retire_effect']) if lease.get('retire_effect') else None,append_state=ListAppendLease(**lease['append_effect']) if lease.get('append_effect') else None,
                        cell_birth=lease.get('cell_birth'),commit_frame=lease.get('commit_frame'))
                    if lease['wide'] and self.store_sites is None:self.store_sites=pointer_store_ends(self.executable)
                p=self.leases[lease['id']]
                if e['kind']=='opcode':self.last_lease[e['frame_id']]=lease['id']
                if p['wide'] and p['direction'] is not None:
                    rest=p['remaining'];self.targets=rest[:3] if p['direction']==1 else list(reversed(rest[-3:]))
            self.lease={k:e[k] for k in ('kind','frame_id','offset') if k in e}
            nt.arm(self.pid,self.targets)
        if e['kind']=='return':self.readonly.pop(e['frame_id'],None)
        return answer
    def result(self):return dict(counts=dict(self.counts),coverage_gaps=dict(self.gaps),runtime_sha256=self.runtime_sha256,
        trusted_runtime_executable_ranges=self.runtime_ranges,reference_program_executions=0,source_expression_evaluations=0)

def run_trial(task,index,mode,folder,seed=0,enforce=True,timeout=150,deadline=None,stop_source_after=None):
    if stop_source_after is not None and enforce:raise ValueError('evaluation work cap is restricted to unprotected controls')
    folder=Path(folder).resolve();folder.mkdir(parents=True,exist_ok=False)
    config=dict(source=task['code'],test=task['test_list'][index],setup=task.get('test_setup_code',''),mode=mode,seed=seed,entry_point=task.get('entry_point'))
    config['category1']=task.get('category1',{})
    config['workload_seed']=int(hashlib.sha256((config['source']+config['test']+config['setup']).encode()).hexdigest()[:16],16)
    (folder/'input.json').write_text(json.dumps(config,ensure_ascii=False))
    a,b=multiprocessing.connection.Pipe(duplex=True);monitor=Monitor(enforce=enforce)
    log=gzip.open(folder/'witnesses.jsonl.gz','wt',compresslevel=6);started=time.monotonic();cpu_started=time.process_time()
    child_usage=resource.getrusage(resource.RUSAGE_CHILDREN);child_cpu_started=child_usage.ru_utime+child_usage.ru_stime
    events=0;attack=None;last={};transport_error=None;child=None;status_done=False;control_witness=False;entry_input=None
    dispatched=0;subject=0;origin_alarm=None
    gate=Gate(folder/'process_origin.jsonl',enforce)
    with (folder/'stderr.log').open('wb') as err,(folder/'stdout.log').open('wb') as out:
        child=subprocess.Popen([sys.executable,'-u',str(HERE/'worker.py'),str(folder),str(b.fileno())],pass_fds=(b.fileno(),),stdout=out,stderr=err,env=dict(task.get('environment',os.environ),PYTHONHASHSEED='0'),start_new_session=True)
        b.close();native=NativeReceipts(child.pid,monitor,log);pending=None;stopped=False
        try:
            _,initial=os.waitpid(child.pid,0)
            if not os.WIFSTOPPED(initial):raise RuntimeError('own-child native observation unavailable')
            nt.TRACE_SYSCALLS=True
            nt.ptrace(nt.SETOPTIONS,child.pid,0,0x100001);nt.resume(child.pid)
            while not status_done:
                if time.monotonic()-started>timeout or (deadline is not None and time.time()>=deadline):raise TimeoutError('trial/global deadline')
                activity=False
                if pending is None and a.poll(0):
                    activity=True
                    try:pending=a.recv()
                    except EOFError:pending=None
                waited,waitstatus=os.waitpid(child.pid,os.WNOHANG|nt.WALL)
                if waited:
                    activity=True
                    if os.WIFEXITED(waitstatus):child.returncode=os.WEXITSTATUS(waitstatus);status_done=True;break
                    if os.WIFSIGNALED(waitstatus):child.returncode=-os.WTERMSIG(waitstatus);status_done=True;break
                    sig=os.WSTOPSIG(waitstatus)
                    if sig==(signal.SIGTRAP|0x80):gate.observe(native,events);nt.resume(child.pid)
                    elif sig==signal.SIGTRAP:native.trap();nt.resume(child.pid)
                    elif sig==signal.SIGSTOP:stopped=True
                    elif sig==signal.SIGCHLD:nt.resume(child.pid,sig)
                    else:raise RuntimeError(f'unexpected traced signal {sig}')
                if pending is not None and (not pending.get('native_stop') or stopped):
                    activity=True;e=pending;pending=None;last=e;events+=1
                    if 'attack' in e:attack=e['attack']
                    if e.get('initial_entry_input') is not None:entry_input=e['initial_entry_input']
                    if stop_source_after is not None and e['subject_executed_before']>=stop_source_after:
                        control_witness=True;raise SufficientExtraWork('evaluation control has already executed excess original work')
                    answer=native.handle(e);native.record(dict(event=e,answer=answer))
                    if e['kind']=='opcode' and answer['ok']:
                        dispatched+=1
                        if native.monitor.codes[native.monitor.frames[e['frame_id']]['code']]['filename'].endswith('/subject.py'):subject+=1
                    a.send(answer)
                    if e.get('native_stop'):nt.resume(child.pid);stopped=False
                if not activity:time.sleep(.00003)
        except OriginBlocked as error:
            origin_alarm=error.alarm
        except BaseException as error:
            transport_error=f'{type(error).__name__}: {error}'
        finally:
            if not status_done:
                try:os.killpg(child.pid,signal.SIGKILL)
                except ProcessLookupError:pass
                try:
                    while True:
                        _,s=os.waitpid(child.pid,nt.WALL)
                        if os.WIFEXITED(s):child.returncode=os.WEXITSTATUS(s);break
                        if os.WIFSIGNALED(s):child.returncode=-os.WTERMSIG(s);break
                        nt.resume(child.pid)
                except ChildProcessError:pass
            a.close();log.close();gate.close();nt.TRACE_SYSCALLS=False
    file=folder/'worker_result.json'
    if origin_alarm is not None:
        attack_file=folder/'attack_started.json'
        attack=json.loads(attack_file.read_text()) if attack_file.exists() else None
        file.write_text(json.dumps(dict(version='TickTether-C1-v1',state='blocked',alarm=origin_alarm,
            observed_original_instructions=subject,dispatched_instructions=dispatched,
            attack_applied=bool(attack),attack=attack,first_entry_input=entry_input,
            source_reference_executions=0,source_rewritten=False))+'\n')
    worker=json.loads(file.read_text()) if file.exists() else dict(state='error',error=transport_error or 'worker terminated before result',
        observed_original_instructions=last.get('subject_executed_before',0),dispatched_instructions=last.get('executed_before',0),attack_applied=bool(attack),attack=attack,censored=True,first_entry_input=entry_input)
    result=dict(version='TickTether-C1-v1',mode=mode,enforce=enforce,task_id=task.get('task_id'),test_index=index,seed=seed,state=worker['state'],worker=worker,
        monitor=monitor.result(),native=native.result(),events=events,elapsed_seconds=time.monotonic()-started,returncode=child.returncode,
        folder=str(folder),attack=worker.get('attack') or attack,transport_error=transport_error,control_sufficient_extra_work=control_witness,
        source_sha256=hashlib.sha256(task['code'].encode()).hexdigest(),cost_prefix_contract=dict(receipts=monitor.receipts,
        actual_dispatches=worker.get('dispatched_instructions',last.get('executed_before')),receipt_precedes_dispatch=True,source_reference_executions=0))
    result['log_sha256']=hashlib.sha256((folder/'witnesses.jsonl.gz').read_bytes()).hexdigest()
    result['origin_blocked']=origin_alarm is not None
    result['process_origin_sha256']=hashlib.sha256((folder/'process_origin.jsonl').read_bytes()).hexdigest()
    child_usage=resource.getrusage(resource.RUSAGE_CHILDREN)
    result['measured_cpu_seconds']=dict(parent=time.process_time()-cpu_started,
        child=child_usage.ru_utime+child_usage.ru_stime-child_cpu_started,
        scope='own worker plus external monitor; no uninstrumented comparison')
    (folder/'result.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n');return result
