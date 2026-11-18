#!/usr/bin/env python3
"""One original execution. Kernel traps actual native producers before next use."""
import ast
import ctypes
import dis
import hashlib
import json
import multiprocessing.connection
import os
from pathlib import Path
import resource
import signal
import sys
import threading
import time
import traceback
import types
import builtins
import random
from input_fingerprint import fingerprint
from effects import PURE_NAMES
from bytecode import description,VERSION
from certificate import build as build_certificate
from scenario_fault import ScenarioFault
from native_state import iterator_state
from native_trace import traceme_stop
from frame_access import token,stack,locals_and_bindings,FrameHead,InterpreterHead,NULL
from destinations import plan


def native_base(frame):
    c=frame.f_code;raw=FrameHead.from_address(id(frame))
    count=c.co_nlocals+sum(n not in c.co_varnames for n in c.co_cellvars)+len(c.co_freevars)
    return raw.frame+72+count*8


def tok(v):return ['null'] if v is NULL else token(v)

def cell_slots(frame):
    c=frame.f_code;names=list(c.co_varnames)+[n for n in c.co_cellvars if n not in c.co_varnames]+list(c.co_freevars)
    raw=FrameHead.from_address(id(frame));p=(ctypes.c_void_p*len(names)).from_address(raw.frame+72)
    return {n:int(p[i] or 0) for i,n in enumerate(names) if n in c.co_cellvars or n in c.co_freevars}

def call_info(op,operands):
    if op.opname!='CALL':return None
    start=len(operands)-(op.arg or 0)-2
    if start<0:return None
    first,second=operands[start:start+2];args=list(operands[start+2:]);receiver=None
    fn=second if first is NULL else first
    if first is not NULL:receiver=second
    if type(fn) in (types.BuiltinFunctionType,types.BuiltinMethodType):
        bound=fn.__self__
        if type(bound) in (list,dict,set,tuple,str,bytes):receiver=bound
        name=fn.__name__
    elif type(fn) in (types.MethodDescriptorType,types.WrapperDescriptorType):name=fn.__name__
    else:name=None
    return dict(function=id(fn),name=name,receiver=id(receiver) if receiver is not None else None,
        receiver_kind=type(receiver).__name__ if receiver is not None else None,
        arguments=[id(v) for v in args if v is not NULL])

class Bridge:
    def __init__(self,conn,folder,mode,seed):
        self.conn=conn;self.folder=folder;self.injector=ScenarioFault({},folder);self.frames={};self.codes={};self.holds={}
        self.entry_name=None;self.entry_calls=0;self.first_entry_input=None;self.request_checkpoint_line=2
        self.code_order=0;self.frame_order=0;self.executed=0;self.subject_executed=0;self.count_limit=1000000
        self.while_names=set();self.started=time.monotonic();self.dynamic_frames=0;self.gaps={}

    def result(self,state,**kw):
        return dict(version=VERSION,state=state,observed_original_instructions=self.subject_executed,
            dispatched_instructions=self.executed,attack_applied=self.injector.applied,attack=self.injector.details,
            attack_attempt_errors=self.injector.attempts[:8],source_reference_executions=0,source_rewritten=False,
            original_request_executions=1,entry_calls=self.entry_calls,first_entry_input=self.first_entry_input,registered_codes=len(self.codes),dynamic_frames=self.dynamic_frames,
            producer_form_gaps=self.gaps,elapsed_seconds=time.monotonic()-self.started,**kw)

    def save(self,r):(self.folder/'worker_result.json').write_text(json.dumps(r,ensure_ascii=False,indent=2)+'\n')

    def rpc(self,e,stop=False):
        e.update(executed_before=self.executed,subject_executed_before=self.subject_executed)
        if self.injector.applied:e['attack']=self.injector.details
        e['native_stop']=stop
        self.conn.send(e)
        if stop:os.kill(os.getpid(),signal.SIGSTOP)
        answer=self.conn.recv()
        if not answer.get('ok',False):
            self.save(self.result('blocked',alarm=answer.get('alarm')));os._exit(86)
        return answer

    def code(self,c):
        if c in self.codes:return self.codes[c]
        d=description(c);self.code_order+=1
        serial=dict(name=c.co_qualname,filename=c.co_filename,first_line=c.co_firstlineno,optimized=bool(c.co_flags&1),
            bytecode_sha256=d['bytecode_sha256'],next=d['next'],depth=d['depth'],
            ops={o:dict(name=i.opname,arg=i.arg,argval=i.argval if type(i.argval) in (str,int,float,type(None)) else repr(type(i.argval)),
                  jump=i.opcode in dis.hasjrel or i.opcode in dis.hasjabs,target=i.argval if i.opcode in dis.hasjrel or i.opcode in dis.hasjabs else None) for o,i in d['ops'].items()},
            handlers=[dict(start=h.start,end=h.end,target=h.target,depth=h.depth,lasti=h.lasti) for h in d['handlers']])
        serial['exposure_certificate']=build_certificate(serial);d['id']=self.code_order;self.codes[c]=d
        self.rpc(dict(kind='register',code_id=d['id'],description=serial));return d

    def admit(self,frame):
        return frame.f_code.co_filename.endswith(('/subject.py','/request.py')) or (frame.f_back is not None and id(frame.f_back) in self.frames)

    def context(self,frame):
        if id(frame) in self.frames:return self.frames[id(frame)]
        d=self.code(frame.f_code);self.frame_order+=1
        ctx=dict(frame=frame,id=self.frame_order,desc=d,control_names={i.argval for i in d['ops'].values() if i.opname in ('LOAD_FAST','LOAD_DEREF')} & self.while_names,pending_targets=[],pending_lease=None,last_iterator=None,request_checkpoint_line=self.request_checkpoint_line)
        self.frames[id(frame)]=ctx
        values,bindings=locals_and_bindings(frame,ctx['id'],self.holds)
        entry_input=None
        if frame.f_code.co_filename.endswith('/subject.py') and frame.f_code.co_name==self.entry_name:
            self.entry_calls+=1
            if self.first_entry_input is None:self.first_entry_input=fingerprint(values);entry_input=self.first_entry_input
        answer=self.rpc(dict(kind='frame',frame_id=ctx['id'],code_id=d['id'],offset=frame.f_lasti,initial_entry_input=entry_input,
            locals={n:(bindings[n],tok(v)) for n,v in values.items()},cell_slots=cell_slots(frame)))
        if answer.get('heap_guard_admitted'):
            for v in values.values():
                if type(v) in (list,tuple,dict,set):self.holds[id(v)]=v
        return ctx

    def trace(self,frame,event,arg):
        if event=='call':
            if not self.admit(frame):return None
            frame.f_trace_opcodes=True;frame.f_trace_lines=True
            if id(frame) in self.frames:self.rpc(dict(kind='resume',frame_id=self.frames[id(frame)]['id'],offset=frame.f_lasti))
            else:self.context(frame)
            return self.trace
        ctx=self.frames.get(id(frame))
        if ctx is None:return None
        if event in ('line','opcode'):
            d=ctx['desc'];values,bindings=locals_and_bindings(frame,ctx['id'],self.holds)
            depth=d['depth'].get(frame.f_lasti);operands=stack(frame,depth) if event=='opcode' and depth is not None else []
            # Retain actual native outputs before any injected application fault.
            # Values are held, never recomputed or executed by the verifier.
            for value in list(values.values())+operands:
                if type(value) in (list,tuple,dict,set):self.holds[id(value)]=value
            self.injector.mutate(frame,ctx,event,values,operands)
            if event=='line':return self.trace
            if self.executed>=self.count_limit:raise RuntimeError('instruction observation limit')
            if threading.active_count()>1:raise RuntimeError('TickTether-C1-v1 native broker currently supports a single application thread')
            offset=frame.f_lasti;op=d['ops'][offset];depth=d['depth'][offset]
            values,bindings=locals_and_bindings(frame,ctx['id'],self.holds);operands=stack(frame,depth)
            reads=[];writes=[];deletes=[];rebind=[];name=op.argval
            if op.opname in ('STORE_FAST','STORE_DEREF'):
                if op.opname=='STORE_FAST' and name in frame.f_code.co_cellvars:
                    rebind.append(name)
                else:
                    pass
                binding=bindings.get(name,f'frame:{ctx["id"]}:{name}')
                if op.opname=='STORE_DEREF' and name not in bindings:
                    c=frame.f_code;names=list(c.co_varnames)+[n for n in c.co_cellvars if n not in c.co_varnames]+list(c.co_freevars)
                    raw=FrameHead.from_address(id(frame));ptrs=(ctypes.c_void_p*len(names)).from_address(raw.frame+72)
                    cell=ctypes.cast(ptrs[names.index(name)],ctypes.py_object).value;self.holds[id(cell)]=cell;binding=f'cell:{id(cell)}'
                if not rebind:
                    if operands[-1] is NULL:deletes.append((name,binding))
                    else:writes.append((binding,tok(operands[-1])))
            elif op.opname in ('STORE_GLOBAL','STORE_NAME'):
                mapping=frame.f_globals if op.opname=='STORE_GLOBAL' else ctypes.cast(InterpreterHead.from_address(FrameHead.from_address(id(frame)).frame).locals,ctypes.py_object).value
                writes.append((f'namespace:{id(mapping)}:{name}',tok(operands[-1])))
            elif op.opname in ('DELETE_FAST','DELETE_DEREF','LOAD_FAST_AND_CLEAR'):
                if op.opname=='LOAD_FAST_AND_CLEAR' and name in frame.f_code.co_cellvars:rebind.append(name)
                elif name in bindings:deletes.append((name,bindings[name]))
            elif op.opname in ('DELETE_GLOBAL','DELETE_NAME'):deletes.append((name,f'namespace:{id(frame.f_globals)}:{name}'))
            if (op.opname=='IMPORT_STAR' or (op.opname=='CALL_INTRINSIC_1' and op.arg==2)) and operands and type(operands[-1]).__name__=='module':
                entries=operands[-1].__dict__
                for imported in entries.get('__all__',[k for k in entries if not k.startswith('_')]):
                    if imported in entries:writes.append((f'namespace:{id(frame.f_globals)}:{imported}',tok(entries[imported])))
            if op.opname in ('LOAD_GLOBAL','LOAD_NAME') and name in frame.f_globals:reads.append((f'namespace:{id(frame.f_globals)}:{name}',tok(frame.f_globals[name])))
            if op.opname=='FOR_ITER' and operands:
                ctx['last_iterator']=operands[-1];self.holds[id(operands[-1])]=operands[-1];s=iterator_state(operands[-1])
                if s is not None:reads.append((f'iterator:{id(operands[-1])}',s))
            layout=plan(op,depth);base=native_base(frame);outputs=[base+8*i for i in layout['outputs']]
            handlers=[h for h in d['handlers'] if h.start<=offset<h.end]
            if op.opname=='RERAISE' and handlers:
                h=handlers[0];layout['invalidate_from']=h.depth;outputs=[base+8*i for i in range(h.depth,h.depth+1+int(h.lasti))]
            cell_birth=None;heap_store=None
            if op.opname=='MAKE_CELL':
                names=list(frame.f_code.co_varnames)+[n for n in frame.f_code.co_cellvars if n not in frame.f_code.co_varnames]+list(frame.f_code.co_freevars)
                addr=FrameHead.from_address(id(frame)).frame+72+8*names.index(name)
                outputs.append(addr);cell_birth=dict(frame=ctx['id'],name=name,address=addr);rebind.append(name)
            if op.opname=='STORE_SUBSCR' and len(operands)>=3:
                target,key=operands[-2:]
                if type(target) is list and type(key) in (int,bool) and -len(target)<=key<len(target):
                    item_base=ctypes.c_void_p.from_address(id(target)+24).value
                    addr=item_base+8*(int(key)%len(target));outputs.append(addr)
                    heap_store=dict(receiver=id(target),address=addr,value=id(operands[-3]))
            wide=len(outputs)>3 and op.opname in ('UNPACK_SEQUENCE','UNPACK_EX')
            targets=list(dict.fromkeys([outputs[0],outputs[-1],outputs[1]])) if wide else outputs[:3]
            lease=dict(id=f'{ctx["id"]}:{self.executed+1}',outputs=outputs,wide=wide,cell_birth=cell_birth,heap_store=heap_store)
            if wide:layout['hardware_overflow']=False
            if not layout['known'] or layout['hardware_overflow']:self.gaps[op.opname]=self.gaps.get(op.opname,0)+1
            ctx['pending_targets']=targets;ctx['pending_lease']=lease
            self.rpc(dict(kind='opcode',frame_id=ctx['id'],offset=offset,
                locals={n:(bindings[n],tok(v)) for n,v in values.items()},reads=reads,writes=writes,deletes=deletes,rebind_names=rebind,
                cell_slots=cell_slots(frame),call_info=call_info(op,operands),
                stack_base=base,stack=[dict(address=base+8*i,pointer=0 if v is NULL else id(v),token=tok(v)) for i,v in enumerate(operands)],
                destination_plan=layout,native_targets=targets,native_lease=lease,native_owner=FrameHead.from_address(id(frame)).frame),stop=True)
            self.executed+=1
            if frame.f_code.co_filename.endswith('/subject.py'):self.subject_executed+=1
        elif event=='exception':
            handlers=[h for h in ctx['desc']['handlers'] if h.start<=frame.f_lasti<h.end]
            h=handlers[0] if handlers else None;base=native_base(frame)
            # The interpreter unwinder produces exception/lasti operands after this callback.
            targets=[base+8*i for i in range(h.depth,h.depth+1+int(h.lasti))] if h else []
            self.rpc(dict(kind='exception',frame_id=ctx['id'],offset=frame.f_lasti,type=type(arg[1]).__name__,
                stack_base=base,invalidate_from=h.depth if h else 0,
                native_targets=targets,native_owner=FrameHead.from_address(id(frame)).frame),stop=True)
        elif event=='return':
            parent=self.frames.get(id(frame.f_back)) if frame.f_back is not None else None
            targets=parent['pending_targets'] if parent is not None else []
            self.rpc(dict(kind='return',frame_id=ctx['id'],offset=frame.f_lasti,native_targets=targets,
                native_lease=parent['pending_lease'] if parent is not None else None,
                native_owner=FrameHead.from_address(id(parent['frame'])).frame if parent is not None else 0),stop=True)
            op=ctx['desc']['ops'].get(frame.f_lasti)
            if op is None or op.opname!='YIELD_VALUE':self.frames.pop(id(frame),None)
        return self.trace

    def branch(self,code,offset,destination):
        if code not in self.codes:return
        f=sys._getframe(1)
        while f is not None and f.f_code is not code:f=f.f_back
        if f is None or id(f) not in self.frames:return
        ctx=self.frames[id(f)];self.rpc(dict(kind='branch',frame_id=ctx['id'],offset=offset,destination=destination))
        if ctx['desc']['ops'][offset].opname=='FOR_ITER' and ctx['last_iterator'] is not None:
            s=iterator_state(ctx['last_iterator'])
            if s is not None:self.rpc(dict(kind='native_write',writes=[(f'iterator:{id(ctx["last_iterator"])}',s)]))


def main():
    folder=Path(sys.argv[1]).resolve();config=json.loads((folder/'input.json').read_text())
    if sys.version_info[:3]!=(3,12,3) or os.uname().machine!='x86_64':raise RuntimeError('TickTether-C1-v1 prototype ABI: CPython 3.12.3 on x86-64')
    resource.setrlimit(resource.RLIMIT_AS,(1536*1024**2,1536*1024**2));resource.setrlimit(resource.RLIMIT_CPU,(90,100))
    conn=multiprocessing.connection.Connection(int(sys.argv[2]));bridge=Bridge(conn,folder,config['mode'],config['seed'])
    if config.get('category1'):
        bridge.injector=ScenarioFault(config['category1'],folder)
    bridge.entry_name=config.get('entry_point');bridge.request_checkpoint_line=len(config['test'].strip().splitlines())+1
    random.seed(config['workload_seed'])
    traceme_stop()
    ctypes.pythonapi.PyThreadState_Get.restype=ctypes.c_void_p
    bridge.rpc(dict(kind='boot',thread_state=ctypes.pythonapi.PyThreadState_Get(),
        pure_builtin_ids=[id(getattr(builtins,n)) for n in PURE_NAMES],
        types={n:id(v) for n,v in dict(int=int,float=float,complex=complex,bool=bool,str=str,bytes=bytes,list=list,tuple=tuple,dict=dict,set=set,range=range,none=None,true=True,false=False).items()}))
    subject=str(folder/'subject.py');driver=str(folder/'request.py')
    try:
        tree=ast.parse(config['source']);bridge.while_names={n.id for loop in ast.walk(tree) if isinstance(loop,ast.While) for n in ast.walk(loop.test) if isinstance(n,ast.Name)}
        namespace={'__name__':'subject','__file__':subject};exec(compile(config['source'],subject,'exec'),namespace)
        if config.get('setup'):exec(compile(config['setup'],str(folder/'setup.py'),'exec'),namespace)
        request=config['test'].strip()+'\n__ticktether_checkpoint=0\n';(folder/'subject.py').write_text(config['source']);(folder/'request.py').write_text(request)
        program=compile(request,driver,'exec');sys.monitoring.use_tool_id(3,'ticktether-native-producers')
        sys.monitoring.register_callback(3,sys.monitoring.events.BRANCH,bridge.branch);sys.monitoring.register_callback(3,sys.monitoring.events.JUMP,bridge.branch)
        sys.monitoring.set_events(3,sys.monitoring.events.BRANCH|sys.monitoring.events.JUMP);sys._getframe().f_trace_opcodes=True
        sys.settrace(bridge.trace);exec(program,namespace);sys.settrace(None)
        bridge.save(bridge.result('complete',assertion_passed=True))
    except BaseException as error:
        sys.settrace(None);bridge.save(bridge.result('error',error=f'{type(error).__name__}: {error}',traceback=traceback.format_exc()))
    finally:
        sys.settrace(None)
        try:bridge.rpc(dict(kind='finished'))
        except (EOFError,BrokenPipeError):pass
        conn.close()

if __name__=='__main__':main()
