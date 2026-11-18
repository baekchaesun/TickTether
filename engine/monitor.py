"""External rolling control/value witness verifier. Never calls application code."""
import hashlib
import pickle
import json
import zlib
from certificate import verify as verify_certificate

class Monitor:
    def __init__(self, enforce=True):
        self.enforce=enforce;self.codes={};self.frames={};self.values={}
        self.recurrence_seen={};self.recurrence_checks=0;self.receipts=0;self.branches=0;self.writes=0;self.alarms=[];self.digest=hashlib.sha256()

    def fail(self, reason, event, **details):
        alarm=dict(reason=reason,event=event,receipt=self.receipts,**details)
        if len(self.alarms)<32:self.alarms.append(alarm)
        return dict(ok=not self.enforce,alarm=alarm)

    def handle(self, e):
        self.digest.update(pickle.dumps(e,protocol=4));kind=e['kind']
        if kind=='register':
            d=e['description'];verify_certificate(d,d['exposure_certificate'])
            self.codes[e['code_id']]=d;return {'ok':True}
        if kind=='frame':
            c=self.codes[e['code_id']];last=e['offset'];nxt=c['next'].get(last)
            if c['ops'][last]['name']=='RETURN_GENERATOR':nxt=c['next'].get(nxt)
            self.frames[e['frame_id']]={'code':e['code_id'],'last':last,'next':{nxt},'locals':{},'exception':False,'loops':{},'resume_epoch':0}
            for name,(binding,tok) in e['locals'].items():
                if binding in self.values and self.values[binding]!=tok:
                    return self.fail('activation_value',kind,binding=binding,expected=self.values[binding],observed=tok)
                self.values[binding]=tok;self.frames[e['frame_id']]['locals'][name]=binding
            return {'ok':True}
        if kind=='resume':
            f=self.frames[e['frame_id']];c=self.codes[f['code']];f['next']={c['next'].get(e['offset'])};f['last']=e['offset'];f['resume_epoch']+=1;return {'ok':True}
        if kind=='opcode':
            f=self.frames[e['frame_id']];c=self.codes[f['code']];offset=e['offset'];self.receipts+=1
            violation=None
            if offset not in f['next']:
                violation=self.fail('control_successor',kind,frame=e['frame_id'],previous=f['last'],expected=sorted(v for v in f['next'] if v is not None),observed=offset)
                if self.enforce:return violation
            present={}
            for name,(binding,tok) in e['locals'].items():
                present[name]=binding
                if binding not in self.values or self.values[binding]!=tok:
                    violation=self.fail('last_writer',kind,frame=e['frame_id'],name=name,binding=binding,expected=self.values.get(binding),observed=tok)
                    if self.enforce:return violation
                    self.values[binding]=tok
            for name,binding in f['locals'].items():
                if name not in present and binding in self.values:
                    violation=self.fail('missing_value',kind,name=name,binding=binding)
                    if self.enforce:return violation
                    self.values.pop(binding,None)
            f['locals']=present
            for name in e.get('rebind_names',[]):f['locals'].pop(name,None)
            for binding,tok in e.get('reads',[]):
                if binding in self.values and self.values[binding]!=tok:
                    violation=self.fail('read_last_writer',kind,binding=binding,expected=self.values[binding],observed=tok)
                    if self.enforce:return violation
                self.values.setdefault(binding,tok)
            recurrence=e.get('recurrence')
            if recurrence is not None:
                self.recurrence_checks+=1
                loop=e.get('loop')
                if loop:
                    expected_scope=[f['resume_epoch'],[[parent,f['loops'].get(parent,0)] for parent in loop['parents']]]
                    if recurrence['epoch']!=expected_scope:
                        violation=self.fail('loop_scope_witness',kind,expected=expected_scope,observed=recurrence['epoch'])
                        if self.enforce:return violation
                # Exact serialized state is retained; SHA collisions are not used for equality.
                blob=bytes.fromhex(recurrence['state_zlib']);canonical=zlib.decompress(blob)
                assert hashlib.sha256(canonical).hexdigest()==recurrence['state_sha256'],'state witness digest'
                key=(e['frame_id'],blob)
                if key in self.recurrence_seen:
                    violation=self.fail('control_state_recurrence',kind,frame=e['frame_id'],offset=offset,first_receipt=self.recurrence_seen[key],repeat_receipt=self.receipts,
                        control_names=recurrence['control_names'])
                    if self.enforce:return violation
                else:self.recurrence_seen[key]=self.receipts
            if e.get('loop'):
                identity=e['loop']['id'];f['loops'][identity]=f['loops'].get(identity,0)+1
            for binding,tok in e.get('writes',[]):
                self.values[binding]=tok;self.writes+=1
            for name,binding in e.get('deletes',[]):
                self.values.pop(binding,None);f['locals'].pop(name,None)
            op=c['ops'][offset];nxt=c['next'].get(offset)
            f['last']=offset;f['next']={nxt};f['exception']=False
            if op['jump']:
                f['next']={nxt,op['target']}
                if op['name'].startswith('JUMP') and 'IF' not in op['name']:f['next']={op['target']}
            if op['name'] in ('RETURN_VALUE','RETURN_CONST','RAISE_VARARGS','RERAISE'):f['next']=set()
            if op['name']=='RERAISE':
                handlers=[h for h in c['handlers'] if h['start']<=offset<h['end']]
                if handlers:f['next']={handlers[0]['target']}
            return violation or {'ok':True}
        if kind=='branch':
            f=self.frames[e['frame_id']];c=self.codes[f['code']];o=e['offset'];d=e['destination'];self.branches+=1
            op=c['ops'][o];allowed={c['next'].get(o),op['target']}
            if op['name']=='FOR_ITER':
                target=op['target'];allowed.add(c['next'].get(target))
            if f['last']!=o or d not in allowed:
                r=self.fail('branch_witness',kind,previous=f['last'],origin=o,destination=d,allowed=sorted(v for v in allowed if v is not None))
                if self.enforce:return r
            f['next']={d};return {'ok':True}
        if kind=='exception':
            f=self.frames[e['frame_id']];c=self.codes[f['code']];off=e['offset']
            if e.get('type') in ('StopIteration','StopAsyncIteration') and c['ops'].get(off,{}).get('name') in ('SEND','END_SEND','FOR_ITER','END_ASYNC_FOR'):
                return {'ok':True}
            handlers=[h for h in c['handlers'] if h['start']<=off<h['end']]
            # CPython selects the innermost table entry. Empty means native unwind.
            f['next']={handlers[0]['target']} if handlers else set();f['exception']=True
            return {'ok':True}
        if kind=='return':
            f=self.frames[e['frame_id']];c=self.codes[f['code']];op=c['ops'].get(e['offset'],{})
            if op.get('name')=='YIELD_VALUE':return {'ok':True}
            if op.get('name') not in ('RETURN_VALUE','RETURN_CONST','RETURN_GENERATOR','RAISE_VARARGS','RERAISE') and not f['exception']:
                r=self.fail('unwitnessed_return',kind,offset=e['offset'],op=op)
                if self.enforce:return r
            self.frames.pop(e['frame_id'],None);return {'ok':True}
        if kind=='native_write':
            for binding,tok in e['writes']:self.values[binding]=tok;self.writes+=1
            return {'ok':True}
        return {'ok':True}

    def result(self):
        return dict(recurrence_checks=self.recurrence_checks,distinct_control_states=len(self.recurrence_seen),receipts=self.receipts,branch_witnesses=self.branches,last_writer_updates=self.writes,
                    alarms=self.alarms,wire_sha256=self.digest.hexdigest(),reference_program_executions=0)
