#!/usr/bin/env python3
"""Independent record-only audit. Application source is never executed."""
import argparse
import collections
import gzip
import hashlib
import json
from pathlib import Path
import time
import tarfile
import sys
import zlib
from certificate import verify
from monitor import Monitor
from native_store import pointer_store_ends
from heap_invariant import certificate as heap_certificate
from creation import ListAppendLease
from retirement import RetirementLease
from readplan import verify_description

def normalized(d):
    d=dict(d)
    for name in ('ops','next','depth'):
        if name in d:d[name]={int(k):v for k,v in d[name].items()}
    return d

class ReceiptAudit:
    """Reconstruct destination leases and seals from saved kernel witnesses."""
    def __init__(self,monitor,ranges):
        self.monitor=monitor;self.ranges=ranges;self.seals={};self.frames={};self.owner=0;self.targets=[]
        self.pending=[];self.violations=[];self.counts=collections.Counter()
        self.leases={};self.last_lease={};self.current_lease=None;self.store_sites=None
        self.heap={};self.heap_roots={};self.heap_admissions=set();self.heap_revocations=set();self.types={}
        self.cell_expected={};self.last_producer=None;self.read_plans={}
    def heap_record(self,r):
        kind=r['kind'];frame=r['frame_id']
        if kind=='heap_admission':
            policy=heap_certificate(self.monitor.codes[r['code_id']])
            if policy!=r['policy'] or not policy['eligible']:self.violations.append('heap invariant certificate')
            raw=zlib.decompress(bytes.fromhex(r['state_zlib']))
            if hashlib.sha256(raw).hexdigest()!=r['state_sha256']:self.violations.append('heap admission digest')
            self.heap[frame]=(raw,r['state_sha256']);self.heap_roots[frame]=r['roots'];self.heap_admissions.add(frame)
            verify_description(r['read_plan'],r['roots'],self.types,raw);self.read_plans[frame]=r['read_plan']['sha256']
            self.counts['heap_invariant_activations']+=1
        elif kind=='heap_check':
            self.counts['heap_invariant_checks']+=1
            if frame not in self.heap:self.violations.append('heap check without admission');return
            if r.get('same_expected'):
                self.counts['heap_fast_equalities']+=1
                if r['state_sha256']!=self.heap[frame][1] or r['read_plan_sha256']!=self.read_plans[frame]:self.violations.append('fast read plan binding')
                return
            if r['state_zlib'] is None:
                self.pending.append(dict(reason='readonly_heap_unreadable',frame=frame,error=r['read_error']))
            else:
                raw=zlib.decompress(bytes.fromhex(r['state_zlib']));digest=hashlib.sha256(raw).hexdigest()
                if digest!=r['state_sha256']:self.violations.append('heap check digest')
                expected,expected_digest=self.heap[frame]
                if raw!=expected:self.pending.append(dict(reason='readonly_heap_changed',frame=frame,expected_sha256=expected_digest,observed_sha256=digest))
        elif kind=='heap_revocation':
            self.heap.pop(frame,None);self.heap_revocations.add(frame)
        elif kind=='heap_commit':
            raw=zlib.decompress(bytes.fromhex(r['state_zlib']))
            if hashlib.sha256(raw).hexdigest()!=r['state_sha256']:self.violations.append('heap commit digest')
            if frame not in self.heap:self.violations.append('heap commit without admission')
            if r['reason']=='native typed-effect completion':
                lease=self.leases.get(self.current_lease,{})
                if not self.last_producer or not self.last_producer['authenticated'] or lease.get('commit_frame')!=frame:self.violations.append('heap commit without authenticated effect producer')
            elif r['reason']=='native instruction retirement':
                lease=self.leases.get(self.current_lease,{})
                if not lease.get('retirement') or not lease['retirement'].completed or lease.get('frame')!=frame or not self.last_producer['authenticated']:self.violations.append('native retirement completion proof')
            elif r['reason']=='authenticated list append completion':
                lease=self.leases.get(self.current_lease,{})
                state=lease.get('append_state')
                if state is None or state.pending() or lease.get('frame')!=frame or not self.last_producer['authenticated']:self.violations.append('list append completion proof')
            elif r['reason']!='typed-effect exceptional completion':self.violations.append('heap commit reason')
            verify_description(r['read_plan'],self.heap_roots[frame],self.types,raw);self.read_plans[frame]=r['read_plan']['sha256']
            self.heap[frame]=(raw,r['state_sha256']);self.counts['heap_effect_commits']+=1
        elif kind=='heap_creation_rejected':
            raw=zlib.decompress(bytes.fromhex(r['state_zlib']))
            if hashlib.sha256(raw).hexdigest()!=r['state_sha256'] or raw==self.heap[frame][0]:self.violations.append('creation rejection state')
            verify_description(r['read_plan'],self.heap_roots[frame],self.types,raw)
            self.pending.append(dict(reason='heap_changed_before_creation',frame=frame))
        elif kind=='heap_creation':
            raw=zlib.decompress(bytes.fromhex(r['state_zlib']));digest=hashlib.sha256(raw).hexdigest()
            if digest!=r['state_sha256'] or frame not in self.heap:self.violations.append('creation digest or frame');return
            previous,old_digest=self.heap[frame];old_graph=json.loads(previous);new_graph=json.loads(raw)
            old_roots,old_nodes=old_graph[:2];new_roots,new_nodes=new_graph[:2]
            if any(new_graph[2].get(k)!=v for k,v in old_graph[2].items()):self.violations.append('creation changed prior atom')
            producer=self.last_producer
            if old_digest!=r['previous_sha256'] or not producer or not producer['authenticated'] or producer.get('pointer')!=r['pointer']:self.violations.append('creation producer binding')
            if new_roots!=old_roots+[['ref',r['pointer']]] or any(new_nodes.get(k)!=v for k,v in old_nodes.items()):self.violations.append('creation changed prior graph')
            self.heap[frame]=(raw,digest);self.heap_roots[frame].append(r['pointer']);self.counts['native_container_adoptions']+=1
            verify_description(r['read_plan'],self.heap_roots[frame],self.types,raw);self.read_plans[frame]=r['read_plan']['sha256']
        elif kind=='heap_readplan_update':
            if frame not in self.heap or self.heap[frame][1]!=r['state_sha256']:self.violations.append('read plan refresh binding')
            verify_description(r['read_plan'],self.heap_roots[frame],self.types,self.heap[frame][0]);self.read_plans[frame]=r['read_plan']['sha256']
        else:self.violations.append('unknown heap receipt')
    def producer(self,e):
        self.last_producer=e
        if e['kind']=='native_retirement':
            self.counts['hardware_retirement_stores']+=1
            lease=self.leases[self.current_lease];retirement=lease['retirement']
            text=any(a<=e['rip']<b for a,b in self.ranges);native=e['active_frame']==self.owner and self.owner!=0 and text
            if e['address']!=retirement.marker or e['address']!=self.owner+56 or native!=e['authenticated'] or text!=e['trusted_runtime_text'] or e['siginfo']['code']!=4:self.violations.append('retirement producer authentication')
            if not native:self.pending.append(dict(reason='foreign_instruction_frontier',address=e['address']));return
            self.counts['authenticated_retirement_stores']+=1
            offset,complete=retirement.observe(e['word'])
            if offset!=e['new_offset'] or complete!=e['completed']:self.violations.append('retirement offset binding')
            if complete:
                self.counts['effect_retirements']+=1;self.targets=[a for a in self.targets if a!=retirement.marker]
            return
        if e['kind']=='native_heap_effect':
            self.counts['hardware_effect_stores']+=1
            text=any(a<=e['rip']<b for a,b in self.ranges)
            native=e['active_frame']==self.owner and self.owner!=0 and text
            if e['address'] not in self.targets or native!=e['authenticated'] or text!=e['trusted_runtime_text'] or e['siginfo']['code']!=4:self.violations.append('typed heap writer authentication')
            if not native:self.pending.append(dict(reason='foreign_heap_effect_producer',address=e['address']));return
            self.counts['authenticated_effect_stores']+=1
            state=self.leases[self.current_lease]['append_state']
            try:state.consume(e['address'],e['word'])
            except ValueError as error:self.pending.append(dict(reason='invalid_heap_effect',detail=str(error)))
            self.targets=state.targets();return
        self.counts['hardware_stores']+=1
        if e['address'] not in self.targets:self.violations.append('native store outside active destination lease')
        if e['lease_owner']!=self.owner:self.violations.append('native lease owner')
        text=any(a<=e['rip']<b for a,b in self.ranges)
        native=e['active_frame']==self.owner and self.owner!=0 and text
        if native!=e['authenticated'] or text!=e['trusted_runtime_text']:self.violations.append('native producer authentication')
        if e['siginfo']['code']!=4:self.violations.append('native witness not hardware breakpoint')
        if native:
            self.counts['authenticated_stores']+=1
            self.seals[e['address']]=dict(pointer=e['pointer'],token=e['token'],owner=self.owner)
            if e.get('cell_birth'):
                birth=e['cell_birth'];self.cell_expected[birth['frame']][birth['name']]=birth['pointer']
                if birth['value'] is not None:self.monitor.values[f'cell:{birth["pointer"]}']=birth['value']
            lease=self.leases.get(self.current_lease)
            if lease and lease['wide']:
                if self.store_sites is None:self.store_sites=pointer_store_ends(sys.executable)
                if e['rip'] not in self.store_sites:self.violations.append('wide writer store width')
                rest=lease['remaining'];address=e['address']
                if lease['direction'] is None:
                    if address==rest[0]:lease['direction']=1
                    elif address==rest[-1]:lease['direction']=-1
                    else:self.violations.append('wide writer endpoint')
                if address!=(rest[0] if lease['direction']==1 else rest[-1]):self.violations.append('wide writer order')
                rest.remove(address);self.counts['wide_authenticated_outputs']+=1
        else:
            self.counts['foreign_stores']+=1
            self.pending.append(dict(reason='foreign_native_producer',address=e['address'],rip=e['rip'],active_frame=e['active_frame'],expected_frame=self.owner))
        lease=self.leases.get(self.current_lease)
        if lease and lease['wide']:
            rest=lease['remaining']
            if lease['direction'] is None:self.targets=list(dict.fromkeys([rest[0],rest[-1],rest[1]])) if len(rest)>2 else rest
            else:self.targets=rest[:3] if lease['direction']==1 else list(reversed(rest[-3:]))
    def event(self,e):
        if e['kind']=='boot':self.types=e['types']
        if e['kind']=='frame':self.cell_expected[e['frame_id']]=dict(e.get('cell_slots',{}))
        if e['kind']=='frame' and e['frame_id'] in self.heap_admissions:
            containers={self.types[k] for k in ('list','tuple','dict','set')}
            tokens=[pair[1] for pair in e['locals'].values()]
            roots=[v[2] for v in tokens if v[0]=='object' and v[1] in containers]
            if roots!=self.heap_roots[e['frame_id']] or any(v[0]=='object' and v[1] not in containers and len(v)<4 for v in tokens):self.violations.append('heap admission inputs')
        if e['kind']=='exception':
            previous=self.last_lease.get(e['frame_id'])
            if previous in self.leases:self.leases[previous]['cancelled']=True
            cut=e['stack_base']+8*e['invalidate_from'];owner=e['native_owner']
            for address in list(self.seals):
                if self.seals[address]['owner']==owner and address>=cut:self.seals.pop(address)
        if e['kind']=='opcode':
            frame=e['frame_id'];owner=e['native_owner'];base=e['stack_base']
            observed=e.get('cell_slots',{});expected=self.cell_expected.get(frame,{})
            if observed!=expected:self.pending.append(dict(reason='cell_slot_identity',frame=frame,expected=dict(expected),observed=observed))
            op=self.monitor.codes[self.monitor.frames[frame]['code']]['ops'][e['offset']];name=op['argval']
            if name in expected:
                if op['name']=='LOAD_FAST_AND_CLEAR':expected[name]=0
                if op['name']=='STORE_FAST':expected[name]=e['stack'][-1]['pointer']
            previous=self.last_lease.get(frame)
            if previous in self.leases:
                p=self.leases[previous]
                if p.get('retirement') is not None and not p['retirement'].completed:self.violations.append('incomplete retirement before consumer')
                if p.get('append_state') is not None and p['append_state'].pending() and not p.get('cancelled'):self.violations.append('incomplete list effect before consumer')
                if p['wide'] and p['remaining'] and not p.get('cancelled'):self.violations.append('wide outputs missing before consumer')
            if frame not in self.frames:
                self.frames[frame]=owner
                for address in list(self.seals):
                    if self.seals[address]['owner']==owner:self.seals.pop(address)
            for item in e['stack']:
                seal=self.seals.get(item['address'])
                if seal is None:self.counts['unsealed_operands']+=1;continue
                self.counts['operand_checks']+=1
                if item['pointer']!=seal['pointer'] or (seal['token'] is not None and item['token']!=seal['token']):
                    self.pending.append(dict(reason='native_result_mismatch',address=item['address'],expected=seal,observed=item))
            cut=base+8*e['destination_plan']['invalidate_from']
            for address in list(self.seals):
                if self.seals[address]['owner']==owner and address>=cut:self.seals.pop(address)
        answer=self.monitor.handle(e)
        if e['kind']=='frame' and e['frame_id'] in self.heap_admissions:answer['heap_guard_admitted']=True
        if self.pending:
            d=self.pending.pop(0);self.pending.clear();answer=self.monitor.fail(d.pop('reason'),e['kind'],**d)
        if e.get('native_stop'):
            self.targets=e.get('native_targets',[]);self.owner=e.get('native_owner',0)
            lease=e.get('native_lease');self.current_lease=lease['id'] if lease else None
            if lease:
                self.leases.setdefault(lease['id'],dict(wide=lease['wide'],remaining=list(lease['outputs']),direction=None,cell_birth=lease.get('cell_birth'),commit_frame=lease.get('commit_frame'),frame=int(lease['id'].split(':')[0]),retirement=RetirementLease(**lease['retire_effect']) if lease.get('retire_effect') else None,append_state=ListAppendLease(**lease['append_effect']) if lease.get('append_effect') else None))
                p=self.leases[lease['id']]
                if p.get('retirement') and lease.get('retire_effect'):p['retirement'].allowed.update(lease['retire_effect']['allowed'])
                if e['kind']=='opcode':self.last_lease[e['frame_id']]=lease['id']
                if p['wide'] and p['direction'] is not None:
                    rest=p['remaining'];self.targets=rest[:3] if p['direction']==1 else list(reversed(rest[-3:]))
        return answer

def redact(value,prefix):
    if isinstance(value,str):return value.replace(prefix,'/blinded-trial')
    if isinstance(value,list):return [redact(v,prefix) for v in value]
    if isinstance(value,dict):return {k:redact(v,prefix) for k,v in value.items() if k!='attack'}
    return value

def trial_audit(folder,result_override=None):
    result=result_override or json.loads((folder/'result.json').read_text());codes={};frames={};accepted=0;subject=0;anchors=0;B=0
    prefix_checks=0;events=0;certificates=0;violations=[];mirror=Monitor(enforce=result['enforce'])
    native=ReceiptAudit(mirror,result['native']['trusted_runtime_executable_ranges'])
    if hashlib.sha256((folder/'witnesses.jsonl.gz').read_bytes()).hexdigest()!=result['log_sha256']:violations.append('witness digest')
    with gzip.open(folder/'witnesses.jsonl.gz','rt') as stream:
        for line in stream:
            r=json.loads(line)
            if 'event' not in r:
                if r['kind'].startswith('heap_'):native.heap_record(r)
                else:native.producer(r)
                continue
            e=r['event'];events+=1;kind=e['kind'];blinded=redact(e,str(folder))
            if kind=='register':blinded['description']=normalized(blinded['description'])
            answer=native.event(blinded)
            if answer!=redact(r['answer'],str(folder)):violations.append(f'blinded decision changed at {events}')
            if e['executed_before']!=accepted or e['subject_executed_before']!=subject:violations.append(f'dispatch sequence {events}')
            if kind=='register':
                d=normalized(e['description']);c=d['exposure_certificate'];verify(d,c)
                codes[e['code_id']]=(d,set(c['anchors']));B=max(B,c['unobserved_run_bound']);certificates+=1
            if kind=='frame':frames[e['frame_id']]=e['code_id'];anchors+=1
            if kind in ('exception','resume'):anchors+=1
            if kind=='opcode':
                prefix_checks+=1;d,A=codes[frames[e['frame_id']]]
                if e['offset'] in A:anchors+=1
                if accepted>(B+1)*anchors+B:violations.append('cost prefix before dispatch')
                if r['answer']['ok']:
                    accepted+=1
                    if d['filename'].endswith('/subject.py'):subject+=1
                    if accepted>(B+1)*anchors+B:violations.append('cost prefix after dispatch')
    worker=result['worker']
    if not worker.get('censored'):
        if worker.get('dispatched_instructions')!=accepted:violations.append('final dispatch count')
        if worker.get('observed_original_instructions')!=subject:violations.append('final subject count')
    else:
        if not worker.get('dispatched_instructions',accepted)<=accepted<=worker.get('dispatched_instructions',accepted)+1:violations.append('censored dispatch interval')
        if not worker.get('observed_original_instructions',subject)<=subject<=worker.get('observed_original_instructions',subject)+1:violations.append('censored subject interval')
    if worker.get('source_reference_executions',0)!=0 or worker.get('source_rewritten',False):violations.append('source replay/rewrite')
    if dict(native.counts)!=result['native']['counts']:violations.append('native witness counters')
    violations.extend(native.violations)
    return dict(folder=str(folder),task_id=result['task_id'],mode=result['mode'],state=result['state'],events=events,
        dispatch_prefixes=prefix_checks,actual_dispatches=accepted,subject_dispatches=subject,anchor_receipts=anchors,
        B=B,certificates=certificates,native_counts=dict(native.counts),label_blinded_decisions_identical=not any('blinded' in v for v in violations),
        violations=violations,passed=not violations)

def main():
    parser=argparse.ArgumentParser();parser.add_argument('results',type=Path);args=parser.parse_args()
    root=args.results.resolve();dest=root/'audit';dest.mkdir(exist_ok=False);started=time.time();rows=[]
    inputs=[(p.parent,None) for p in sorted(root.glob('functions/*/*/result.json'))]
    for archive in sorted(root.glob('functions/*/request_metadata.tar.gz')):
        with tarfile.open(archive,'r:gz') as tar:
            for member in tar:
                if member.name.endswith('/result.json'):
                    inputs.append((archive.parent/Path(member.name).parent,json.loads(tar.extractfile(member).read())))
    for folder,result in inputs:
        try:row=trial_audit(folder,result)
        except BaseException as error:row=dict(folder=str(folder),passed=False,error=f'{type(error).__name__}: {error}')
        rows.append(row)
        with (dest/'trials.jsonl').open('a') as f:f.write(json.dumps(row,separators=(',',':'))+'\n')
        if len(rows)%200==0:print('Audited',len(rows),flush=True)
    counts=collections.Counter()
    for row in rows:counts.update(row.get('native_counts',{}))
    summary=dict(version='TickTether-C1-v1-AUDIT',trials=len(rows),passed_trials=sum(r['passed'] for r in rows),
        dispatch_prefixes=sum(r.get('dispatch_prefixes',0) for r in rows),actual_dispatches=sum(r.get('actual_dispatches',0) for r in rows),
        native_counts=dict(counts),checked_code_certificates=sum(r.get('certificates',0) for r in rows),
        maximum_B=max((r.get('B',0) for r in rows),default=0),
        label_blinded_decisions_identical=all(r.get('label_blinded_decisions_identical',False) for r in rows),
        violations=[r for r in rows if not r['passed']],elapsed_seconds=time.time()-started,
        application_executions_by_audit=0,source_expression_evaluations=0)
    (dest/'summary.json').write_text(json.dumps(summary,ensure_ascii=False,indent=2)+'\n');print(json.dumps(summary,ensure_ascii=False,indent=2))

if __name__=='__main__':main()
