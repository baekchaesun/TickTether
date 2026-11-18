"""Exact live-memory equality plans. No cross-snapshot value assumption."""
import ctypes
import hashlib
import json
from contextlib import contextmanager
import native_trace as nt

class ReadPlan:
    def __init__(self, reads, objects):
        merged=[]
        for address, raw in sorted(reads, key=lambda x:x[0]):
            if not raw:
                continue
            if not merged or address>merged[-1][0]+len(merged[-1][1]):
                merged.append([address, raw])
            else:
                start, previous=merged[-1]
                overlap=min(start+len(previous)-address,len(raw))
                if previous[address-start:address-start+overlap]!=raw[:overlap]:
                    raise ValueError('memory changed inside stopped-process snapshot')
                if address+len(raw)>start+len(previous):
                    merged[-1][1]=previous+raw[overlap:]
        excluded=sorted((x,x+8) for x in objects)
        segments=[];index=0
        for start,raw in merged:
            end=start+len(raw);cursor=start
            while index<len(excluded) and excluded[index][1]<=start:
                index+=1
            j=index
            while j<len(excluded) and excluded[j][0]<end:
                a,b=excluded[j]
                if a>cursor:segments.append((cursor,raw[cursor-start:min(a,end)-start]))
                cursor=max(cursor,min(b,end));j+=1
            if cursor<end:segments.append((cursor,raw[cursor-start:]))
        self.segments=segments
        self.expected=b''.join(raw for _,raw in segments)
        self.buffer=ctypes.create_string_buffer(max(1,len(self.expected)))
        self.parts=[];offset=0
        for first in range(0,len(segments),1024):
            part=segments[first:first+1024]
            remote=(nt.IOVec*len(part))(*(nt.IOVec(a,len(raw))for a,raw in part))
            length=sum(len(raw)for _,raw in part)
            self.parts.append((offset,length,remote));offset+=length
        self.description=dict(version='exact-live-read-plan-v1',segments=[[a,raw.hex()]for a,raw in segments],
                              excluded_refcount_objects=sorted(objects))
        self.sha256=hashlib.sha256(json.dumps(self.description,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    def matches(self,pid):
        for offset,length,remote in self.parts:
            local=nt.IOVec(ctypes.addressof(self.buffer)+offset,length)
            copied=nt.libc.process_vm_readv(pid,ctypes.byref(local),1,remote,len(remote),0)
            if copied!=length:
                raise OSError(ctypes.get_errno(),'live memory plan read failed')
        return self.buffer.raw[:len(self.expected)]==self.expected
    def record(self):
        return dict(description=self.description,sha256=self.sha256)

@contextmanager
def recording():
    previous=nt.READ_CAPTURE
    capture=dict(reads=[],objects=set());nt.READ_CAPTURE=capture
    try:yield capture
    finally:nt.READ_CAPTURE=previous

def capture_snapshot(pid,roots,types):
    from heap_invariant import snapshot
    with recording() as capture:
        raw,digest=snapshot(pid,roots,types)
    return raw,digest,ReadPlan(capture['reads'],capture['objects'])


def verify_description(record, roots, types, expected_state):
    """Rebuild only the observed memory graph from saved bytes, never a function."""
    import bisect
    import heap_invariant as graph
    import value_decode as decoder
    description=record['description']
    actual=hashlib.sha256(json.dumps(description,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    if actual!=record['sha256']:
        raise AssertionError('read plan digest')
    segments=[(int(a),bytes.fromhex(h))for a,h in description['segments']]
    starts=[a for a,_ in segments]
    objects=description['excluded_refcount_objects']
    if starts!=sorted(set(starts)) or objects!=sorted(set(objects)):
        raise AssertionError('read plan ordering')
    for i,(a,data) in enumerate(segments):
        if not data or (i and segments[i-1][0]+len(segments[i-1][1])>a):
            raise AssertionError('read plan overlap')
        j=bisect.bisect_right(objects,a)-1
        if j>=0 and a<objects[j]+8:raise AssertionError('protected refcount bookkeeping')
        j=bisect.bisect_left(objects,a)
        if j<len(objects) and objects[j]<a+len(data):raise AssertionError('protected refcount bookkeeping')
    def read_view(pid,address,length):
        result=[];end=address+length
        while address<end:
            i=bisect.bisect_right(starts,address)-1
            if i>=0 and address<segments[i][0]+len(segments[i][1]):
                a,data=segments[i];n=min(end-address,a+len(data)-address)
                result.append(data[address-a:address-a+n]);address+=n;continue
            j=bisect.bisect_right(objects,address)-1
            if j>=0 and address<objects[j]+8:
                n=min(end-address,objects[j]+8-address);result.append(bytes(n));address+=n;continue
            raise AssertionError('canonical memory read missing from plan')
        return b''.join(result)
    old_graph,old_value=graph.read,decoder.read
    try:
        graph.read=read_view;decoder.read=read_view
        raw,_=graph.snapshot(0,roots,types)
    finally:graph.read=old_graph;decoder.read=old_value
    if raw!=expected_state:raise AssertionError('read plan does not reconstruct canonical state')
    return True
