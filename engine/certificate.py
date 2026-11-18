"""Profile-free bounded work-exposure certificates for bytecode control graphs.
No expression execution, path enumeration, learned ordinal, or normal reference.
The certificate bounds observed VM work; a native CALL is one VM instruction.
"""
from collections import deque
import hashlib
import json

VERSION='WCV1-CUT'


def graph(d):
    ops=d['ops'];nexts=d['next'];nodes=set(ops);edges={v:set() for v in nodes}
    anchors=set()
    for v,op in ops.items():
        name=op['name'];nxt=nexts.get(v)
        if op['jump']:
            edges[v].add(op['target']);anchors.add(v)
            if not (name.startswith('JUMP') and 'IF' not in name) and nxt is not None:edges[v].add(nxt)
            if name=='FOR_ITER' and op['target'] in nexts:edges[v].add(nexts[op['target']])
        elif name not in ('RETURN_VALUE','RETURN_CONST','RAISE_VARARGS','RERAISE','RETURN_GENERATOR') and nxt is not None:
            edges[v].add(nxt)
        if name.startswith(('STORE_','DELETE_')) or name in ('CALL','CALL_FUNCTION_EX','RETURN_VALUE','RETURN_CONST','YIELD_VALUE','RAISE_VARARGS','RERAISE','RETURN_GENERATOR','IMPORT_STAR','CALL_INTRINSIC_1'):
            anchors.add(v)
    for h in d['handlers']:
        anchors.add(h['target'])
        for v in nodes:
            if h['start']<=v<h['end']:edges[v].add(h['target'])
    for v in nodes:edges[v].intersection_update(nodes)
    return nodes,edges,anchors


def acyclic_potential(nodes,edges,anchors):
    live=nodes-anchors;successors={v:edges[v]&live for v in live};pred={v:set() for v in live}
    for v in live:
        for w in successors[v]:pred[w].add(v)
    degree={v:len(successors[v]) for v in live};ready=deque(v for v in live if degree[v]==0)
    potential={v:0 for v in anchors};done=set()
    while ready:
        v=ready.popleft();done.add(v);potential[v]=1+max((potential[w] for w in edges[v]),default=0)
        for p in pred[v]:
            degree[p]-=1
            if degree[p]==0:ready.append(p)
    return potential,live-done


def build(d):
    nodes,edges,anchors=graph(d);fallback=[]
    while True:
        potential,cyclic=acyclic_potential(nodes,edges,anchors)
        if not cyclic:break
        # Generic finite fallback, unrelated to a function's intended order.
        v=min(cyclic);anchors.add(v);fallback.append(v)
    bound=max(potential.values(),default=0)
    c=dict(version=VERSION,bytecode_sha256=d['bytecode_sha256'],nodes=sorted(nodes),
        anchors=sorted(anchors),potential={str(v):potential[v] for v in sorted(nodes)},
        unobserved_run_bound=bound,work_per_receipt_bound=bound+1,
        inequality='D(prefix) <= (B+1)*E(prefix) + B',
        weight='one original VM opcode; native call internals not expanded',fallback_anchors=fallback)
    c['certificate_sha256']=hashlib.sha256(json.dumps(c,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    return c


def verify(d,c):
    copy=dict(c);digest=copy.pop('certificate_sha256',None)
    assert hashlib.sha256(json.dumps(copy,sort_keys=True,separators=(',',':')).encode()).hexdigest()==digest,'certificate digest'
    assert c['bytecode_sha256']==d['bytecode_sha256'],'bytecode binding'
    nodes,edges,_=graph(d);assert set(c['nodes'])==nodes,'node completeness'
    anchors=set(c['anchors']);assert anchors<=nodes,'unknown anchor'
    p={int(v):h for v,h in c['potential'].items()};assert set(p)==nodes,'potential completeness'
    assert all(type(v) is int and v>=0 for v in p.values()),'potential domain'
    for v in nodes:
        if v in anchors:assert p[v]==0,'anchor potential'
        else:
            assert p[v]>=1,'positive work'
            for w in edges[v]:assert p[v]>=1+p[w],'unobserved edge potential'
    b=max(p.values(),default=0)
    assert c['unobserved_run_bound']==b and c['work_per_receipt_bound']==b+1,'bound binding'
    return True
