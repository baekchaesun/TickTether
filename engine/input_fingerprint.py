"""Evaluation-only initial-input fingerprints, no application callbacks."""
import hashlib
import json
from frame_access import content_token

def fingerprint(values):
    memo={};opaque=False;visited=0
    def visit(v):
        nonlocal opaque,visited
        visited+=1
        if visited>100000:raise ValueError('input fingerprint size bound')
        pointer=id(v)
        if pointer in memo:return ['ref',memo[pointer]]
        number=len(memo);memo[pointer]=number;t=type(v)
        if v is None or t in (bool,int,float,complex,str,bytes):return ['value',number,content_token(v)]
        if t in (list,tuple):return ['sequence',number,'list'if t is list else'tuple',[visit(x)for x in v]]
        if t is dict:return ['dict',number,[[visit(k),visit(x)]for k,x in v.items()]]
        if t in (set,frozenset):return ['set',number,[visit(x)for x in v]]
        if t is range:return ['range',number,v.start,v.stop,v.step]
        opaque=True;return ['opaque',number]
    raw=json.dumps([[name,visit(v)]for name,v in sorted(values.items())],sort_keys=True,separators=(',',':'))
    return dict(sha256=hashlib.sha256(raw.encode()).hexdigest(),closed_builtin_inputs=not opaque)
