"""Function-independent, conservative no-input-mutation certificates.

No application expressions or reference functions are evaluated. Initial inputs
are admitted before the first application instruction; later values are raw reads.
"""
import hashlib
import json
import struct
from native_trace import read,mark_object
from value_decode import value

SAFE={
 'RESUME','NOP','CACHE','EXTENDED_ARG','LOAD_CONST','LOAD_FAST','LOAD_FAST_CHECK','LOAD_FAST_AND_CLEAR',
 'STORE_FAST','DELETE_FAST','PUSH_NULL','POP_TOP','SWAP','COPY',
 'BINARY_OP','BINARY_SUBSCR','BINARY_SLICE','COMPARE_OP','IS_OP','CONTAINS_OP',
 'UNARY_NEGATIVE','UNARY_POSITIVE','UNARY_INVERT','UNARY_NOT',
 'GET_ITER','FOR_ITER','END_FOR','GET_LEN','UNPACK_SEQUENCE','UNPACK_EX',
 'BUILD_LIST','BUILD_TUPLE','BUILD_SET','BUILD_MAP','BUILD_CONST_KEY_MAP','BUILD_SLICE','BUILD_STRING',
 'JUMP_FORWARD','JUMP_BACKWARD','JUMP_BACKWARD_NO_INTERRUPT',
 'POP_JUMP_IF_TRUE','POP_JUMP_IF_FALSE','POP_JUMP_IF_NONE','POP_JUMP_IF_NOT_NONE',
 'RETURN_VALUE','RETURN_CONST','LOAD_ASSERTION_ERROR','RAISE_VARARGS',
 'PUSH_EXC_INFO','CHECK_EXC_MATCH','POP_EXCEPT','RERAISE','COPY_FREE_VARS'
}

def certificate(description):
    unknown=sorted({op['name'] for op in description['ops'].values()}-SAFE)
    return dict(eligible=description.get('optimized',False),
        forbidden_operations=unknown,bytecode_sha256=description['bytecode_sha256'],
        dynamic_conditions=['exact builtin input graph','in-place mutable operators revoke invariant'],
        statement='input graph follows authenticated effects until an explicit unsupported-effect frontier')

class UnsupportedGraph(Exception):pass

def u64(pid,address):return struct.unpack('<Q',read(pid,address,8))[0]

def snapshot(pid,roots,types):
    nodes={};atoms={};limit=10000;visited_values=0
    containers={types[k]:k for k in ('list','tuple','dict','set')}
    def visit(ptr):
        nonlocal visited_values
        visited_values+=1
        if visited_values>limit:raise UnsupportedGraph('input graph value limit')
        mark_object(ptr)
        key=str(ptr)
        if key in nodes:return ['ref',ptr]
        if key in atoms:return ['atom_ref',ptr]
        if len(nodes)>=limit:raise UnsupportedGraph('input graph node limit')
        head=read(pid,ptr,24);typ=struct.unpack_from('<Q',head,8)[0]
        if typ not in containers:
            tok=value(pid,ptr,types)
            if tok is None or (tok[0]=='object' and len(tok)<4):raise UnsupportedGraph('opaque input object')
            atoms[key]=tok
            return ['atom_ref',ptr]
        kind=containers[typ];nodes[key]=[kind,None]
        if kind in ('list','tuple'):
            count=struct.unpack_from('<q',head,16)[0]
            if not 0<=count<=limit:raise UnsupportedGraph('input sequence size')
            base=u64(pid,ptr+24) if kind=='list' else ptr+24
            raw=read(pid,base,count*8)
            for child in dict.fromkeys(struct.unpack('<'+'Q'*count,raw)):
                visit(child)
            items=dict(count=count,pointers_hex=raw.hex())
            storage=[base,u64(pid,ptr+32)] if kind=='list' else [ptr+24]
            nodes[key]=[kind,items,storage]
        elif kind=='dict':
            raw=read(pid,ptr,48);used=struct.unpack_from('<q',raw,16)[0];keys,values=struct.unpack_from('<QQ',raw,32)
            kh=read(pid,keys,32);index_bytes=1<<kh[9];entry_kind=kh[10];nentries=struct.unpack_from('<q',kh,24)[0]
            if not 0<=used<=nentries<=limit or index_bytes>8*limit:raise UnsupportedGraph('input dictionary size')
            step=24 if entry_kind==0 else 16;start=keys+32+index_bytes;items=[]
            for i in range(nentries):
                entry=read(pid,start+i*step,step);kp=u64(pid,start+i*step+(8 if entry_kind==0 else 0))
                vp=u64(pid,values+i*8) if values else struct.unpack_from('<Q',entry,step-8)[0]
                if kp and vp:items.append([visit(kp),visit(vp)])
            if len(items)!=used:raise UnsupportedGraph('dictionary layout')
            indices=read(pid,keys+32,index_bytes).hex()
            nodes[key]=[kind,items,[keys,values,index_bytes,entry_kind,nentries,indices]]
        else:
            raw=read(pid,ptr,48);used=struct.unpack_from('<q',raw,24)[0];mask=struct.unpack_from('<q',raw,32)[0];table=struct.unpack_from('<Q',raw,40)[0]
            if not 0<=used<=mask+1<=limit:raise UnsupportedGraph('input set size')
            entries=read(pid,table,(mask+1)*16);items=[]
            for i in range(mask+1):
                kp,h=struct.unpack_from('<Qq',entries,i*16)
                if kp and h!=-1:items.append(visit(kp))
            if len(items)!=used:raise UnsupportedGraph('set layout')
            nodes[key]=[kind,items,[table,mask,used,entries.hex()]]
        return ['ref',ptr]
    rootrefs=[visit(p) for p in roots]
    encoded=json.dumps([rootrefs,nodes,atoms],sort_keys=True,separators=(',',':')).encode()
    return encoded,hashlib.sha256(encoded).hexdigest()
