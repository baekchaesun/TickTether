"""Decode actual primitive values copied at an own-child native store trap."""
import struct
from native_trace import read,mark_object


def content(pid,pointer,types):
    if not pointer:return ['null']
    mark_object(pointer)
    head=read(pid,pointer,24);typ=struct.unpack_from('<Q',head,8)[0]
    if pointer==types['none']:return ['none']
    if typ==types['bool']:return ['bool',pointer==types['true']]
    if typ==types.get('range'):
        fields=[]
        for off in (16,24,32,40):
            p=struct.unpack('<Q',read(pid,pointer+off,8))[0];t=struct.unpack('<Q',read(pid,p+8,8))[0]
            if t==types['int']:fields.append(content(pid,p,types)+[p])
            else:fields.append(['object',t,p])
        return ['object',typ,pointer,['range_state',fields]]
    if typ==types['int']:
        tag=struct.unpack_from('<Q',head,16)[0];size=tag>>3
        if size>8192:return None
        digits=read(pid,pointer+24,size*4);result=0
        for i in range(size-1,-1,-1):result=(result<<30)|struct.unpack_from('<I',digits,i*4)[0]
        if tag&3==2:result=-result
        return ['int',hex(result)]
    if typ==types['float']:return ['float',read(pid,pointer+16,8).hex()]
    if typ==types['complex']:return ['complex',read(pid,pointer+16,16).hex()]
    if typ==types['bytes']:
        length=struct.unpack_from('<q',head,16)[0]
        if 0<=length<=1000000:return ['bytes',read(pid,pointer+32,length).hex()]
    if typ==types['str']:
        raw=read(pid,pointer,40);length=struct.unpack_from('<q',raw,16)[0];state=struct.unpack_from('<I',raw,32)[0]
        kind=(state>>2)&7;compact=(state>>5)&1;ascii_flag=(state>>6)&1
        if compact and kind in (1,2,4) and 0<=length<=1000000:
            data=read(pid,pointer+(40 if ascii_flag else 56),length*kind)
            encoding='latin-1' if kind==1 else 'utf-16-le' if kind==2 else 'utf-32-le'
            return ['str',data.decode(encoding,errors='surrogatepass')]
    return ['object',typ,pointer]

def value(pid,pointer,types):
    result=content(pid,pointer,types)
    if result is None or result[0] in ('object','null'):return result
    return result+[pointer]
