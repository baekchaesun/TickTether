"""Read-only CPython 3.12 frame/operand observations; no expression evaluation.
Layout: CPython v3.12.3 Include/internal/pycore_frame.h.
"""
import ctypes
import struct
import sys
import types

class FrameHead(ctypes.Structure):
    _fields_=[('refcnt',ctypes.c_ssize_t),('type',ctypes.c_void_p),('back',ctypes.c_void_p),('frame',ctypes.c_void_p)]

class InterpreterHead(ctypes.Structure):
    _fields_=[('code',ctypes.c_void_p),('previous',ctypes.c_void_p),('func',ctypes.c_void_p),
              ('globals',ctypes.c_void_p),('builtins',ctypes.c_void_p),('locals',ctypes.c_void_p),
              ('frame_obj',ctypes.c_void_p),('previous_instruction',ctypes.c_void_p),
              ('stacktop',ctypes.c_int),('return_offset',ctypes.c_uint16),('owner',ctypes.c_ubyte)]

assert ctypes.sizeof(InterpreterHead)==72
NULL=object()


def content_token(value):
    t=type(value)
    if value is None:return ['none']
    if t is bool:return ['bool',value]
    if t is int:return ['int',hex(value)]
    if t is float:return ['float',struct.pack('<d',value).hex()]
    if t is complex:return ['complex',struct.pack('<dd',value.real,value.imag).hex()]
    if t is str:return ['str',value]
    if t is bytes:return ['bytes',value.hex()]
    return ['object',id(t),id(value)]

def token(value):
    if type(value) is range:
        ptrs=(ctypes.c_void_p*4).from_address(id(value)+16)
        fields=[]
        for p in ptrs:
            v=ctypes.cast(p,ctypes.py_object).value
            t=content_token(v);fields.append(t if t[0]=='object' else t+[id(v)])
        return ['object',id(range),id(value),['range_state',fields]]
    result=content_token(value)
    return result if result[0]=='object' else result+[id(value)]


def stack(frame,depth=None):
    if sys.version_info[:2]!=(3,12):raise RuntimeError('CPython 3.12 frame layout required')
    raw=FrameHead.from_address(id(frame))
    head=InterpreterHead.from_address(raw.frame)
    if head.code!=id(frame.f_code):raise RuntimeError('frame code layout mismatch')
    code=frame.f_code
    base=code.co_nlocals+sum(n not in code.co_varnames for n in code.co_cellvars)+len(code.co_freevars)
    top=head.stacktop if depth is None else base+depth
    if not base<=top<=base+code.co_stacksize:
        raise RuntimeError(f'invalid materialized operand stack {head.stacktop}, expected {base}..{base+code.co_stacksize}')
    count=top-base
    ptrs=(ctypes.c_void_p*count).from_address(raw.frame+ctypes.sizeof(InterpreterHead)+base*ctypes.sizeof(ctypes.c_void_p))
    return [NULL if not ptr else ctypes.cast(ptr,ctypes.py_object).value for ptr in ptrs]


def local_tokens(frame):
    return {k:token(v) for k,v in frame.f_locals.items()}


def locals_and_bindings(frame, frame_id, holds=None):
    """Read fast locals without refreshing the application's locals() dictionary."""
    raw=FrameHead.from_address(id(frame));head=InterpreterHead.from_address(raw.frame)
    if head.code!=id(frame.f_code):raise RuntimeError('frame code layout mismatch')
    code=frame.f_code
    if not code.co_flags & 1:  # CO_OPTIMIZED
        mapping=ctypes.cast(head.locals,ctypes.py_object).value if head.locals else {}
        if type(mapping) is not dict:raise RuntimeError('opaque locals mapping')
        values=dict(mapping)
        return values,{k:f'namespace:{id(mapping)}:{k}' for k in values}
    names=list(code.co_varnames)+[n for n in code.co_cellvars if n not in code.co_varnames]+list(code.co_freevars)
    ptrs=(ctypes.c_void_p*len(names)).from_address(raw.frame+ctypes.sizeof(InterpreterHead))
    values={};bindings={}
    for name,ptr in zip(names,ptrs):
        if not ptr:continue
        value=ctypes.cast(ptr,ctypes.py_object).value
        if name in code.co_cellvars or name in code.co_freevars:
            if type(value) is not types.CellType:raise RuntimeError('cell layout mismatch')
            if holds is not None:holds[id(value)]=value
            bindings[name]=f'cell:{id(value)}'
            try:value=value.cell_contents
            except ValueError:continue
        else:bindings[name]=f'frame:{frame_id}:{name}'
        values[name]=value
    return values,bindings
