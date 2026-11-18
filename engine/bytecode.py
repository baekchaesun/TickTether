"""Generic bytecode CFG, exception entries and operand-stack depths (no execution)."""
import collections
import dis
import hashlib
import types

VERSION='TickTether-C1-v1'


def functions(code):
    yield code
    for value in code.co_consts:
        if isinstance(value,types.CodeType):yield from functions(value)


def description(code):
    rows=list(dis.get_instructions(code));by={v.offset:v for v in rows}
    positions={v.offset:i for i,v in enumerate(rows)}
    nexts={v.offset:rows[i+1].offset if i+1<len(rows) else None for i,v in enumerate(rows)}
    handlers=list(dis.Bytecode(code).exception_entries)
    heights={};queue=collections.deque([(rows[0].offset,0)])
    for row in rows:
        if row.opname=='RETURN_GENERATOR' and nexts[row.offset] is not None:queue.append((nexts[row.offset],1))
    for h in handlers:queue.append((h.target,h.depth+1+int(h.lasti)))
    conflicts=[]
    while queue:
        offset,depth=queue.popleft()
        if offset not in by:continue
        if offset in heights:
            if heights[offset]!=depth:conflicts.append((offset,heights[offset],depth))
            continue
        heights[offset]=depth;op=by[offset];name=op.opname
        if name in ('RETURN_VALUE','RETURN_CONST','RAISE_VARARGS','RERAISE','RETURN_GENERATOR'):continue
        jump=op.opcode in dis.hasjabs or op.opcode in dis.hasjrel
        unconditional=name.startswith('JUMP') and 'IF' not in name
        paths=[(op.argval,True)] if unconditional else ([(nexts[offset],False),(op.argval,True)] if jump else [(nexts[offset],None)])
        for target,taken in paths:
            if target is None:continue
            kw={} if taken is None else {'jump':taken}
            effect=dis.stack_effect(op.opcode,op.arg,**kw) if op.arg is not None else dis.stack_effect(op.opcode,**kw)
            queue.append((target,depth+effect))
    if conflicts:raise ValueError('inconsistent abstract stack depths: '+repr(conflicts))
    return dict(code=code,ops=by,next=nexts,depth=heights,handlers=handlers,
                first=nexts[rows[0].offset],bytecode_sha256=hashlib.sha256(code.co_code).hexdigest())
