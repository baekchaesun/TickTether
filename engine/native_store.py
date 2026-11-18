"""Identify 64-bit pointer stores in the exact trusted VM executable."""
import re
import subprocess

_CACHE={}
REG64=r'(?:r(?:ax|bx|cx|dx|si|di|bp|sp|8|9|1[0-5]))'

def pointer_store_ends(executable):
    if executable in _CACHE:return _CACHE[executable]
    text=subprocess.run(['objdump','-d','--no-show-raw-insn',executable],capture_output=True,text=True,check=True).stdout
    rows=[]
    for line in text.splitlines():
        match=re.match(r'^\s*([0-9a-f]+):\s+(\S+)\s*(.*)$',line)
        if match:rows.append((int(match[1],16),match[2],match[3]))
    valid=set()
    for (_,op,args),(nxt,_,_) in zip(rows,rows[1:]):
        if op=='movq' and ',' in args and '(' in args.split(',',1)[1]:valid.add(nxt)
        elif op in ('mov','movabs','xchg') and re.match(r'%'+REG64+r',',args) and '(' in args.split(',',1)[1]:valid.add(nxt)
    if not valid:raise RuntimeError('native pointer-store decoder found no sites')
    _CACHE[executable]=valid;return valid
