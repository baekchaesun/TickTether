"""Read built-in iterator state without advancing it; never consumes an iterator.
Range layout: CPython 3.12 Objects/rangeobject.c and pycore_range.h.
"""
import ctypes

INDEX_TYPES={'list_iterator','list_reverseiterator','tuple_iterator','str_iterator','bytes_iterator','bytearray_iterator'}

def iterator_state(it):
    t=type(it)
    if t.__module__!='builtins':return None
    if t.__name__=='range_iterator':
        slots=(ctypes.c_long*3).from_address(id(it)+2*ctypes.sizeof(ctypes.c_void_p))
        return ['range',slots[0],slots[1],slots[2]]
    if t.__name__=='longrange_iterator':
        reduced=it.__reduce__();r=reduced[1][0]
        return ['longrange',r.start,r.step,len(r)]
    if t.__name__ in INDEX_TYPES:
        reduced=it.__reduce__()
        return ['index',reduced[2]] if len(reduced)>2 and type(reduced[2]) is int else None
    return None


def fault_restore_iterator(it,old):
    """Fault injection ONLY. The observation bridge never invokes this function."""
    if old[0]=='range':
        slots=(ctypes.c_long*3).from_address(id(it)+2*ctypes.sizeof(ctypes.c_void_p))
        slots[0],slots[1],slots[2]=old[1:];return
    if old[0]=='index':it.__setstate__(old[1]);return
    raise TypeError('no native fault adapter')
