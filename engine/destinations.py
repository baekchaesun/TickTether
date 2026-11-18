"""VM storage destinations, independent of function-specific normal progress."""
import dis


def plan(op,depth):
    name=op.opname;arg=op.arg or 0;start=depth;outputs=[];known=True
    if name in ('LOAD_CONST','LOAD_FAST','LOAD_FAST_CHECK','LOAD_FAST_AND_CLEAR','LOAD_DEREF','LOAD_CLOSURE','LOAD_NAME','LOAD_BUILD_CLASS','LOAD_ASSERTION_ERROR'):
        outputs=[depth]
    elif name=='PUSH_NULL':outputs=[depth]
    elif name=='LOAD_GLOBAL':outputs=list(range(depth,depth+1+(arg&1)))
    elif name=='LOAD_ATTR':
        start=depth-1;outputs=list(range(start,start+1+(arg&1)))
    elif name in ('BINARY_OP','BINARY_SUBSCR','COMPARE_OP','IS_OP','CONTAINS_OP'):
        start=depth-2;outputs=[start]
    elif name=='BINARY_SLICE':start=depth-3;outputs=[start]
    elif name=='LOAD_SUPER_ATTR':start=depth-3;outputs=list(range(start,start+1+(arg&1)))
    elif name.startswith('UNARY_') or name in ('GET_ITER','GET_YIELD_FROM_ITER','GET_AWAITABLE','GET_AITER','ASYNC_GEN_WRAP','LIST_TO_TUPLE','TO_BOOL'):
        start=depth-1;outputs=[start]
    elif name in ('STORE_FAST','STORE_DEREF','STORE_NAME','STORE_GLOBAL','POP_TOP','RETURN_VALUE','YIELD_VALUE'):
        start=depth-1
    elif name in ('STORE_ATTR',):start=depth-2
    elif name=='STORE_SUBSCR':start=depth-3
    elif name=='STORE_SLICE':start=depth-4
    elif name=='DELETE_SUBSCR':start=depth-2
    elif name=='CALL':start=depth-arg-2;outputs=[start]
    elif name=='CALL_FUNCTION_EX':start=depth-(4 if arg&1 else 3);outputs=[start]
    elif name in ('BUILD_LIST','BUILD_TUPLE','BUILD_SET','BUILD_STRING'):
        start=depth-arg;outputs=[start]
    elif name=='BUILD_MAP':start=depth-2*arg;outputs=[start]
    elif name=='BUILD_CONST_KEY_MAP':start=depth-arg-1;outputs=[start]
    elif name=='BUILD_SLICE':start=depth-arg;outputs=[start]
    elif name=='UNPACK_SEQUENCE':start=depth-1;outputs=list(range(start,start+arg))
    elif name=='UNPACK_EX':start=depth-1;outputs=list(range(start,start+(arg&255)+(arg>>8)+1))
    elif name=='COPY':outputs=[depth]
    elif name=='SWAP':start=depth-arg;outputs=[depth-arg,depth-1]
    elif name=='FOR_ITER':outputs=[depth]
    elif name=='SEND':start=depth-1;outputs=[start]
    elif name=='END_SEND':start=depth-2;outputs=[start]
    elif name=='MAKE_FUNCTION':start=depth-1-sum(bool(arg&flag) for flag in (1,2,4,8));outputs=[start]
    elif name=='CALL_INTRINSIC_1':start=depth-1;outputs=[start]
    elif name=='CALL_INTRINSIC_2':start=depth-2;outputs=[start]
    elif name in ('GET_LEN','MATCH_MAPPING','MATCH_SEQUENCE','MATCH_KEYS','GET_ANEXT','WITH_EXCEPT_START'):outputs=[depth]
    elif name=='MATCH_CLASS':start=depth-3;outputs=[start]
    elif name=='FORMAT_VALUE':start=depth-(2 if arg&4 else 1);outputs=[start]
    elif name in ('BEFORE_WITH','BEFORE_ASYNC_WITH'):start=depth-1;outputs=[start,start+1]
    elif name in ('LIST_EXTEND','SET_UPDATE','DICT_UPDATE','DICT_MERGE','POP_EXCEPT'):start=depth-1
    elif name=='END_FOR':start=depth-1
    elif name=='RERAISE':start=depth-1
    elif name=='RAISE_VARARGS':start=depth-arg
    elif name=='CLEANUP_THROW':start=depth-3;outputs=[start]
    elif name in ('PUSH_EXC_INFO',):start=depth-1;outputs=[start,start+1]
    elif name=='CHECK_EXC_MATCH':start=depth-1;outputs=[start]
    elif name in ('IMPORT_NAME',):start=depth-2;outputs=[start]
    elif name=='IMPORT_FROM':outputs=[depth]
    elif name.startswith('POP_JUMP') or name in ('JUMP_IF_TRUE_OR_POP','JUMP_IF_FALSE_OR_POP'):
        start=depth-1
    elif name in ('LIST_APPEND','SET_ADD'):start=depth-1
    elif name in ('MAP_ADD',):start=depth-2
    elif name in ('RESUME','NOP','CACHE','EXTENDED_ARG','JUMP_FORWARD','JUMP_BACKWARD','JUMP_BACKWARD_NO_INTERRUPT','RETURN_CONST','KW_NAMES','COPY_FREE_VARS','MAKE_CELL','RETURN_GENERATOR','DELETE_FAST','DELETE_DEREF','DELETE_NAME','DELETE_GLOBAL'):
        pass
    else:
        # Unsupported producer forms are explicit coverage gaps, not inferred values.
        start=0;known=False
    return dict(invalidate_from=max(0,start),outputs=[v for v in outputs if v>=0],known=known,
                hardware_overflow=len(outputs)>3)
