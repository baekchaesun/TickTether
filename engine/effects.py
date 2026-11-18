"""Runtime effect models, independent of workload names and normal loop counts."""
import builtins

PURE_NAMES=('abs','all','any','bool','bytes','chr','complex','dict','divmod','float','frozenset','hex','int','len','list','max','min','oct','ord','pow','range','repr','reversed','round','set','sorted','str','sum','tuple')
PURE_IDS={id(getattr(builtins,n)) for n in PURE_NAMES}
MUTATORS={
 'list':{'append','extend','insert','pop','remove','clear','reverse','sort'},
 'dict':{'update','setdefault','pop','popitem','clear'},
 'set':{'add','update','remove','discard','pop','clear','difference_update','intersection_update','symmetric_difference_update'}
}
READ_METHODS={
 'list':{'count','index','copy'},'tuple':{'count','index'},
 'dict':{'get','keys','items','values','copy'},
 'set':{'copy','isdisjoint','issubset','issuperset','union','intersection','difference','symmetric_difference'},
 'str':{'lower','upper','casefold','strip','lstrip','rstrip','split','rsplit','splitlines','join','replace','find','rfind','index','rindex','count','startswith','endswith','isdigit','isalpha','isalnum','isspace'},
 'bytes':{'lower','upper','strip','split','replace','find','count'}
}
DISPATCH={'BINARY_OP','BINARY_SUBSCR','BINARY_SLICE','COMPARE_OP','CONTAINS_OP','GET_ITER','GET_LEN','UNPACK_SEQUENCE','UNPACK_EX','LOAD_ATTR'}
