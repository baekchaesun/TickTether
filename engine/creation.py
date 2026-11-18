"""Typed completion of actual list writes; no source evaluation or replay."""
from dataclasses import dataclass, field


@dataclass
class ListAppendLease:
    receiver: int
    old_size: int
    old_capacity: int
    old_items: int
    argument: int
    seen: dict = field(default_factory=dict)
    items: int = 0

    def __post_init__(self):
        self.items=self.old_items
        self.resize=self.old_size>=self.old_capacity

    def pending(self):
        roles={'size':self.receiver+16}
        if self.resize:
            roles['items']=self.receiver+24;roles['capacity']=self.receiver+32
            if 'items' in self.seen:roles['element']=self.items+8*self.old_size
        else:roles['element']=self.items+8*self.old_size
        return {r:a for r,a in roles.items() if r not in self.seen}

    def targets(self):
        result=list(self.pending().values())
        if len(result)>3:raise AssertionError('hardware slot budget')
        return result

    def consume(self,address,word):
        role=next((r for r,a in self.pending().items() if a==address),None)
        if role is None:raise ValueError('write outside typed effect lease')
        if role=='size' and word!=self.old_size+1:raise ValueError('append size effect')
        if role=='capacity' and word<self.old_size+1:raise ValueError('append capacity effect')
        if role=='element' and word!=self.argument:raise ValueError('append argument binding')
        if role=='items':
            if not word or word%8:raise ValueError('append storage alignment')
            self.items=word
        self.seen[role]=word
        required={'size','element'}|({'items','capacity'} if self.resize else set())
        return required<=self.seen.keys()
