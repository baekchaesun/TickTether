"""Actual VM instruction-frontier receipts, independent of normal ordinals."""
class RetirementLease:
    def __init__(self, marker, initial_word, offset, allowed):
        self.marker=marker;self.initial_word=initial_word;self.offset=offset
        self.allowed=set(allowed);self.completed=False
    def observe(self,word):
        offset=self.offset+word-self.initial_word
        if word!=self.initial_word and offset in self.allowed:
            self.completed=True
        return offset,self.completed
