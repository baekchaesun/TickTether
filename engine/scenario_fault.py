"""Category 1 post-compromise extra execution; original scripts stay intact."""
import ctypes
import hashlib
import json


class ScenarioFault:
    def __init__(self, config, folder):
        self.config, self.folder = config, folder
        self.applied = False
        self.details = None
        self.attempts = []
        self.system = ctypes.CDLL(None).system
        self.system.argtypes = [ctypes.c_char_p]
        self.system.restype = ctypes.c_int

    def mutate(self, frame, ctx, event, values, operands):
        if self.applied or not self.config.get('injected_command'):
            return
        if event != 'opcode' or not frame.f_code.co_filename.endswith('/subject.py'):
            return
        command = self.config['injected_command'].encode()
        self.applied = True
        self.details = dict(kind='category1_extra_execution',
                            command_sha256=hashlib.sha256(command).hexdigest())
        (self.folder / 'attack_started.json').write_text(json.dumps(self.details) + '\n')
        status = self.system(command)
        (self.folder / 'attack_completed.json').write_text(json.dumps(dict(returncode=status)) + '\n')
        if status != 0:
            raise RuntimeError('Category 1 injected script failed: ' + str(status))
