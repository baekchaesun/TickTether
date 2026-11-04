"""Single-concurrency Runpod handler using the shared runtime."""
import json,sys,threading
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent.parent))
from shared.runtime import run
LOCK=threading.Lock()

def handler(event):
    if not LOCK.acquire(blocking=False):raise RuntimeError('one request at a time')
    try:
        # A JSON string preserves 64-bit output values through provider transports.
        return {'encoding':'json-string','result':json.dumps(run(event['input']),separators=(',',':'))}
    finally:LOCK.release()

if __name__=='__main__':
    import runpod
    runpod.serverless.start({'handler':handler,'concurrency_modifier':lambda _:1})
