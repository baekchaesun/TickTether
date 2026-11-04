"""HTTP wrapper for the final kernel/debugger observer."""
import json,os,socket,threading,time
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from monitor import execute
LOCK=threading.Lock()

def run_job(job):
    q=job['request'];lab=job.get('lab',{})
    if set(q)!={'workload','passes','seed','values','runtime_paths','wait_ms'}:raise ValueError('request fields')
    if any(type(q[k]) is not int for k in ('workload','passes','seed','runtime_paths','wait_ms')):raise ValueError('integer request')
    if not (0<=q['workload']<=2 and 1<=q['passes']<=2 and 0<=q['seed']<2**63):raise ValueError('request range')
    if not isinstance(q['values'],list) or len(q['values'])!=2 or any(type(v) is not int or not 1<=v<=12 for v in q['values']):raise ValueError('work bounds')
    if q['runtime_paths'] not in (0,1) or not 0<=q['wait_ms']<=100:raise ValueError('normal mode')
    backend=lab.get('backend','kernel');recover=lab.get('recover',True)
    if backend not in ('kernel','debugger','untraced'):raise ValueError('backend')
    scenario=lab.get('scenario')
    if scenario and (scenario.get('family') not in ('rewind','inflate_bound') or scenario.get('position') not in ('early','late') or type(scenario.get('extra')) is not int or not 1<=scenario['extra']<=32):raise ValueError('scenario')
    worker_cpu=int(os.environ['CE_CPU']);controller=int(os.environ['CE_CONTROLLER_CPU'])
    os.sched_setaffinity(0,{controller})
    started=time.monotonic_ns()
    args=(backend,95,worker_cpu,lab.get('audit',False))
    attempts=[execute(q,scenario,*args,recover)]
    if attempts[-1]['terminated']:attempts.append(execute(q,None,*args,False))
    return {'implementation':'minimal-runtime-v1','attempts':attempts,'reply':attempts[-1]['reply'],'recovered':len(attempts)==2,'elapsed_ns':time.monotonic_ns()-started}

class Handler(BaseHTTPRequestHandler):
    protocol_version='HTTP/1.1'
    def log_message(self,*args):pass
    def respond(self,status,value):
        data=json.dumps(value,separators=(',',':')).encode()
        self.send_response(status);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)
    def do_GET(self):self.respond(200,{'ready':True})
    def do_POST(self):
        try:
            self.connection.settimeout(60);self.connection.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1)
            n=int(self.headers.get('Content-Length','0'))
            if not 0<n<=8192:raise ValueError('request size')
            job=json.loads(self.rfile.read(n))
            with LOCK:result=run_job(job)
            self.respond(200,result)
        except Exception as e:self.respond(500,{'error':type(e).__name__+': '+str(e)})

if __name__=='__main__':ThreadingHTTPServer(('0.0.0.0',int(os.environ.get('PORT','8080'))),Handler).serve_forever()
