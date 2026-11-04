"""Build and run the shared detector used locally and by Runpod."""
import argparse,hashlib,json,os,subprocess,time
from pathlib import Path
ROOT=Path(__file__).resolve().parent

def build_shared():
    source=ROOT/'worker.c';target=ROOT/'build/worker_sp1'
    stamp=ROOT/'build/source.sha256';digest=hashlib.sha256(source.read_bytes()).hexdigest()
    assets=[ROOT/'assets'/size/(f'image{k}.ppm' if kind=='image' else f'file{k}.bin') for size in ('small','large') for k in range(4) for kind in ('image','file')]
    if target.exists() and target.with_suffix('.symbols.json').exists() and stamp.exists() and stamp.read_text()==digest and all(p.exists() for p in assets):return
    target.parent.mkdir(exist_ok=True)
    subprocess.run(['gcc','-O0','-g','-Wall','-Wextra','-fno-pie','-no-pie','-fno-omit-frame-pointer',str(source),'-ldl','-o',str(target)],check=True)
    symbols={}
    for line in subprocess.check_output(['nm','-n',str(target)],text=True).splitlines():
        row=line.split()
        if len(row)==3 and row[2].startswith('ce_'):symbols[row[2]]=int(row[0],16)
    assert {'ce_head','ce_body','ce_taskdone','ce_done','ce_state','ce_request'}<=set(symbols)
    target.with_suffix('.symbols.json').write_text(json.dumps(symbols))
    for size,side,n in [('small',128,16384),('large',512,262144)]:
        folder=ROOT/'assets'/size;folder.mkdir(parents=True,exist_ok=True)
        for k in range(4):
            stream=b''.join(hashlib.sha256(f'SP1-{k}-{i}'.encode()).digest() for i in range((side*side*3+31)//32))
            (folder/f'image{k}.ppm').write_bytes(f'P6\n{side} {side}\n255\n'.encode()+stream[:side*side*3])
            data=stream[:4096]+b'cost-exposure-public-fixture\n'*32
            (folder/f'file{k}.bin').write_bytes((data*((n+len(data)-1)//len(data)))[:n])
    stamp.write_text(digest)

def build_knative(folder):
    folder=Path(folder);worker=folder/'worker'
    subprocess.run(['gcc','-O0','-g','-Wall','-Wextra','-fno-pie','-no-pie','-fno-omit-frame-pointer',str(folder/'worker.c'),'-ldl','-o',str(worker)],check=True)
    symbols={}
    for line in subprocess.check_output(['nm','-n',str(worker)],text=True).splitlines():
        row=line.split()
        if len(row)==3 and row[2].startswith('ce_'):symbols[row[2]]=int(row[0],16)
    (folder/'symbols.json').write_text(json.dumps(symbols))
    subprocess.run(['gcc','-O2','-fPIC','-shared',str(folder/'perf_bridge.c'),'-o',str(folder/'perf_bridge.so')],check=True)
    subprocess.run(['gcc','-O2','-fPIC','-shared',str(folder/'sample_fast.c'),'-ldl','-o',str(folder/'sample_fast.so')],check=True)
    subprocess.run(['gcc','-O2',str(folder/'native_broker.c'),'-o',str(folder/'native_broker')],check=True)

def run(job):
    build_shared()
    try:from .observer import execute
    except ImportError:from observer import execute
    if not isinstance(job,dict) or 'request' not in job:raise ValueError('request object required')
    scenario=job.get('scenario');backend=job.get('backend','SP1')
    if type(job.get('audit',False)) is not bool or type(job.get('recover',True)) is not bool:raise ValueError('audit/recover must be boolean')
    if backend not in ('I1','O1','SP1'):raise ValueError('backend')
    if job['request']['workload'] not in (3,4):raise ValueError('workload must be image=3 or compression=4')
    cpu=job.get('cpu',min(os.sched_getaffinity(0)))
    if cpu not in os.sched_getaffinity(0):raise ValueError('CPU outside process affinity')
    options=dict(backend=backend,p=95,cpu=cpu,audit=job.get('audit',False),
                 key_hex=job.get('key_hex'),path=job.get('path',0),asset_size=job.get('asset_size','small'))
    if options['asset_size'] not in ('small','large'):raise ValueError('asset_size')
    start=time.monotonic_ns();cpu_start=time.process_time_ns()
    attempts=[execute(job['request'],scenario,recover=job.get('recover',True),**options)]
    if attempts[-1]['terminated']:attempts.append(execute(job['request'],None,**options))
    return {'implementation':'minimal-runtime-v1','attempts':attempts,'reply':attempts[-1]['reply'],
            'recovered':len(attempts)==2,'elapsed_ns':time.monotonic_ns()-start,
            'owned_cpu_ns':time.process_time_ns()-cpu_start+sum(a['worker_cpu_ns'] for a in attempts)}

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--build-only',action='store_true');p.add_argument('--build-knative',action='store_true')
    p.add_argument('--workload',choices=['image','compression'],default='image');p.add_argument('--fault',choices=['rewind','inflate_bound'])
    p.add_argument('--extra',type=int,default=4);p.add_argument('--late',action='store_true');p.add_argument('--no-recover',action='store_true')
    a=p.parse_args()
    if a.build_knative:build_knative(ROOT.parent/'knative')
    elif a.build_only:build_shared()
    else:
        job={'request':{'workload':3 if a.workload=='image' else 4,'passes':1,'seed':0,'values':[2,3],'runtime_paths':0,'wait_ms':0},'recover':not a.no_recover}
        if a.fault:job['scenario']={'family':a.fault,'extra':a.extra,'position':'late' if a.late else 'early'}
        print(json.dumps(run(job),separators=(',',':')))
