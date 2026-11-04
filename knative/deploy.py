"""Build, deploy one Knative function and run its scoped host brokers."""
import argparse,base64,hashlib,json,os,subprocess,sys,tempfile,time
from pathlib import Path
ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT.parent))
from shared.runtime import build_knative
NAMESPACE=os.environ.get('CE_NAMESPACE','ce-knative')

def cpu(role):
    cpus=sorted(os.sched_getaffinity(0));index={'worker':-1,'controller':-2,'helper':-3}[role]
    chosen=int(os.environ.get('CE_'+role.upper()+'_CPU',cpus[index] if len(cpus)>=abs(index) else cpus[0]))
    if chosen not in cpus:raise ValueError('CPU outside current affinity')
    return chosen

def helper_image():return os.environ.get('CE_FUNCTION_IMAGE','ce-knative:local')
def kube(_experiment,*args,data=None,timeout=60):
    context=os.environ.get('CE_KNATIVE_CONTEXT')
    if not context:raise RuntimeError('set CE_KNATIVE_CONTEXT explicitly')
    r=subprocess.run(['kubectl','--context',context,*args],input=None if data is None else json.dumps(data),capture_output=True,text=True,timeout=timeout)
    if r.returncode:raise RuntimeError(r.stderr)
    return r.stdout

def documents():
    sources={name:(ROOT/name).read_text() for name in ['app.py','monitor.py','perf_client.py','symbols.json']}
    sources['detector.py']=(ROOT.parent/'shared/detector.py').read_text()
    binaries={name:base64.b64encode((ROOT/name).read_bytes()).decode() for name in ['worker','perf_bridge.so','sample_fast.so']}
    cm='ce-code-'+hashlib.sha256(json.dumps([sources,binaries],sort_keys=True).encode()).hexdigest()[:16]
    env=[{'name':'CE_CPU','value':str(cpu('worker'))},{'name':'CE_CONTROLLER_CPU','value':str(cpu('controller'))},{'name':'CE_EXTERNAL_PERF','value':'1'}]
    for name,field in [('POD_NAME','metadata.name'),('POD_UID','metadata.uid'),('NODE_NAME','spec.nodeName')]:env.append({'name':name,'valueFrom':{'fieldRef':{'fieldPath':field}}})
    container={'name':'function','image':helper_image(),'imagePullPolicy':'Never','command':['python','-B','/code/app.py'],'workingDir':'/code',
      'ports':[{'containerPort':8080}],'env':env,'resources':{'requests':{'cpu':'100m','memory':'128Mi'},'limits':{'cpu':'4','memory':'256Mi'}},
      'securityContext':{'allowPrivilegeEscalation':False,'capabilities':{'drop':['ALL']},'seccompProfile':{'type':'Unconfined'}},
      'volumeMounts':[{'name':'code','mountPath':'/code','readOnly':True},{'name':'perf-channel','mountPath':'/tmp'}]}
    return [
      {'apiVersion':'v1','kind':'Namespace','metadata':{'name':NAMESPACE}},
      {'apiVersion':'v1','kind':'ConfigMap','metadata':{'name':cm,'namespace':NAMESPACE},'immutable':True,'data':sources,'binaryData':binaries},
      {'apiVersion':'serving.knative.dev/v1','kind':'Service','metadata':{'name':'ce-main','namespace':NAMESPACE},'spec':{'template':{
        'metadata':{'annotations':{'autoscaling.knative.dev/min-scale':'1','autoscaling.knative.dev/max-scale':'1'}},
        'spec':{'containerConcurrency':1,'timeoutSeconds':60,'automountServiceAccountToken':False,'containers':[container],
          'volumes':[{'name':'code','configMap':{'name':cm,'defaultMode':365}},{'name':'perf-channel','emptyDir':{'sizeLimit':'1Mi'}}]}}}}
    ]

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--build-only',action='store_true');a=p.parse_args()
    build_knative(ROOT)
    if a.build_only:print('Native observer built')
    else:
        for doc in documents():print(kube(None,'apply','-f','-',data=doc).strip())
        print(kube(None,'wait','--for=condition=Ready','ksvc/ce-main','-n',NAMESPACE,'--timeout=180s',timeout=200))
        # Import the same module name used by broker.py when this file is __main__.
        sys.modules['deploy']=sys.modules[__name__]
        from broker import Brokers
        state=Path(tempfile.mkdtemp(prefix='ce-broker-'));brokers=Brokers(state)
        try:
            brokers.sync();print('Ready; brokers remain active while this process runs.',flush=True)
            print('Service:',json.loads(kube(None,'get','ksvc/ce-main','-n',NAMESPACE,'-o','json'))['status']['url'],flush=True)
            while True:time.sleep(1);brokers.sync()
        except KeyboardInterrupt:pass
        finally:brokers.close()
