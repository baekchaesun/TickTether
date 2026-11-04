"""Launch read-only host observers only for this study's function cgroups."""
import json
import hashlib
from pathlib import Path
import subprocess
import threading

from deploy import ROOT,kube,cpu,helper_image,NAMESPACE

class Brokers:
    def __init__(self,out):
        self.out=Path(out);self.items={};self.lock=threading.RLock()
    def sync(self):
        with self.lock:self._sync()
    def _sync(self):
        service=json.loads(kube('paper_main','get','ksvc','ce-main','-n',NAMESPACE,'-o','json'))
        current_revision=service['status']['latestReadyRevisionName']
        pods=json.loads(kube('paper_main','get','pods','-n',NAMESPACE,'-o','json'))['items']
        for pod in pods:
            if not pod['metadata']['labels'].get('serving.knative.dev/service')=='ce-main':continue
            if pod['metadata']['labels'].get('serving.knative.dev/revision')!=current_revision:continue
            if pod['metadata'].get('deletionTimestamp'):continue
            status=next((c for c in pod.get('status',{}).get('containerStatuses',[]) if c['name']=='function' and c.get('state',{}).get('running')),None)
            if status is None:continue
            uid=pod['metadata']['uid']
            if uid in self.items:continue
            cid=status['containerID'].split('://',1)[1]
            matches=list(Path('/sys/fs/cgroup').rglob('*'+cid+'.scope'))
            assert len(matches)==1,matches
            cgroup=matches[0]
            assert uid.replace('-','_') in str(cgroup) or uid in str(cgroup)
            node=pod['spec']['nodeName']
            mounts=json.loads(subprocess.check_output(['docker','inspect',node,'--format','{{json .Mounts}}'],text=True))
            node_var=next(m['Source'] for m in mounts if m['Destination']=='/var')
            channel=f'{node_var}/lib/kubelet/pods/{uid}/volumes/kubernetes.io~empty-dir/perf-channel'
            name='ce-perf-broker-'+uid[:8]
            command=['docker','run','--rm','-i','--name',name,'--network=none','--pid=host','--read-only',
                     '--cap-drop=ALL','--cap-add=PERFMON','--cap-add=SYS_PTRACE',
                     '--security-opt=no-new-privileges','--security-opt=seccomp=unconfined',
                     '--security-opt=apparmor=unconfined',
                     '--pids-limit=8','--memory=96m','--cpus=1','--cpuset-cpus='+str(cpu('helper')),
                     '--mount',f'type=bind,src={ROOT},dst=/work,readonly',
                     '--mount','type=bind,src=/sys/fs/cgroup,dst=/sys/fs/cgroup,readonly',
                     '--mount',f'type=bind,src={channel},dst=/channel,readonly',
                     helper_image(),'python','-B','/work/perf_broker.py',str(cgroup),uid,cid]
            if self.out.name.startswith('smoke'):command.append('--self-test')
            log=(self.out/('broker-'+uid[:8]+'.stderr')).open('w')
            proc=subprocess.Popen(command,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=log,text=True)
            ready=proc.stdout.readline()
            if not ready:
                proc.wait(timeout=3);log.close();raise RuntimeError(f'broker failed for owned pod {uid}; inspect stderr')
            info=json.loads(ready);assert info['ready'] and info['pod_uid']==uid
            helper_pid=json.loads(subprocess.check_output(['docker','inspect',name],text=True))[0]['State']['Pid']
            helper_relative=Path(f'/proc/{helper_pid}/cgroup').read_text().strip().split('::',1)[1]
            helper_cgroup=Path('/sys/fs/cgroup')/helper_relative.lstrip('/')
            fast_name='ce-fast-broker-'+uid[:8]
            fast_command=command[:]
            fast_command[fast_command.index(name)]=fast_name
            cut=fast_command.index(helper_image())
            fast_command=fast_command[:cut]+[helper_image(),'/work/native_broker',str(cgroup),uid,cid,str(info['parent_host_pid']),str(json.loads((ROOT/'symbols.json').read_text())['ce_body']),str(json.loads((ROOT/'symbols.json').read_text())['ce_taskdone']),str(json.loads((ROOT/'symbols.json').read_text())['ce_done']),hashlib.sha256((ROOT/'worker').read_bytes()).hexdigest(),'1' if self.out.name.startswith('smoke') else '0']
            fast_log=(self.out/('native-'+uid[:8]+'.stderr')).open('w')
            fast_proc=subprocess.Popen(fast_command,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=fast_log,text=True)
            fast_ready=fast_proc.stdout.readline()
            if not fast_ready:
                fast_proc.wait(timeout=3);raise RuntimeError('native broker failed; inspect native stderr')
            fast_info=json.loads(fast_ready);assert fast_info['ready'] and fast_info['pod_uid']==uid
            fast_pid=json.loads(subprocess.check_output(['docker','inspect',fast_name],text=True))[0]['State']['Pid']
            fast_relative=Path(f'/proc/{fast_pid}/cgroup').read_text().strip().split('::',1)[1]
            fast_cgroup=Path('/sys/fs/cgroup')/fast_relative.lstrip('/')
            (self.out/('native-'+uid[:8]+'.json')).write_text(json.dumps({'command':fast_command,'ready':fast_info,'helper_host_pid':fast_pid},indent=2)+'\n')
            self.items[uid]={'native_helper_cgroup':str(fast_cgroup),'fast_process':fast_proc,'fast_log':fast_log,'fast_container_name':fast_name,'function_cgroup':str(cgroup),'helper_cgroup':str(helper_cgroup),'process':proc,'log':log,'container_name':name,'command':command,'ready':info}
            (self.out/('broker-'+uid[:8]+'.json')).write_text(json.dumps({'command':command,'ready':info},indent=2)+'\n')
    def close(self):
        rows=[]
        for uid,item in self.items.items():
            p=item['process']
            subprocess.run(['docker','stop','--time','1',item['container_name']],capture_output=True,text=True)
            p.wait(timeout=5);item['log'].close();p.stdin.close();p.stdout.close()
            fp=item['fast_process']
            subprocess.run(['docker','stop','--time','1',item['fast_container_name']],capture_output=True,text=True)
            fp.wait(timeout=5);item['fast_log'].close();fp.stdin.close();fp.stdout.close()
            rows.append({'native_container_name':item['fast_container_name'],'native_exitcode':fp.returncode,'pod_uid':uid,'container_name':item['container_name'],'exitcode':p.returncode})
        (self.out/'brokers-cleanup.json').write_text(json.dumps(rows,indent=2)+'\n')
