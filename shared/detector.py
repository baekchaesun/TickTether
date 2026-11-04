"""No label, fault plan, environment noise, history, or truth ledger input."""
def bounds(request,path):
    return [request['values'][t%2] * (1+int(bool(request['runtime_paths'] and not ((request['seed']>>t)&1) and ((path>>t)&1))))
            for t in range(request['passes']*2)]

def maximum_count(request):
    return sum(request['values'][t%2]*(1+int(bool(request['runtime_paths'] and not ((request['seed']>>t)&1))))
               for t in range(request['passes']*2))

def verdicts(request,snapshot):
    task,j,bound,path,tick=snapshot
    bs=bounds(request,path)
    legal=task<len(bs) and bound==bs[task] and j<bound
    tau=sum(bs[:task])+j if task<len(bs) else -1
    return {'variables':not legal,'clock':tick>=maximum_count(request),
            'combined':not legal or tick!=tau}
