#define _GNU_SOURCE
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>

/* Parent owns the stopped child. No system-wide event or global perf setting. */
int ce_perf_open(int pid, uint64_t address, uint64_t period) {
    struct perf_event_attr a = {.size=sizeof(a), .type=PERF_TYPE_BREAKPOINT,
        .bp_type=HW_BREAKPOINT_X, .bp_addr=address, .bp_len=sizeof(long),
        .disabled=1, .exclude_kernel=1, .exclude_hv=1, .pinned=1,
        .read_format=PERF_FORMAT_TOTAL_TIME_ENABLED|PERF_FORMAT_TOTAL_TIME_RUNNING};
    if (period) { a.sample_period=period; a.sigtrap=1; a.remove_on_exec=1; }
    return syscall(__NR_perf_event_open, &a, pid, -1, -1, PERF_FLAG_FD_CLOEXEC);
}
int ce_perf_enable(int fd) { return ioctl(fd, PERF_EVENT_IOC_ENABLE, 0); }
int ce_perf_disable(int fd) { return ioctl(fd, PERF_EVENT_IOC_DISABLE, 0); }
int ce_perf_period(int fd, uint64_t period) { return ioctl(fd, PERF_EVENT_IOC_PERIOD, &period); }

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>

/* Same validations as the Python broker, in one native call. The fd is a
 * kernel pidfd for the stopped direct child, not a caller-supplied host PID.
 * No process memory or executable contents are read by this helper. */
int ce_validate_owned_pidfd(int pidfd, const char *cg, uint64_t inode,
                          int parent, int local_pid) {
    char path[4096], line[4096], args[4096];
    int pid=-1, found=0, v, pp=-1, ns=-1, tracer=-1, threads=-1;
    unsigned long long caps=~0ULL;
    char state=0; unsigned fields=0;
    struct stat st;
    snprintf(path,sizeof(path),"/proc/self/fdinfo/%d",pidfd);
    FILE *f=fopen(path,"r"); if(!f) return -1;
    while(fgets(line,sizeof(line),f)) if(sscanf(line,"Pid: %d",&v)==1) pid=v;
    fclose(f); if(pid<=0) {errno=ESRCH;return -2;}
    if(stat(cg,&st) || (uint64_t)st.st_ino!=inode) {errno=ESTALE;return -3;}
    if(snprintf(path,sizeof(path),"%s/cgroup.procs",cg)>=(int)sizeof(path)) {errno=ENAMETOOLONG;return -4;}
    f=fopen(path,"r"); if(!f) return -4;
    while(fscanf(f,"%d",&v)==1) if(v==pid)found=1;
    fclose(f); if(!found) {errno=EACCES;return -5;}
    snprintf(path,sizeof(path),"/proc/%d/status",pid);
    f=fopen(path,"r"); if(!f) return -6;
    while(fgets(line,sizeof(line),f)) {
        if(!strncmp(line,"PPid:",5) && sscanf(line+5,"%d",&v)==1) {pp=v;fields|=1;}
        else if(!strncmp(line,"TracerPid:",10) && sscanf(line+10,"%d",&v)==1) {tracer=v;fields|=2;}
        else if(!strncmp(line,"Threads:",8) && sscanf(line+8,"%d",&v)==1) {threads=v;fields|=4;}
        else if(!strncmp(line,"CapEff:",7) && sscanf(line+7,"%llx",&caps)==1) fields|=8;
        else if(!strncmp(line,"State:",6) && sscanf(line+6," %c",&state)==1) fields|=16;
        else if(!strncmp(line,"NSpid:",6)) {
            char *p=line+6,*end; ns=-1;
            while(1) {long n=strtol(p,&end,10);if(end==p)break;ns=(int)n;p=end;}
            fields|=32;
        }
    }
    fclose(f);
    if(fields!=63 || pp!=parent || ns!=local_pid || state!='t' || threads!=1 || caps!=0 || tracer<=0) {errno=EACCES;return -7;}
    snprintf(path,sizeof(path),"/proc/%d/task/%d",parent,tracer);
    if(stat(path,&st) || !S_ISDIR(st.st_mode)) {errno=EACCES;return -8;}
    snprintf(path,sizeof(path),"/proc/%d/cmdline",pid);
    int fd=open(path,O_RDONLY|O_CLOEXEC);if(fd<0)return -9;
    ssize_t n=read(fd,args,sizeof(args)-1);close(fd);
    if(n<=0 || !memchr(args,0,(size_t)n)) {errno=EINVAL;return -10;}
    args[n]=0;
    if(strlen(args)<17) {errno=EACCES;return -11;}
    char *slash=strchr(args+6,'/');
    if(strncmp(args,"/code/..20",10) || !slash || strcmp(slash,"/worker")) {errno=EACCES;return -11;}
    return pid;
}
