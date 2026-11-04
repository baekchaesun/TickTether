#define _GNU_SOURCE
#include "perf_bridge.c"
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <signal.h>

/* PIDFD_GET_INFO v0 prefix from Linux UAPI, 64 bytes. Linux extensible ioctl
 * validates type/number and handles the supplied structure size. */
struct ce_pidfd_info {uint64_t mask,cgroupid;uint32_t pid,tgid,ppid,ruid,rgid,euid,egid,suid,sgid,fsuid,fsgid;int32_t exit_code;};
#define CE_PIDFD_GET_INFO _IOWR(0xff,11,struct ce_pidfd_info)
static uint64_t stamp(clockid_t c) {struct timespec t;if(clock_gettime(c,&t))abort();return (uint64_t)t.tv_sec*1000000000ULL+t.tv_nsec;}

static int validate_info(int pfd,const char *cg,uint64_t inode,int parent,int local,int require_stop) {
    struct ce_pidfd_info info={.mask=5};struct stat st;
    if(ioctl(pfd,CE_PIDFD_GET_INFO,&info))return -20;
    if((info.mask&5)!=5 || !info.pid || info.pid!=info.tgid || info.ppid!=(unsigned)parent || info.cgroupid!=inode) {errno=EACCES;return -21;}
    if(stat(cg,&st) || (uint64_t)st.st_ino!=inode) {errno=ESTALE;return -22;}
    if(!require_stop)return (int)info.pid;
    int pid=(int)info.pid,pp=-1,ns=-1,tracer=-1,threads=-1,v;unsigned fields=0;unsigned long long caps=~0ULL;char state=0;
    char path[4096],line[4096],args[4096];snprintf(path,sizeof(path),"/proc/%d/status",pid);
    FILE *f=fopen(path,"r");if(!f)return -23;
    while(fgets(line,sizeof(line),f)) {
        if(!strncmp(line,"PPid:",5) && sscanf(line+5,"%d",&v)==1){pp=v;fields|=1;}
        else if(!strncmp(line,"TracerPid:",10) && sscanf(line+10,"%d",&v)==1){tracer=v;fields|=2;}
        else if(!strncmp(line,"Threads:",8) && sscanf(line+8,"%d",&v)==1){threads=v;fields|=4;}
        else if(!strncmp(line,"CapEff:",7) && sscanf(line+7,"%llx",&caps)==1)fields|=8;
        else if(!strncmp(line,"State:",6) && sscanf(line+6," %c",&state)==1)fields|=16;
        else if(!strncmp(line,"NSpid:",6)) {char *p=line+6,*end;while(1){long n=strtol(p,&end,10);if(p==end)break;ns=(int)n;p=end;}fields|=32;}
    }
    fclose(f);
    if(fields!=63 || pp!=parent || ns!=local || threads!=1 || caps || state=='Z' || state=='X' || (require_stop && (state!='t' || tracer<=0))){errno=EACCES;return -24;}
    snprintf(path,sizeof(path),"/proc/%d/task/%d",parent,tracer);
    if(tracer>0 && (stat(path,&st)||!S_ISDIR(st.st_mode))){errno=EACCES;return -25;}
    snprintf(path,sizeof(path),"/proc/%d/cmdline",pid);
    int fd=open(path,O_RDONLY|O_CLOEXEC);if(fd<0)return -26;
    ssize_t n=read(fd,args,sizeof(args)-1);close(fd);
    if(n<=0 || !memchr(args,0,(size_t)n)){errno=EACCES;return -27;}
    args[n]=0;if(strlen(args)<17 || strncmp(args,"/code/..20",10)){errno=EACCES;return -28;}
    char *slash=strchr(args+6,'/');if(!slash || strcmp(slash,"/worker")){errno=EACCES;return -29;}
    return pid;
}

static int open_stopped_active(int pid,uint64_t address,uint64_t period) {
    struct perf_event_attr a={.size=sizeof(a),.type=PERF_TYPE_BREAKPOINT,
        .bp_type=HW_BREAKPOINT_X,.bp_addr=address,.bp_len=sizeof(long),
        .disabled=0,.exclude_kernel=1,.exclude_hv=1,.pinned=1,
        .read_format=PERF_FORMAT_TOTAL_TIME_ENABLED|PERF_FORMAT_TOTAL_TIME_RUNNING,
        .sample_period=period,.sigtrap=1,.remove_on_exec=1};
    return syscall(__NR_perf_event_open,&a,pid,-1,-1,PERF_FLAG_FD_CLOEXEC);
}

static volatile sig_atomic_t stopping;
static void stop_broker(int signum){(void)signum;stopping=1;}
static int register_self_disabled(void) {
    struct perf_event_attr a={.size=sizeof(a),.type=PERF_TYPE_SOFTWARE,
        .config=PERF_COUNT_SW_DUMMY,.disabled=1,.exclude_kernel=1,.exclude_hv=1};
    return syscall(__NR_perf_event_open,&a,0,-1,-1,PERF_FLAG_FD_CLOEXEC);
}

int main(int argc,char **argv) {
    if(argc!=10)return 2;
    signal(SIGPIPE,SIG_IGN);
    struct sigaction action={.sa_handler=stop_broker};sigemptyset(&action.sa_mask);
    sigaction(SIGTERM,&action,NULL);sigaction(SIGINT,&action,NULL);
    const char *cg=argv[1],*uid=argv[2],*cid=argv[3],*sha=argv[8];
    int parent=atoi(argv[4]),selftest=atoi(argv[9]);uint64_t address=strtoull(argv[5],NULL,10),task_address=strtoull(argv[6],NULL,10),done_address=strtoull(argv[7],NULL,10);struct stat st;
    char uid_under[80];if(strlen(uid)>=sizeof(uid_under)||strlen(sha)!=64)return 3;
    strcpy(uid_under,uid);for(char *p=uid_under;*p;p++)if(*p=='-')*p='_';
    if(!strstr(cg,cid)||(!strstr(cg,uid)&&!strstr(cg,uid_under))||stat(cg,&st))return 4;
    uint64_t inode=st.st_ino;
    int sock=socket(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0);if(sock<0)return 5;
    struct sockaddr_un sa={.sun_family=AF_UNIX};strcpy(sa.sun_path,"/channel/ce-fast.sock");
    int ok=0;for(int i=0;i<100;i++){if(!connect(sock,(struct sockaddr*)&sa,sizeof(sa))){ok=1;break;}usleep(50000);}if(!ok)return 6;
    char ready[6];if(recv(sock,ready,6,MSG_WAITALL)!=6||memcmp(ready,"ready\n",6))return 7;
    char meta[2048];int size=snprintf(meta,sizeof(meta),"{\"ready\":true,\"parent_host_pid\":%d,\"pod_uid\":\"%s\",\"container_id\":\"%s\",\"cgroup_inode\":%llu,\"worker_sha256\":\"%s\",\"event_address\":%llu,\"validation_backend\":\"native_pidfd_info\",\"boundary_event_addresses\":[%llu,%llu],\"events_pre_enabled\":true,\"preparation_phase\":\"after_owned_stop\",\"lazy_self_registration\":true}\n",parent,uid,cid,(unsigned long long)inode,sha,(unsigned long long)address,(unsigned long long)task_address,(unsigned long long)done_address);
    if(size<=0||size>=(int)sizeof(meta)||send(sock,meta,(size_t)size,MSG_NOSIGNAL)!=size)return 8;
    fputs(meta,stdout);fflush(stdout);
    int registration_fd=-1;
    while(!stopping){
        uint64_t job[3];char control[CMSG_SPACE(sizeof(int))];struct iovec iov={job,sizeof(job)};
        struct msghdr msg={.msg_iov=&iov,.msg_iovlen=1,.msg_control=control,.msg_controllen=sizeof(control)};
        ssize_t n=recvmsg(sock,&msg,MSG_WAITALL|MSG_CMSG_CLOEXEC);if(n<0&&errno==EINTR){if(stopping)break;continue;}
        if(!n)break;
        if(n!=(ssize_t)sizeof(job))return 9;
        int pfd=-1,count=0;
        for(struct cmsghdr *c=CMSG_FIRSTHDR(&msg);c;c=CMSG_NXTHDR(&msg,c))if(c->cmsg_level==SOL_SOCKET&&c->cmsg_type==SCM_RIGHTS&&c->cmsg_len==CMSG_LEN(sizeof(int))){memcpy(&pfd,CMSG_DATA(c),sizeof(pfd));count++;}
        uint64_t cpu=stamp(CLOCK_PROCESS_CPUTIME_ID),began=stamp(CLOCK_MONOTONIC);
        int pid=-1,fd=-1,taskfd=-1,donefd=-1,error=EINVAL;
        int eligible=count==1 && !(msg.msg_flags&MSG_CTRUNC) && job[0]>0 && job[0]<=INT32_MAX && job[1]>0 && job[1]<=2048 && job[2]==1;
        char commit=0;ssize_t committed=recv(sock,&commit,1,MSG_WAITALL);
        uint64_t committed_at=stamp(CLOCK_MONOTONIC);
        if(committed!=1||commit!='C'){if(pfd>=0)close(pfd);break;}
        if(eligible){pid=validate_info(pfd,cg,inode,parent,(int)job[0],1);error=errno;}
        uint64_t validated=stamp(CLOCK_MONOTONIC);
        uint64_t registration_setup=0;
        if(pid>0 && registration_fd<0){
            uint64_t init_began=stamp(CLOCK_MONOTONIC);
            registration_fd=register_self_disabled();
            registration_setup=stamp(CLOCK_MONOTONIC)-init_began;
            if(registration_fd<0){error=errno;pid=-1;}
        }
        if(pid>0){
            fd=open_stopped_active(pid,address,job[1]);if(fd<0)error=errno;
            if(fd>=0){taskfd=open_stopped_active(pid,task_address,1);if(taskfd<0)error=errno;}
            if(taskfd>=0){donefd=open_stopped_active(pid,done_address,1);if(donefd<0)error=errno;}
            if(fd<0||taskfd<0||donefd<0){if(fd>=0)close(fd);if(taskfd>=0)close(taskfd);if(donefd>=0)close(donefd);fd=taskfd=donefd=-1;}
        }
        uint64_t opened=stamp(CLOCK_MONOTONIC);
        if(fd>=0 && selftest){
            if(ce_validate_owned_pidfd(pfd,cg,inode,parent,(int)job[0])!=pid)abort();
            if(validate_info(pfd,cg,inode+1,parent,(int)job[0],1)>=0 || validate_info(pfd,cg,inode,parent+1,(int)job[0],1)>=0 || validate_info(pfd,cg,inode,parent,(int)job[0]+1,1)>=0 || validate_info(-1,cg,inode,parent,(int)job[0],1)>=0)abort();
            fprintf(stderr,"{\"native_validation_selftest\":true,\"same_pid_as_previous\":%d,\"wrong_inode_parent_local_nonpidfd_rejected\":true}\n",pid);fflush(stderr);selftest=0;
        }
        int64_t result[8]={fd<0?-(error?error:EINVAL):0,pid,(int64_t)(validated-committed_at),(int64_t)(opened-validated),(int64_t)(stamp(CLOCK_PROCESS_CPUTIME_ID)-cpu),0,(int64_t)(committed_at-began),(int64_t)registration_setup};
        char out_control[CMSG_SPACE(3*sizeof(int))];struct iovec oiov={result,sizeof(result)};
        struct msghdr out={.msg_iov=&oiov,.msg_iovlen=1};
        if(fd>=0){out.msg_control=out_control;out.msg_controllen=sizeof(out_control);struct cmsghdr *c=CMSG_FIRSTHDR(&out);c->cmsg_level=SOL_SOCKET;c->cmsg_type=SCM_RIGHTS;c->cmsg_len=CMSG_LEN(3*sizeof(int));int returned[3]={fd,taskfd,donefd};memcpy(CMSG_DATA(c),returned,sizeof(returned));}
        ssize_t sent=sendmsg(sock,&out,MSG_NOSIGNAL);
        if(fd>=0)close(fd);
        if(taskfd>=0)close(taskfd);
        if(donefd>=0)close(donefd);
        if(pfd>=0)close(pfd);
        if(sent!=(ssize_t)sizeof(result))break;
    }
    if(registration_fd>=0){
        uint64_t count=~0ULL,began=stamp(CLOCK_MONOTONIC),cpu=stamp(CLOCK_PROCESS_CPUTIME_ID);
        ssize_t n=read(registration_fd,&count,sizeof(count));close(registration_fd);
        uint64_t close_ns=stamp(CLOCK_MONOTONIC)-began,close_cpu=stamp(CLOCK_PROCESS_CPUTIME_ID)-cpu;
        if(n!=(ssize_t)sizeof(count)||count!=0)abort();
        fprintf(stderr,"{\"self_registration_closed\":true,\"never_enabled_count\":%llu,\"owner_host_pid\":%d,\"close_wall_ns\":%llu,\"close_cpu_ns\":%llu}\n",(unsigned long long)count,getpid(),(unsigned long long)close_ns,(unsigned long long)close_cpu);fflush(stderr);
    }
    close(sock);return 0;
}
