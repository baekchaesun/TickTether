#define _GNU_SOURCE
#include <dlfcn.h>
#include <inttypes.h>
#include <linux/capability.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/random.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

typedef unsigned char *(*sha_fn)(const unsigned char *,size_t,unsigned char *);
typedef const void *(*md_fn)(void);
typedef int (*pb_fn)(const char *,int,const unsigned char *,int,int,const void *,int,unsigned char *);
typedef int (*z_fn)(unsigned char *,unsigned long *,const unsigned char *,unsigned long,int);
typedef unsigned long (*crc_fn)(unsigned long,const unsigned char *,unsigned int);
static sha_fn hash256; static md_fn md256; static pb_fn pbkdf; static z_fn compress_fn; static crc_fn crc;

/* Only original request fields; tracing and lab fault controls are absent. */
volatile struct { uint64_t workload,passes,seed,values[2],runtime_paths,wait_ms; } ce_request;
volatile struct { uint64_t task,j,bound,last,path; } ce_state;
volatile uint64_t ce_results[4][64];
static unsigned char payload[65536], compressed[66000];
static uint64_t ns(clockid_t c) { struct timespec t; clock_gettime(c,&t);return t.tv_sec*UINT64_C(1000000000)+t.tv_nsec; }
static uint64_t le64(const unsigned char *p) { uint64_t x=0;for(int i=0;i<8;i++)x|=(uint64_t)p[i]<<(8*i);return x; }
static void put64(unsigned char *p,uint64_t x) { for(int i=0;i<8;i++)p[i]=(x>>(8*i))&255; }
static uint64_t rotate(uint64_t x) { return (x<<7)|(x>>57); }
static uint64_t bound_for(uint64_t task) {
    uint64_t b=ce_request.values[task%2];
    /* Public input selects fixed work or a runtime-dependent normal retry path. */
    if (ce_request.runtime_paths && !((ce_request.seed>>task)&1) && ((ce_state.path>>task)&1)) b*=2;
    return b;
}
__attribute__((noinline)) uint64_t ce_work(uint64_t task,uint64_t j) {
    unsigned char out[32],salt[16],password[8];
    put64(salt,task);put64(salt+8,j);put64(password,ce_request.seed);
    uint64_t answer=0;
    if (ce_request.workload==0) {
        put64(payload,task);put64(payload+8,j);
        for (uint64_t r=0;r<128;r++) {
            put64(payload+16,r);hash256(payload,sizeof(payload),out);
            answer=rotate(answer)^le64(out);
        }
    } else if (ce_request.workload==1) {
        if (!pbkdf((const char *)password,8,salt,16,16000,md256(),32,out)) _exit(20);
        answer=le64(out);
    } else {
        put64(payload,task);put64(payload+8,j);
        for (uint64_t r=0;r<4;r++) {
            put64(payload+16,r);unsigned long size=sizeof(compressed);
            if (compress_fn(compressed,&size,payload,sizeof(payload),6)) _exit(21);
            answer=rotate(answer)^(((uint64_t)crc(0,compressed,size)<<32)^size);
        }
    }
    return answer;
}
__attribute__((noinline)) uint64_t ce_function(void) {
    for (uint64_t task=0;task<ce_request.passes*2;task++) {
        ce_state.task=task;ce_state.j=0;ce_state.bound=bound_for(task);
        for (;;) {
            __asm__ volatile(".global ce_head\nce_head:" ::: "memory");
            if (ce_state.j>=ce_state.bound) break;
            __asm__ volatile(".global ce_body\nce_body:" ::: "memory");
            uint64_t j=ce_state.j;
            if (j>=64) _exit(22);
            uint64_t value=ce_work(ce_state.task,j);
            ce_results[ce_state.task][j]=value;
            ce_state.last=value;
            ce_state.j++;
        }
        __asm__ volatile(".global ce_taskdone\nce_taskdone:" ::: "memory");
    }
    __asm__ volatile(".global ce_done\nce_done:" ::: "memory");
    uint64_t answer=UINT64_C(0x123456789abcdef0);
    for (uint64_t t=0;t<ce_request.passes*2;t++)
        for (uint64_t j=0;j<bound_for(t);j++) answer=rotate(answer)^ce_results[t][j];
    return answer;
}
int main(int argc,char **argv) {
    if (argc!=10) return 2;
    struct __user_cap_header_struct header={_LINUX_CAPABILITY_VERSION_3,0};
    struct __user_cap_data_struct caps[2]={{0},{0}};
    if (syscall(SYS_capset,&header,caps)||prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0))return 9;
    int traced=atoi(argv[1]),cpu=atoi(argv[2]);
    ce_request.workload=strtoull(argv[3],0,10);ce_request.passes=strtoull(argv[4],0,10);
    ce_request.seed=strtoull(argv[5],0,10);ce_request.values[0]=strtoull(argv[6],0,10);
    ce_request.values[1]=strtoull(argv[7],0,10);ce_request.runtime_paths=strtoull(argv[8],0,10);
    ce_request.wait_ms=strtoull(argv[9],0,10);
    if (ce_request.workload>2||ce_request.passes<1||ce_request.passes>2||
        ce_request.values[0]<1||ce_request.values[1]<1||ce_request.values[0]>12||ce_request.values[1]>12||
        ce_request.runtime_paths>1||ce_request.wait_ms>100) return 3;
    struct rlimit lim={10,10};setrlimit(RLIMIT_CPU,&lim);alarm(20);prctl(PR_SET_PDEATHSIG,SIGKILL);
    cpu_set_t cpus;CPU_ZERO(&cpus);CPU_SET(cpu,&cpus);if(sched_setaffinity(0,sizeof(cpus),&cpus))return 4;
    void *crypto=dlopen("libcrypto.so.3",RTLD_NOW),*z=dlopen("libz.so.1",RTLD_NOW);
    if (!crypto||!z) return 5;
    hash256=dlsym(crypto,"SHA256");md256=dlsym(crypto,"EVP_sha256");
    pbkdf=dlsym(crypto,"PKCS5_PBKDF2_HMAC");compress_fn=dlsym(z,"compress2");crc=dlsym(z,"crc32");
    if (!hash256||!md256||!pbkdf||!compress_fn||!crc) return 6;
    uint32_t value=(uint32_t)ce_request.seed;
    for (size_t k=0;k<sizeof(payload);k++) {value=value*1664525u+1013904223u;payload[k]=value>>24;}
    uint64_t path=0;if (ce_request.runtime_paths && getrandom(&path,sizeof(path),0)!=sizeof(path))return 7;
    ce_state.path=path&15;
    if (traced) {if(ptrace(PTRACE_TRACEME,0,0,0))return 8;raise(SIGSTOP);}
    uint64_t wall=ns(CLOCK_MONOTONIC),cpu_ns=ns(CLOCK_PROCESS_CPUTIME_ID);
    if (ce_request.wait_ms) {struct timespec t={0,ce_request.wait_ms*1000000};nanosleep(&t,0);}
    uint64_t result=ce_function();
    printf("{\"result\":%"PRIu64",\"path\":%"PRIu64",\"roi_wall_ns\":%"PRIu64",\"roi_cpu_ns\":%"PRIu64"}\n",
        result,ce_state.path,ns(CLOCK_MONOTONIC)-wall,ns(CLOCK_PROCESS_CPUTIME_ID)-cpu_ns);
    return 0;
}
