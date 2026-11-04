#define _GNU_SOURCE
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <dlfcn.h>
#include <unistd.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <sys/ioctl.h>
#include <linux/perf_event.h>
#include <time.h>

static void *crypto;
static void *(*ctx_new)(void);
static void (*ctx_free)(void*);
static int (*ctx_init)(void*,const void*,int,const void*,void*);
static int (*ctx_copy)(void*,const void*);
static int (*ctx_update)(void*,const unsigned char*,size_t);
static int (*ctx_final)(void*,unsigned char*,unsigned int*);
static const void *(*sha256_md)(void);
static unsigned char *(*hmac_sha)(const void*,const void*,int,const unsigned char*,size_t,unsigned char*,unsigned int*);
__attribute__((constructor)) static void init_crypto(void) {
    crypto=dlopen("libcrypto.so.3",RTLD_NOW|RTLD_LOCAL);
    if(crypto){
        *(void**)(&ctx_new)=dlsym(crypto,"HMAC_CTX_new");*(void**)(&ctx_free)=dlsym(crypto,"HMAC_CTX_free");
        *(void**)(&ctx_init)=dlsym(crypto,"HMAC_Init_ex");*(void**)(&ctx_copy)=dlsym(crypto,"HMAC_CTX_copy");
        *(void**)(&ctx_update)=dlsym(crypto,"HMAC_Update");*(void**)(&ctx_final)=dlsym(crypto,"HMAC_Final");
        *(void**)(&sha256_md)=dlsym(crypto,"EVP_sha256");*(void**)(&hmac_sha)=dlsym(crypto,"HMAC");}
}
struct ce_context {unsigned char key[32];uint64_t request[7],numerator,next_tick,period,updates,skips;void *base,*work;};
struct ce_sample {uint64_t snapshot[5],rip,counter,enabled,running,relative_ns,flags;};
static uint64_t mono(void){struct timespec t;if(clock_gettime(CLOCK_MONOTONIC,&t))return 0;return (uint64_t)t.tv_sec*1000000000ULL+t.tv_nsec;}
int ce_draw(const unsigned char *key,uint64_t tick,uint64_t *out) {
    unsigned char data[12]={'b','o','d','y'},digest[32];unsigned int n=0;
    memcpy(data+4,&tick,8);
    if(!hmac_sha||!sha256_md||!hmac_sha(sha256_md(),key,32,data,sizeof(data),digest,&n)||n!=32){errno=EIO;return -1;}
    memcpy(out,digest,8);return 0;
}
int ce_cached_draw(struct ce_context *c,uint64_t tick,uint64_t *out) {
    unsigned char data[12]={'b','o','d','y'},digest[32];unsigned int n=0;memcpy(data+4,&tick,8);
    if(!c->base||!c->work||!ctx_copy(c->work,c->base)||!ctx_update(c->work,data,sizeof(data))||!ctx_final(c->work,digest,&n)||n!=32){errno=EIO;return -1;}
    memcpy(out,digest,8);return 0;
}
void ce_sampler_free(struct ce_context *c){if(ctx_free){if(c->base)ctx_free(c->base);if(c->work)ctx_free(c->work);}c->base=c->work=NULL;}
static int next(struct ce_context *c,uint64_t start,uint64_t *out) {
    uint64_t threshold=(uint64_t)(((unsigned __int128)c->numerator<<64)/100),draw;
    for(uint64_t t=start;t<512;t++){if(ce_cached_draw(c,t,&draw))return -1;if(draw<threshold){*out=t;return 0;}}
    *out=start+1024;return 0;
}
int ce_sampler_prepare(struct ce_context *c) {
    if(!ctx_new||!ctx_free||!ctx_init||!ctx_copy||!ctx_update||!ctx_final||!sha256_md){errno=ENOSYS;return -1;}
    c->base=ctx_new();c->work=ctx_new();
    if(!c->base||!c->work||!ctx_init(c->base,c->key,32,sha256_md(),NULL)){ce_sampler_free(c);errno=EIO;return -2;}
    return next(c,0,&c->next_tick);
}
int ce_sampler_next(struct ce_context *c,uint64_t start){return next(c,start,&c->next_tick);}
static unsigned decisions(const uint64_t *req,const uint64_t *s) {
    uint64_t t=s[0],j=s[1],b=s[2],path=s[3],tick=s[4],n=2*req[1],tau=j,max=0,bound=0;
    for(uint64_t k=0;k<n;k++){
        uint64_t base=req[3+k%2],v=base;
        if(req[5] && !((req[2]>>k)&1) && ((path>>k)&1))v*=2;
        if(k<t)tau+=v;
        if(k==t)bound=v;
        max+=base*(req[5]&&!((req[2]>>k)&1)?2:1);
    }
    unsigned invalid=(t>=n||b!=bound||j>=b);
    return invalid | ((tick>=max)<<1) | ((invalid||t>=n||tick!=tau)<<2);
}
/* Return at any software hook or an anomalous selected body. Normal selected
 * bodies are classified and recorded before resume. No truth/input repair. */
int ce_run_until_control(int pid,int fd,uint64_t body,uint64_t state,uint64_t began,
                        struct ce_context *ctx,struct user_regs_struct *regs,
                        struct ce_sample *samples,uint64_t *used) {
    *used=0;
    while(1){
        int status;pid_t got;
        do{got=waitpid(pid,&status,0);}while(got<0&&errno==EINTR);
        if(got!=pid||!WIFSTOPPED(status)||WSTOPSIG(status)!=SIGTRAP){errno=EPROTO;return -1;}
        if(ptrace(PTRACE_GETREGS,pid,0,regs))return -2;
        if(regs->rip!=body)return 0;
        uint64_t cnt[3],v[5];ssize_t n=read(fd,cnt,sizeof(cnt));
        if(n!=(ssize_t)sizeof(cnt)||cnt[0]==0||cnt[0]-1!=ctx->next_tick||cnt[1]!=cnt[2]||cnt[0]>500){errno=EPROTO;return -3;}
        struct iovec local={v,sizeof(v)},remote={(void*)(uintptr_t)state,sizeof(v)};
        if(process_vm_readv(pid,&local,1,&remote,1,0)!=(ssize_t)sizeof(v))return -4;
        if(*used>=64){errno=EOVERFLOW;return -5;}
        struct ce_sample *s=&samples[(*used)++];
        s->snapshot[0]=v[0];s->snapshot[1]=v[1];s->snapshot[2]=v[2];s->snapshot[3]=v[4];s->snapshot[4]=cnt[0]-1;
        s->rip=regs->rip;s->counter=cnt[0];s->enabled=cnt[1];s->running=cnt[2];s->relative_ns=mono()-began;s->flags=decisions(ctx->request,s->snapshot);
        if(s->relative_ns>25000000000ULL){errno=ETIMEDOUT;return -6;}
        if(s->flags)return 1; /* still stopped, no anomalous body executed */
        if(next(ctx,s->snapshot[4]+1,&ctx->next_tick))return -7;
        uint64_t period=ctx->next_tick-s->snapshot[4];
        if(period!=ctx->period){if(ioctl(fd,PERF_EVENT_IOC_PERIOD,&period))return -8;ctx->period=period;ctx->updates++;}
        else ctx->skips++;
        if(ptrace(PTRACE_CONT,pid,0,0))return -9;
    }
}

/* Fused records: kind, five state values, PC, three body counter values,
 * timestamp, live decision flags, three control counter values. */
struct ce_record {uint64_t kind,value[5],rip,body[3],relative_ns,flags,control[3];};
static int read_exact_counter(int fd,uint64_t out[3]) {
    if(read(fd,out,24)!=24 || out[1]!=out[2] || !out[1]){errno=EPROTO;return -1;}
    return 0;
}
int ce_run_fused(int pid,int fd,int taskfd,uint64_t body,uint64_t task,uint64_t done,
                 uint64_t state,uint64_t began,struct ce_context *ctx,
                 struct user_regs_struct *regs,struct ce_record *records,uint64_t *used) {
    *used=0;
    while(1){
        int status;pid_t got;
        do{got=waitpid(pid,&status,0);}while(got<0&&errno==EINTR);
        if(got!=pid||!WIFSTOPPED(status)||WSTOPSIG(status)!=SIGTRAP){errno=EPROTO;return -11;}
        if(ptrace(PTRACE_GETREGS,pid,0,regs))return -12;
        if(regs->rip==done || (regs->rip!=body && regs->rip!=task))return 0;
        if(*used>=64){errno=EOVERFLOW;return -13;}
        struct ce_record *r=&records[(*used)++];memset(r,0,sizeof(*r));r->rip=regs->rip;
        if(read_exact_counter(fd,r->body))return -14;
        uint64_t v[5];struct iovec local={v,sizeof(v)},remote={(void*)(uintptr_t)state,sizeof(v)};
        if(process_vm_readv(pid,&local,1,&remote,1,0)!=(ssize_t)sizeof(v))return -15;
        r->relative_ns=mono()-began;
        if(r->relative_ns>25000000000ULL || r->body[0]>500){errno=ETIMEDOUT;return -16;}
        if(regs->rip==body){
            if(!r->body[0] || r->body[0]-1!=ctx->next_tick){errno=EPROTO;return -17;}
            r->value[0]=v[0];r->value[1]=v[1];r->value[2]=v[2];r->value[3]=v[4];r->value[4]=r->body[0]-1;
            r->flags=decisions(ctx->request,r->value);
            if(r->flags)return 1; /* selected anomaly remains stopped */
            if(next(ctx,r->value[4]+1,&ctx->next_tick))return -18;
            uint64_t period=ctx->next_tick-r->value[4];
            if(period!=ctx->period){if(ioctl(fd,PERF_EVENT_IOC_PERIOD,&period))return -19;ctx->period=period;ctx->updates++;}
            else ctx->skips++;
        }else{
            r->kind=1;memcpy(r->value,v,sizeof(v));
            if(read_exact_counter(taskfd,r->control) || r->control[0]!=v[0]+1){errno=EPROTO;return -20;}
            uint64_t bound=ctx->request[3+v[0]%2];
            if(v[0]<64 && ctx->request[5] && !((ctx->request[2]>>v[0])&1) && ((v[4]>>v[0])&1))bound*=2;
            r->flags=(v[0]>=2*ctx->request[1] || v[1]!=bound || v[2]!=bound);
            if(r->flags)return 2; /* boundary anomaly remains stopped */
        }
        if(*used==64)return 3; /* flush while stopped, then resume */
        if(ptrace(PTRACE_CONT,pid,0,0))return -21;
    }
}
