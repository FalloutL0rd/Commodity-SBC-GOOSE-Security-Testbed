/*
This is the MAIN USER-FACING PROGRAM
-------------------------------------
*/

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <json-c/json.h>

#define ENGINE_BIN    "./bitw_engine"
#define REGISTRY_PATH "policies/registry.json"

static bool file_exists(const char *p){ struct stat st; return (stat(p,&st)==0 && S_ISREG(st.st_mode)); }
static bool dir_exists(const char *p){ struct stat st; return (stat(p,&st)==0 && S_ISDIR(st.st_mode)); }
static bool proc_alive(pid_t pid){ return (pid>0 && (kill(pid,0)==0 || errno==EPERM)); }
static void die(const char*fmt, ...){ va_list ap; va_start(ap,fmt); vfprintf(stderr,fmt,ap); fprintf(stderr,"\n"); va_end(ap); exit(1); }
static const char* base_name(const char *path){ const char *b=strrchr(path,'/'); return b?b+1:path; }

static void safe_basename(char out[], size_t n, const char*path){
    const char *b = base_name(path);
    size_t L = strlen(b); if (L >= n) L = n-1;
    memcpy(out,b,L); out[L]='\0';
    char *dot = strrchr(out,'.'); if (dot) *dot='\0';
    for(char *p=out; *p; ++p) if(!(isalnum((unsigned char)*p)||*p=='_'||*p=='-')) *p='_';
}

static struct json_object* registry_load(void){
    if (!file_exists(REGISTRY_PATH)) {
        if (!dir_exists("policies")) {
            if (mkdir("policies", 0775)!=0 && errno!=EEXIST) die("Cannot create policies/: %s", strerror(errno));
        }
        struct json_object *empty = json_object_new_array();
        json_object_to_file_ext(REGISTRY_PATH, empty, JSON_C_TO_STRING_PRETTY);
        json_object_put(empty);
    }
    struct json_object *arr = json_object_from_file(REGISTRY_PATH);
    if (!arr || !json_object_is_type(arr, json_type_array)) die("Failed to read %s", REGISTRY_PATH);
    return arr;
}
static void registry_save(struct json_object *arr){
    if (!json_object_is_type(arr,json_type_array)) die("Internal: registry not array");
    if (json_object_to_file_ext(REGISTRY_PATH, arr, JSON_C_TO_STRING_PRETTY)!=0) die("Failed writing %s", REGISTRY_PATH);
}
static void registry_prune_dead(struct json_object *arr){
    for (int i=json_object_array_length(arr)-1;i>=0;--i){
        struct json_object *e=json_object_array_get_idx(arr,i), *jp=NULL;
        if (!json_object_object_get_ex(e,"pid",&jp)) continue;
        pid_t pid=(pid_t)json_object_get_int(jp);
        if (!proc_alive(pid)) json_object_array_del_idx(arr,i,1);
    }
}
static bool registry_find_by_name(struct json_object*arr,const char*name,int*idx_out){
    int len=json_object_array_length(arr);
    for(int i=0;i<len;++i){
        struct json_object *e=json_object_array_get_idx(arr,i), *jn=NULL;
        if (json_object_object_get_ex(e,"name",&jn)){
            const char *n=json_object_get_string(jn);
            if (n && strcmp(n,name)==0){ if(idx_out)*idx_out=i; return true; }
        }
    }
    return false;
}
static bool registry_find_by_pid(struct json_object*arr,pid_t pid,int*idx_out){
    int len=json_object_array_length(arr);
    for(int i=0;i<len;++i){
        struct json_object *e=json_object_array_get_idx(arr,i), *jp=NULL;
        if (json_object_object_get_ex(e,"pid",&jp)){
            if ((pid_t)json_object_get_int(jp)==pid){ if(idx_out)*idx_out=i; return true; }
        }
    }
    return false;
}

//Start/stop
static void start_bitw(const char*policy_path,const char*ifA,const char*ifB){
    if (!file_exists(ENGINE_BIN)) die("Missing %s (build it)", ENGINE_BIN);
    if (!file_exists(policy_path)) die("Config not found: %s", policy_path);
    if (!ifA || !*ifA || !ifB || !*ifB) die("Need two interfaces");

    char name[64]; safe_basename(name,sizeof(name),policy_path);

    pid_t pid=fork();
    if (pid<0) die("fork: %s", strerror(errno));
    if (pid==0){
        setsid();
        int fd=open("/dev/null",O_RDWR);
        if (fd>=0){ dup2(fd,0); dup2(fd,1); dup2(fd,2); if(fd>2) close(fd); }
        execlp(ENGINE_BIN, ENGINE_BIN, policy_path, ifA, ifB, (char*)NULL);
        _exit(127);
    }

    struct json_object *reg=registry_load(); registry_prune_dead(reg);
    struct json_object *e=json_object_new_object();
    json_object_object_add(e,"pid",json_object_new_int(pid));
    json_object_object_add(e,"name",json_object_new_string(name));
    json_object_object_add(e,"ifA",json_object_new_string(ifA));
    json_object_object_add(e,"ifB",json_object_new_string(ifB));
    json_object_object_add(e,"policy",json_object_new_string(policy_path));
    json_object_object_add(e,"started_at",json_object_new_int64((int64_t)time(NULL)));
    json_object_array_add(reg,e); registry_save(reg); json_object_put(reg);

    printf("Started %s (PID %d) on %s <-> %s\n", name, (int)pid, ifA, ifB);
}
static void stop_one(const char*arg){
    struct json_object *reg=registry_load(); registry_prune_dead(reg);
    if (strcmp(arg,"all")==0){
        for(int i=json_object_array_length(reg)-1;i>=0;--i){
            struct json_object *e=json_object_array_get_idx(reg,i), *jp=NULL, *jn=NULL;
            json_object_object_get_ex(e,"pid",&jp); pid_t pid=(pid_t)json_object_get_int(jp);
            const char *name=""; if (json_object_object_get_ex(e,"name",&jn)) name=json_object_get_string(jn);
            if (proc_alive(pid)){ kill(pid,SIGTERM); for(int k=0;k<30 && proc_alive(pid);++k) usleep(100*1000); if (proc_alive(pid)) kill(pid,SIGKILL); }
            char pbuf[128]; snprintf(pbuf,sizeof(pbuf),"/tmp/bitw_status_%d.json",(int)pid); unlink(pbuf);
            json_object_array_del_idx(reg,i,1); printf("Stopped %s (PID %d)\n", name, (int)pid);
        }
        registry_save(reg); json_object_put(reg); return;
    }
    char *end=NULL; long p=strtol(arg,&end,10);
    int idx=-1;
    if (end && *end=='\0' && p>0) registry_find_by_pid(reg,(pid_t)p,&idx);
    else registry_find_by_name(reg,arg,&idx);
    if (idx>=0){
        struct json_object *e=json_object_array_get_idx(reg,idx), *jp=NULL, *jn=NULL;
        json_object_object_get_ex(e,"pid",&jp); pid_t pid=(pid_t)json_object_get_int(jp);
        const char *name=""; if (json_object_object_get_ex(e,"name",&jn)) name=json_object_get_string(jn);
        if (proc_alive(pid)){ kill(pid,SIGTERM); for(int k=0;k<30 && proc_alive(pid);++k) usleep(100*1000); if (proc_alive(pid)) kill(pid,SIGKILL); }
        char pbuf[128]; snprintf(pbuf,sizeof(pbuf),"/tmp/bitw_status_%d.json",(int)pid); unlink(pbuf);
        json_object_array_del_idx(reg,idx,1); registry_save(reg); printf("Stopped %s (PID %d)\n", name, (int)pid);
    } else printf("No matching entry.\n");
    json_object_put(reg);
}

//Live status monitor
static volatile sig_atomic_t live_exit=0;
static void on_sigint(int s){ (void)s; live_exit=1; }
static void live_monitor(void){
    signal(SIGINT,on_sigint);
    while(!live_exit){
        (void)!system("clear");
        printf("Live Monitor (Ctrl+C to exit)\n\n");
        printf("%-6s %-18s %-10s %-10s %-19s %-6s %-8s\n","PID","Name","IfA","IfB","Last Packet (UTC)","Strips","#Streams");
        printf("------ ------------------ ---------- ---------- ------------------- ------ --------\n");

        struct json_object *reg=registry_load();
        int len=json_object_array_length(reg);
        for(int i=0;i<len;++i){
            struct json_object *e=json_object_array_get_idx(reg,i), *jp=NULL,*jn=NULL,*ja=NULL,*jb=NULL,*jpol=NULL;
            pid_t pid=0; const char*name=""; const char*ifA=""; const char*ifB=""; const char*policy="";
            if (json_object_object_get_ex(e,"pid",&jp)) pid=(pid_t)json_object_get_int(jp);
            if (json_object_object_get_ex(e,"name",&jn)) name=json_object_get_string(jn);
            if (json_object_object_get_ex(e,"ifA",&ja)) ifA=json_object_get_string(ja);
            if (json_object_object_get_ex(e,"ifB",&jb)) ifB=json_object_get_string(jb);
            if (json_object_object_get_ex(e,"policy",&jpol)) policy=json_object_get_string(jpol);
            char pbuf[128]; snprintf(pbuf,sizeof(pbuf),"/tmp/bitw_status_%d.json",(int)pid);
            char tsbuf[20]=""; int strips=0; int streams=0;
            if (file_exists(pbuf)){
                struct json_object *st=json_object_from_file(pbuf);
                if (st){
                    struct json_object *t=NULL,*s=NULL,*n=NULL;
                    if (json_object_object_get_ex(st,"lastPacketUtc",&t)){
                        time_t tt=(time_t)json_object_get_int64(t); struct tm tm; gmtime_r(&tt,&tm);
                        strftime(tsbuf,sizeof(tsbuf),"%Y-%m-%d %H:%M:%S",&tm);
                    }
                    if (json_object_object_get_ex(st,"stripped",&s)) strips=json_object_get_int(s);
                    if (json_object_object_get_ex(st,"streams",&n))  streams=json_object_get_int(n);
                    json_object_put(st);
                }
            }
            printf("%-6d %-18s %-10s %-10s %-19s %-6d %-8d\n",(int)pid,name,ifA,ifB,tsbuf, strips, streams);
            printf("    policy: %s%s\n", policy, proc_alive(pid)?"":"  [DEAD]");
        }
        json_object_put(reg);
        fflush(stdout);
        usleep(250000);
    }
    printf("Live monitor closed.\n");
}

//Print the menu
static void print_menu(void){
    printf("\n=== BITW Manager ===\n");
    printf("1) Start policy\n");
    printf("2) Stop policy (name|pid|all)\n");
    printf("3) List once\n");
    printf("4) Live monitor (Ctrl+C to exit)\n");
    printf("5) Quit\n");
}
static void list_once(void){
    struct json_object *reg=registry_load(); registry_prune_dead(reg);
    printf("\nPID    Name               IfA        IfB         Policy\n");
    printf("-----  -----------------  ---------- ----------  -------------------------\n");
    int len=json_object_array_length(reg);
    for(int i=0;i<len;++i){
        struct json_object *e=json_object_array_get_idx(reg,i), *jp=NULL,*jn=NULL,*ja=NULL,*jb=NULL,*jpol=NULL;
        int pid=0; const char*name=""; const char*ifA=""; const char*ifB=""; const char*pol="";
        if (json_object_object_get_ex(e,"pid",&jp)) pid=json_object_get_int(jp);
        if (json_object_object_get_ex(e,"name",&jn)) name=json_object_get_string(jn);
        if (json_object_object_get_ex(e,"ifA",&ja)) ifA=json_object_get_string(ja);
        if (json_object_object_get_ex(e,"ifB",&jb)) ifB=json_object_get_string(jb);
        if (json_object_object_get_ex(e,"policy",&jpol)) pol=json_object_get_string(jpol);
        printf("%-5d  %-17s  %-10s %-10s  %s%s\n", pid, name, ifA, ifB, pol, proc_alive(pid)?"":"  [DEAD]");
    }
    json_object_put(reg);
}
int main(void){
    for(;;){
        print_menu(); printf("\n> "); fflush(stdout);
        int c=getchar(); if (c==EOF) break; while(getchar()!='\n' && !feof(stdin)){}
        if (c=='1'){
            char pol[256]={0}, ifA[32]={0}, ifB[32]={0};
            printf("Policy JSON: "); if (!fgets(pol,sizeof(pol),stdin)) continue; pol[strcspn(pol,"\r\n")]=0;
            printf("Interface In: "); if (!fgets(ifA,sizeof(ifA),stdin)) continue; ifA[strcspn(ifA,"\r\n")]=0;
            printf("Interface Out: "); if (!fgets(ifB,sizeof(ifB),stdin)) continue; ifB[strcspn(ifB,"\r\n")]=0;
            if (pol[0]&&ifA[0]&&ifB[0]) start_bitw(pol,ifA,ifB);
            else printf("Missing inputs.\n");
        } else if (c=='2'){
            char arg[64]={0}; printf("Name, PID, or 'all': "); if (!fgets(arg,sizeof(arg),stdin)) continue; arg[strcspn(arg,"\r\n")]=0; if (arg[0]) stop_one(arg);
        } else if (c=='3'){ list_once();
        } else if (c=='4'){ live_monitor();
        } else if (c=='5' || c=='q' || c=='Q'){ break; }
    }
    return 0;
}
