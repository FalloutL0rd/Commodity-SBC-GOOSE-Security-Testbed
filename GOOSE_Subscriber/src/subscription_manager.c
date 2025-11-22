/*
MAIN USER-FACING PROGRAM
-------------------------
Starts/stops background subscriber processes (subscriber_engine)
Then tracks them in subscriptions/registry.json, and provides a live monitor showing stNum/sqNum/valid/TTL/Age
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
#include <time.h>
#include <fcntl.h>
#include <json-c/json.h>

#define REGISTRY_PATH "subscriptions/registry.json"
#define ENGINE_BIN    "./subscriber_engine"

static bool file_exists(const char *p) { struct stat st; return (stat(p,&st)==0 && S_ISREG(st.st_mode)); }
static bool dir_exists(const char *p)  { struct stat st; return (stat(p,&st)==0 && S_ISDIR(st.st_mode)); }
static bool proc_alive(pid_t pid)
{
    if (pid <= 0) return false;
    //Process exists and we can signal it
    if (kill(pid, 0) == 0) return true;
    //Permission denied => process exists (different uid)
    return (errno == EPERM);
}


static const char* base_name(const char *path) { const char *b = strrchr(path, '/'); return b ? b+1 : path; }
static void strip_ext(char *s) { char *d=strrchr(s,'.'); if (d)*d='\0'; }
static void die(const char *fmt, ...) { va_list ap; va_start(ap, fmt); vfprintf(stderr, fmt, ap); fprintf(stderr, "\n"); va_end(ap); exit(1); }

//Loads/creates the registry JSON array
static struct json_object* registry_load(void) {
    if (!file_exists(REGISTRY_PATH)) {
        if (!dir_exists("subscriptions")) {
            if (mkdir("subscriptions", 0775) != 0 && errno != EEXIST)
                die("Cannot create subscriptions/: %s", strerror(errno));
        }
        struct json_object *empty = json_object_new_array();
        json_object_to_file_ext(REGISTRY_PATH, empty, JSON_C_TO_STRING_PRETTY);
        json_object_put(empty);
    }
    struct json_object *arr = json_object_from_file(REGISTRY_PATH);
    if (!arr || !json_object_is_type(arr, json_type_array))
        die("Failed to read registry at %s", REGISTRY_PATH);
    return arr;
}

//Saves the registry JSON array
static void registry_save(struct json_object *arr) {
    if (!json_object_is_type(arr, json_type_array))
        die("Internal: registry not array");
    if (json_object_to_file_ext(REGISTRY_PATH, arr, JSON_C_TO_STRING_PRETTY) != 0)
        die("Failed to write %s", REGISTRY_PATH);
}

//Removes entries for dead processes
static void registry_prune_dead(struct json_object *arr) {
    for (int i = json_object_array_length(arr)-1; i >= 0; --i) {
        struct json_object *e = json_object_array_get_idx(arr, i);
        struct json_object *jp = NULL;
        if (!json_object_object_get_ex(e, "pid", &jp)) continue;
        pid_t pid = (pid_t) json_object_get_int(jp);

        int r = kill(pid, 0);
        if (r == 0)         continue;
        if (errno == EPERM) continue;
        json_object_array_del_idx(arr, i, 1);
    }
}

//Reads appId from a subscription JSON
static int cfg_get_appId(const char *cfg_path) {
    struct json_object *root = json_object_from_file(cfg_path);
    if (!root) return -1;
    struct json_object *x = NULL; int appId = -1;
    if (json_object_object_get_ex(root, "appId", &x)) appId = json_object_get_int(x);
    json_object_put(root);
    return appId;
}

//Derives a friendly name from the config file name
static void cfg_guess_name(const char *cfg_path, char out[64]) {
    snprintf(out, 64, "%s", base_name(cfg_path));
    strip_ext(out);
    for (char *p=out; *p; ++p)
        if (!(isalnum((unsigned char)*p)||*p=='_'||*p=='-')) *p='_';
}

//Starts a background subscriber using subscriber_engine
static void start_subscriber(const char *cfg_path, const char *iface) {
    if (!file_exists(ENGINE_BIN)) die("Missing %s (build it)", ENGINE_BIN);
    if (!file_exists(cfg_path))   die("Config not found: %s", cfg_path);
    if (!iface || !*iface)        die("Interface missing");

    int appId = cfg_get_appId(cfg_path);
    if (appId <= 0) die("Invalid/missing appId in %s", cfg_path);

    char name[64]; cfg_guess_name(cfg_path, name);

    pid_t pid = fork();
    if (pid < 0) die("fork failed: %s", strerror(errno));
    if (pid == 0) {
        setsid();
        int fd = open("/dev/null", O_RDWR);
        if (fd >= 0) {
            dup2(fd, STDIN_FILENO);
            dup2(fd, STDOUT_FILENO);
            dup2(fd, STDERR_FILENO);
            if (fd > 2) close(fd);
        }
        execlp(ENGINE_BIN, ENGINE_BIN, cfg_path, iface, (char*)NULL);
        _exit(127);
    }

    struct json_object *reg = registry_load();
    registry_prune_dead(reg);

    struct json_object *entry = json_object_new_object();
    json_object_object_add(entry, "pid",        json_object_new_int(pid));
    json_object_object_add(entry, "name",       json_object_new_string(name));
    json_object_object_add(entry, "appId",      json_object_new_int(appId));
    json_object_object_add(entry, "iface",      json_object_new_string(iface));
    json_object_object_add(entry, "config",     json_object_new_string(cfg_path));
    json_object_object_add(entry, "started_at", json_object_new_int64((int64_t)time(NULL)));

    json_object_array_add(reg, entry);
    registry_save(reg);
    json_object_put(reg);

    printf("Started %s (PID %d, AppID %d) on %s\n", name, (int)pid, appId, iface);
}

//Finds a registry index by name
static bool registry_find_by_name(struct json_object *arr, const char *name, int *idx_out) {
    int len = json_object_array_length(arr);
    for (int i = 0; i < len; ++i) {
        struct json_object *e = json_object_array_get_idx(arr, i);
        struct json_object *jn = NULL;
        if (json_object_object_get_ex(e, "name", &jn)) {
            const char *n = json_object_get_string(jn);
            if (n && strcmp(n, name) == 0) { if (idx_out) *idx_out = i; return true; }
        }
    } return false;
}

//Finds a registry index by pid
static bool registry_find_by_pid(struct json_object *arr, pid_t pid, int *idx_out) {
    int len = json_object_array_length(arr);
    for (int i = 0; i < len; ++i) {
        struct json_object *e = json_object_array_get_idx(arr, i);
        struct json_object *jp = NULL;
        if (json_object_object_get_ex(e, "pid", &jp)) {
            if ((pid_t)json_object_get_int(jp) == pid) { if (idx_out) *idx_out = i; return true; }
        }
    } return false;
}

//Terminates a subscriber by registry index and removes its state
static void stop_index(struct json_object *reg, int idx) {
    struct json_object *e = json_object_array_get_idx(reg, idx);
    struct json_object *jp=NULL,*jn=NULL;
    if (!json_object_object_get_ex(e, "pid", &jp)) return;
    pid_t pid = (pid_t) json_object_get_int(jp);
    const char *name = "";
    if (json_object_object_get_ex(e, "name", &jn)) name = json_object_get_string(jn);

    if (proc_alive(pid)) {
        kill(pid, SIGTERM);
        for (int i=0;i<30 && proc_alive(pid);++i) usleep(100*1000);
        if (proc_alive(pid)) kill(pid, SIGKILL);
    }
    char pbuf[128]; snprintf(pbuf, sizeof(pbuf), "/tmp/goose_sub_status_%d.json", (int)pid);
    unlink(pbuf);

    json_object_array_del_idx(reg, idx, 1);
    registry_save(reg);
    printf("Stopped %s (PID %d)\n", name, (int)pid);
}

//Kills one or more subscribers by name, pid, or "all"
static void stop_one(const char *arg) {
    struct json_object *reg = registry_load();
    registry_prune_dead(reg);

    if (strcmp(arg,"all")==0) {
        for (int i=json_object_array_length(reg)-1; i>=0; --i) stop_index(reg,i);
        json_object_put(reg); return;
    }

    char *end=NULL; long p = strtol(arg,&end,10);
    if (end && *end=='\0' && p>0) {
        int idx=-1; if (registry_find_by_pid(reg,(pid_t)p,&idx)) stop_index(reg,idx);
        else printf("No entry with PID %ld\n", p);
        json_object_put(reg); return;
    }

    int idx=-1; if (registry_find_by_name(reg,arg,&idx)) stop_index(reg,idx);
    else printf("No entry named \"%s\"\n", arg);
    json_object_put(reg);
}

//Send manual reset (SIGUSR1) to subscribers
static bool proc_alive(pid_t pid);

static void reset_one(const char *arg) {
    struct json_object *reg = registry_load();
    registry_prune_dead(reg);

    if (strcmp(arg,"all")==0) {
        int len = json_object_array_length(reg);
        for (int i=0; i<len; ++i) {
            struct json_object *e = json_object_array_get_idx(reg, i);
            struct json_object *jp=NULL;
            if (!json_object_object_get_ex(e,"pid",&jp)) continue;
            pid_t pid = (pid_t) json_object_get_int(jp);
            if (proc_alive(pid)) kill(pid, SIGUSR1);
        }
        printf("Sent reset to all active subscribers.\n");
        json_object_put(reg);
        return;
    }
    
    char *end=NULL; long p = strtol(arg,&end,10);
    if (end && *end=='\0' && p>0) {
        if (proc_alive((pid_t)p)) {
            kill((pid_t)p, SIGUSR1);
            printf("Sent reset to PID %ld\n", p);
        } else {
            printf("No active process with PID %ld\n", p);
        }
        json_object_put(reg); return;
    }

    int idx=-1;
    if (registry_find_by_name(reg,arg,&idx)) {
        struct json_object *e = json_object_array_get_idx(reg, idx);
        struct json_object *jp=NULL;
        if (json_object_object_get_ex(e,"pid",&jp)) {
            pid_t pid = (pid_t) json_object_get_int(jp);
            if (proc_alive(pid)) {
                kill(pid, SIGUSR1);
                printf("Sent reset to %s (PID %d)\n", arg, (int)pid);
            } else {
                printf("%s not running\n", arg);
            }
        }
    } else {
        printf("No entry named \"%s\"\n", arg);
    }
    json_object_put(reg);
}

//Renders the live monitor table by reading /tmp/goose_sub_status_<pid>.json
static void render_live(struct json_object *reg) {
    printf("\033[H\033[J");
    printf("Subscriber Live Monitor (Ctrl+C to exit)\n\n");
    printf("%-6s %-12s %-6s %-7s %-7s %-6s %-7s %-8s %-10s %s\n",
           "PID","Name","AppID","stNum","sqNum","Valid","TTLms","ALARM","Iface","Config");
    printf("------ ------------ ------ ------- ------- ------ ------- -------- ---------- ------------------------------\n");

    int len = json_object_array_length(reg);
    int64_t now_ms = (int64_t)time(NULL) * 1000;
    for (int i=0;i<len;++i) {
        struct json_object *e = json_object_array_get_idx(reg,i);
        struct json_object *jp=NULL,*jn=NULL,*ja=NULL,*ji=NULL,*jc=NULL;
        pid_t pid=0; const char*name=""; const char*iface=""; const char*cfg=""; int appId=-1;

        if (json_object_object_get_ex(e,"pid",&jp)) pid = (pid_t)json_object_get_int(jp);
        if (json_object_object_get_ex(e,"name",&jn)) name = json_object_get_string(jn);
        if (json_object_object_get_ex(e,"appId",&ja)) appId = json_object_get_int(ja);
        if (json_object_object_get_ex(e,"iface",&ji)) iface = json_object_get_string(ji);
        if (json_object_object_get_ex(e,"config",&jc)) cfg = json_object_get_string(jc);

        char pbuf[128]; snprintf(pbuf,sizeof(pbuf),"/tmp/goose_sub_status_%d.json",(int)pid);
        int stNum=-1, sqNum=-1, ttl=-1, age=-1; int valid=-1; int trip=-1; const char* reason="";
        if (file_exists(pbuf)) {
            struct json_object *st = json_object_from_file(pbuf);
            if (st) {
                struct json_object *s=NULL,*q=NULL,*t=NULL,*v=NULL,*ls=NULL,*tr=NULL,*rr=NULL;
                if (json_object_object_get_ex(st,"stNum",&s)) stNum = json_object_get_int(s);
                if (json_object_object_get_ex(st,"sqNum",&q)) sqNum = json_object_get_int(q);
                if (json_object_object_get_ex(st,"ttl_ms",&t)) ttl = json_object_get_int(t);
                if (json_object_object_get_ex(st,"valid",&v)) valid = json_object_get_boolean(v);
                if (json_object_object_get_ex(st,"trip",&tr)) trip = json_object_get_boolean(tr);
                if (json_object_object_get_ex(st,"trip_reason",&rr)) reason = json_object_get_string(rr);
                int64_t lastRecvMs = -1;
                if (json_object_object_get_ex(st,"lastRecvMs",&ls)) lastRecvMs = json_object_get_int64(ls);
                if (lastRecvMs > 0) age = (int)(now_ms - lastRecvMs);
                json_object_put(st);
            }
        }

        const char *alarm = "NORMAL";
        if      (trip == 1)                         alarm = "TRIPPED";
        else if (ttl > 0 && age >= 0 && age > ttl)  alarm = "OFFLINE";
        else if (valid == 0)                        alarm = "INVALID";


        printf("%-6d %-12s %-6d %-7d %-7d %-6s %-7d %-8s %-10s %s%s\n",
               (int)pid, name, appId, stNum, sqNum,
               (valid==1 ? "yes" : (valid==0 ? "no" : "?")),
               ttl, alarm, iface, cfg, proc_alive(pid) ? "" : "  [DEAD]");

        if (trip==1 && reason && *reason)
            printf("   -> TRIP REASON: %s\n", reason);
        if (ttl>0 && age>=0 && age>ttl)
            printf("   -> OFFLINE: Age %dms exceeded TTL %dms\n", age, ttl);
    }
}

//Live monitor loop with simple input for start/stop commands
static volatile sig_atomic_t live_exit = 0;
static void on_sigint(int sig){ (void)sig; live_exit = 1; }

static void live_monitor(void) {
    signal(SIGINT,on_sigint);
    int flags = fcntl(STDIN_FILENO, F_GETFL, 0);
    fcntl(STDIN_FILENO, F_SETFL, flags | O_NONBLOCK);

    char input[512]; size_t in_len=0; input[0]='\0'; time_t last=0;

    while (!live_exit) {
        struct json_object *reg = registry_load();
        registry_prune_dead(reg);

        time_t now = time(NULL);
        if (now != last && in_len==0) { render_live(reg); last = now; printf("\n> "); fflush(stdout); }

        char ch; ssize_t r = read(STDIN_FILENO,&ch,1);
        if (r==1) {
            if (ch=='\n'||ch=='\r') {
                input[in_len]='\0'; char cmd[512]; snprintf(cmd,sizeof(cmd),"%s",input);
                in_len=0; input[0]='\0';

                char *tok = strtok(cmd," \t");
                if (tok) {
                    if (strcmp(tok,"start")==0) {
                        char *cfg=strtok(NULL," \t"), *iface=strtok(NULL," \t");
                        if (!cfg||!iface) printf("\nUsage: start <config.json> <iface>\n");
                        else start_subscriber(cfg,iface);
                    } else if (strcmp(tok,"stop")==0) {
                        char *arg=strtok(NULL," \t");
                        if(!arg) printf("\nUsage: stop <name|pid|all>\n");
                        else stop_one(arg);
                    } else {
                        printf("\nCommands: start <cfg> <iface> | stop <name|pid|all>\n");
                    }
                }
                render_live(reg); printf("\n> "); fflush(stdout);
            }
            else if (ch==0x7f || ch==0x08) { if (in_len>0){ in_len--; input[in_len]='\0'; } }
            else if (isprint((unsigned char)ch) && in_len < sizeof(input)-1) { input[in_len++]=ch; input[in_len]='\0'; }
        }

        usleep(20000);
        json_object_put(reg);
    }

    fcntl(STDIN_FILENO, F_SETFL, flags);
    printf("\nLive monitor closed.\n");
}

//One-shot list of active subscribers
static void list_once(void){
    struct json_object *reg = registry_load();
    registry_prune_dead(reg);

    printf("\n%-8s %-16s %-8s %-10s %-24s %s\n",
           "PID","Name","AppID","Interface","Started (UTC)","Config");
    printf("-------- ---------------- -------- ---------- ------------------------ ------------------------------\n");

    int len = json_object_array_length(reg);
    for (int i=0;i<len;++i){
        struct json_object *e=json_object_array_get_idx(reg,i);
        struct json_object *jp=NULL,*jn=NULL,*ja=NULL,*ji=NULL,*jc=NULL,*js=NULL;
        pid_t pid=0; const char *name="", *iface="", *cfg=""; int appId=-1; time_t started=0;

        if (json_object_object_get_ex(e,"pid",&jp)) pid=(pid_t)json_object_get_int(jp);
        if (json_object_object_get_ex(e,"name",&jn)) name=json_object_get_string(jn);
        if (json_object_object_get_ex(e,"appId",&ja)) appId=json_object_get_int(ja);
        if (json_object_object_get_ex(e,"iface",&ji)) iface=json_object_get_string(ji);
        if (json_object_object_get_ex(e,"config",&jc)) cfg=json_object_get_string(jc);
        if (json_object_object_get_ex(e,"started_at",&js)) started=(time_t)json_object_get_int64(js);

        char ts[32]=""; struct tm tm; gmtime_r(&started,&tm);
        strftime(ts,sizeof(ts),"%Y-%m-%d %H:%M:%S",&tm);

        printf("%-8d %-16s %-8d %-10s %-24s %s%s\n",
               (int)pid, name, appId, iface, ts, cfg, proc_alive(pid) ? "" : "  [DEAD]");
    }
    json_object_put(reg);
}

//Prints the menu
static void print_menu(void){
    printf("\n=== Subscription Manager ===\n");
    printf("1) Start subscriber\n");
    printf("2) Stop subscriber (name|pid|all)\n");
    printf("3) Live monitor (Ctrl+C to exit)\n");
    printf("4) List once\n");
    printf("5) Quit\n");
    printf("6) Reset subscriber (name|pid|all)\n> ");
    fflush(stdout);
}


//Main CLI loop
int main(void){
    if (!dir_exists("subscriptions")) {
        if (mkdir("subscriptions", 0775) != 0 && errno != EEXIST)
            die("Cannot create subscriptions/: %s", strerror(errno));
    }

    char line[512];
    while (1) {
        print_menu();
        if (!fgets(line,sizeof(line),stdin)) break;
        size_t L=strlen(line); if (L && line[L-1]=='\n') line[L-1]='\0';

        if (strcmp(line,"1")==0) {
            char cfg[256], iface[64];
            printf("Config path: ");
            if (!fgets(cfg,sizeof(cfg),stdin)) continue;
            L=strlen(cfg); if (L && cfg[L-1]=='\n') cfg[L-1]='\0';
            printf("Interface: ");
            if (!fgets(iface,sizeof(iface),stdin)) continue;
            L=strlen(iface); if (L && iface[L-1]=='\n') iface[L-1]='\0';
            start_subscriber(cfg, iface);
        }
        else if (strcmp(line,"2")==0) {
            char arg[128];
            printf("Stop which (name|pid|all): ");
            if (!fgets(arg,sizeof(arg),stdin)) continue;
            L=strlen(arg); if (L && arg[L-1]=='\n') arg[L-1]='\0';
            stop_one(arg);
        }
        else if (strcmp(line,"3")==0) {
            live_exit=0;
            live_monitor();
        }
        else if (strcmp(line,"4")==0) {
            list_once();
        }
        else if (strcmp(line,"5")==0 || strcasecmp(line,"q")==0 || strcasecmp(line,"quit")==0) {
            printf("Bye.\n");
            break;
        }
        else if (strcmp(line,"6")==0) {
            char arg[128];
            printf("Reset which (name|pid|all): ");
            if (!fgets(arg,sizeof(arg),stdin)) continue;
            size_t L=strlen(arg); if (L && arg[L-1]=='\n') arg[L-1]='\0';
            reset_one(arg);
        }
        else {
            printf("Enter 1..5\n");
        }
    }
    return 0;
}
