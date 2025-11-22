/*
  - Runs a steady GOOSE subscriber
  - Evaluates realistic trip rules
  - Enforces stNum-change + post-event burst + latch + reset hysteresis
  - Writes status JSON for the manager
*/

#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include <json-c/json.h>

#include "libiec61850/goose_receiver.h"
#include "libiec61850/goose_subscriber.h"
#include "libiec61850/hal_thread.h"
#include "libiec61850/linked_list.h"
#include "libiec61850/mms_value.h"

//Matches loader struct to avoid header deps
typedef struct {
    char     name[64];
    uint16_t appId;
    char     gocbRef[128];
    uint8_t  dstMac[6];
    int      data_values_count;
    char     trip_logic_path[256];
} SubscriptionConfig;

//Trip rules model (config-driven)
typedef struct {
    int  index;
    char type[8];
    int  equals_int;
    bool equals_bool;
    char label[64];
} TripRule;

typedef struct {
    char name[64];
    enum { TRIP_ANY=0, TRIP_ALL=1 } logic;
    bool latch;

    //Realism knobs
    bool require_stnum_change;
    bool require_burst;
    int  burst_window_ms;
    int  burst_min_frames;
    int  burst_interval_max_ms;

    //Manual reset only + baseline re-learn (configurable)
    //Unlatch only when manager sends Reset
    bool manual_reset_required;
    //Silence window to accept next stNum=1 as fresh   
    int  baseline_relearn_ms;

    //Reset hysteresis (eligibility only and do not auto-unlatch in manual mode)
    struct {
        bool normal_required;
        int  min_sq_in_state;
        int  normal_dwell_ms;
        int  no_burst_ms;
        TripRule normal_rules[16];
        int      normal_rule_count;
    } reset;

    //Keep for compatibility (we won't auto-reset)
    bool reset_on_stnum_change;   

    //Trip rules
    TripRule rules[16];
    int      rule_count;
    bool pin_source;
    int  source_cooldown_ms;
} TripLogic;

//FSM for trip runtime
typedef enum { ST_IDLE=0, ST_ARM_CAND, ST_TRIPPED, ST_RESET_PEND } RTState;

typedef struct {
    RTState  state;
    uint32_t last_stNum;
    int64_t  last_arrival_ms;
    int64_t  st_change_ms;
    int      burst_count;
    bool     in_burst_window;

    bool     latched;

    //Reset tracking / eligibility (telemetry only in manual mode)
    int64_t  normal_start_ms;
    int64_t  last_burst_like_ms;
    int      sq_seen_in_state;
    uint32_t state_sq_base;
} TripRT;

//Epoch in ms
static int64_t now_ms(void) {
    struct timespec ts; clock_gettime(CLOCK_REALTIME, &ts);
    return (int64_t)ts.tv_sec*1000 + ts.tv_nsec/1000000;
}

//Writes subscriber status into /tmp/goose_sub_status_<pid>.json
static void write_status_json(uint32_t stNum, uint32_t sqNum, uint32_t ttl,
                              uint64_t goose_ts_ms, bool valid,
                              bool trip, const char *trip_reason)
{
    pid_t pid = getpid();
    char path[128];
    snprintf(path, sizeof(path), "/tmp/goose_sub_status_%d.json", (int)pid);

    struct json_object *root = json_object_new_object();
    json_object_object_add(root, "pid", json_object_new_int(pid));
    json_object_object_add(root, "stNum", json_object_new_int((int)stNum));
    json_object_object_add(root, "sqNum", json_object_new_int((int)sqNum));
    json_object_object_add(root, "ttl_ms", json_object_new_int((int)ttl));
    json_object_object_add(root, "valid", json_object_new_boolean(valid));
    json_object_object_add(root, "lastRecvMs", json_object_new_int64((int64_t)goose_ts_ms));
    json_object_object_add(root, "lastUpdate", json_object_new_int64((int64_t)now_ms()));
    json_object_object_add(root, "trip", json_object_new_boolean(trip));
    if (trip_reason && *trip_reason)
        json_object_object_add(root, "trip_reason", json_object_new_string(trip_reason));

    json_object_to_file_ext(path, root, JSON_C_TO_STRING_PLAIN);
    json_object_put(root);
}

//Trip logic loader
static bool trip_logic_eval_rules_anyall(const TripRule *rules, int n, MmsValue *values, char reason[96]) {
    if (!values || n<=0) return false;
    int matches=0; reason[0]='\0';
    for (int i=0;i<n;i++) {
        const TripRule *r=&rules[i];
        MmsValue *el = MmsValue_getElement(values, r->index);
        if (!el) continue;
        bool hit=false;
        if (strcasecmp(r->type,"bool")==0 && MmsValue_getType(el)==MMS_BOOLEAN)
            hit = (MmsValue_getBoolean(el) == r->equals_bool);
        else if (strcasecmp(r->type,"int")==0 && (MmsValue_getType(el)==MMS_INTEGER || MmsValue_getType(el)==MMS_UNSIGNED))
            hit = (MmsValue_toInt32(el) == r->equals_int);
        if (hit) {
            matches++;
            if (reason[0]=='\0' && r->label[0]) snprintf(reason,96,"%s", r->label);
        }
    }
    return (matches>0);
}

static bool trip_logic_eval_trip(const TripLogic *tl, MmsValue *values, char reason[96]) {
    if (!tl || tl->rule_count==0) return false;
    bool any = trip_logic_eval_rules_anyall(tl->rules, tl->rule_count, values, reason);
    if (tl->logic == TRIP_ANY) return any;
    int hits=0;
    for (int i=0;i<tl->rule_count;i++) {
        TripRule r = tl->rules[i];
        char tmp[96]="";
        bool ok = trip_logic_eval_rules_anyall(&r,1,values,tmp);
        if (ok) hits++;
    }
    if (hits == tl->rule_count) {
        if (reason[0]=='\0' && tl->rules[0].label[0]) snprintf(reason,96,"%s", tl->rules[0].label);
        return true;
    }
    return false;
}

static bool trip_logic_eval_normal(const TripLogic *tl, MmsValue *values) {
    if (!tl) return false;
    if (!tl->reset.normal_required) return true;
    if (tl->reset.normal_rule_count<=0) return false;
    char unused[96];
    //Normal is satisfied if ALL normal_rules match
    int hits=0;
    for (int i=0;i<tl->reset.normal_rule_count;i++) {
        TripRule r = tl->reset.normal_rules[i];
        bool ok = trip_logic_eval_rules_anyall(&r,1,values,unused);
        if (ok) hits++;
    }
    return (hits == tl->reset.normal_rule_count);
}

static bool trip_logic_load(const char *path, TripLogic *tl) {
    if (!path || !*path) return false;
    memset(tl, 0, sizeof(*tl));

    //Reasonable defaults (overridden by JSON if present)
    tl->logic = TRIP_ANY;
    tl->latch = true;
    tl->require_stnum_change   = true;
    tl->require_burst          = true;
    tl->burst_window_ms        = 60;
    tl->burst_min_frames       = 3;
    tl->burst_interval_max_ms  = 10;
    tl->manual_reset_required  = true;
    tl->baseline_relearn_ms    = 3000;
    tl->reset.normal_required  = true;
    tl->reset.min_sq_in_state  = 3;
    tl->reset.normal_dwell_ms  = 2000;
    tl->reset.no_burst_ms      = 500;
    tl->pin_source             = false;
    tl->source_cooldown_ms     = 6000;

    struct json_object *root = json_object_from_file(path);
    if (!root) return false;

    struct json_object *x=NULL, *arr=NULL;

    if (json_object_object_get_ex(root,"name",&x)) {
        const char *s=json_object_get_string(x); if (s) snprintf(tl->name,sizeof(tl->name),"%s",s);
    }
    if (json_object_object_get_ex(root,"logic",&x)) {
        const char *s=json_object_get_string(x);
        tl->logic = (s && strcasecmp(s,"all")==0) ? TRIP_ALL : TRIP_ANY;
    }
    if (json_object_object_get_ex(root,"latch",&x))
        tl->latch = json_object_get_boolean(x);

    if (json_object_object_get_ex(root,"require_stnum_change",&x))
        tl->require_stnum_change = json_object_get_boolean(x);
    if (json_object_object_get_ex(root,"require_burst",&x))
        tl->require_burst = json_object_get_boolean(x);
    if (json_object_object_get_ex(root,"burst_window_ms",&x))
        tl->burst_window_ms = json_object_get_int(x);
    if (json_object_object_get_ex(root,"burst_min_frames",&x))
        tl->burst_min_frames = json_object_get_int(x);
    if (json_object_object_get_ex(root,"burst_interval_max_ms",&x))
        tl->burst_interval_max_ms = json_object_get_int(x);
    if (json_object_object_get_ex(root,"baseline_relearn_ms",&x))
        tl->baseline_relearn_ms = json_object_get_int(x);

    if (json_object_object_get_ex(root,"reset_on_stnum_change",&x))
        tl->reset_on_stnum_change = json_object_get_boolean(x);

    //Optional source pinning
    if (json_object_object_get_ex(root,"pin_source",&x))
        tl->pin_source = json_object_get_boolean(x);
    if (json_object_object_get_ex(root,"source_cooldown_ms",&x))
        tl->source_cooldown_ms = json_object_get_int(x);

    //Trip rules
    if (json_object_object_get_ex(root,"rules",&arr) && json_object_is_type(arr,json_type_array)) {
        int n=json_object_array_length(arr); if (n>16) n=16;
        for (int i=0;i<n;++i) {
            struct json_object *r=json_object_array_get_idx(arr,i);
            TripRule *tr=&tl->rules[tl->rule_count];
            memset(tr,0,sizeof(*tr));
            if (json_object_object_get_ex(r,"index",&x)) tr->index=json_object_get_int(x);
            if (json_object_object_get_ex(r,"type",&x)) {
                const char *s=json_object_get_string(x); if (s) snprintf(tr->type,sizeof(tr->type),"%s",s);
            }
            if (json_object_object_get_ex(r,"equals",&x)) {
                if (json_object_is_type(x,json_type_boolean)) tr->equals_bool=json_object_get_boolean(x);
                else tr->equals_int=json_object_get_int(x);
            }
            if (json_object_object_get_ex(r,"label",&x)) {
                const char *s=json_object_get_string(x); if (s) snprintf(tr->label,sizeof(tr->label),"%s",s);
            }
            tl->rule_count++;
        }
    }

    //Reset policy (eligibility only in manual-reset mode)
    struct json_object *rp=NULL;
    if (json_object_object_get_ex(root,"reset_policy",&rp) && json_object_is_type(rp,json_type_object)) {
        if (json_object_object_get_ex(rp,"normal_required",&x)) tl->reset.normal_required=json_object_get_boolean(x);
        if (json_object_object_get_ex(rp,"min_sq_in_state",&x)) tl->reset.min_sq_in_state=json_object_get_int(x);
        if (json_object_object_get_ex(rp,"normal_dwell_ms",&x)) tl->reset.normal_dwell_ms=json_object_get_int(x);
        if (json_object_object_get_ex(rp,"no_burst_ms",&x)) tl->reset.no_burst_ms=json_object_get_int(x);

        struct json_object *nr=NULL;
        if (json_object_object_get_ex(rp,"normal_rules",&nr) && json_object_is_type(nr,json_type_array)) {
            int n=json_object_array_length(nr); if (n>16) n=16;
            for (int i=0;i<n;i++){
                struct json_object *r=json_object_array_get_idx(nr,i);
                TripRule *tr=&tl->reset.normal_rules[tl->reset.normal_rule_count];
                memset(tr,0,sizeof(*tr));
                if (json_object_object_get_ex(r,"index",&x)) tr->index=json_object_get_int(x);
                if (json_object_object_get_ex(r,"type",&x)) {
                    const char *s=json_object_get_string(x); if (s) snprintf(tr->type,sizeof(tr->type),"%s",s);
                }
                if (json_object_object_get_ex(r,"equals",&x)) {
                    if (json_object_is_type(x,json_type_boolean)) tr->equals_bool=json_object_get_boolean(x);
                    else tr->equals_int=json_object_get_int(x);
                }
                tl->reset.normal_rule_count++;
            }
        }
    }

    json_object_put(root);
    return (tl->rule_count>0 || tl->reset.normal_rule_count>0);
}

//Listener + FSM
static volatile int running = 1;
static volatile sig_atomic_t reset_requested = 0;

static void on_sigterm(int sig){ (void)sig; running = 0; }
static void on_sigusr1(int sig){ (void)sig; reset_requested = 1; }

static void subscriber_listener(GooseSubscriber s, void *param) {
    //Unpack context
    struct {
        SubscriptionConfig *cfg;
        TripLogic          *tl;
        TripRT             *rt;
    } *C = param;

    const TripLogic *tl = C->tl;
    TripRT *rt = C->rt;

    uint32_t stNum = GooseSubscriber_getStNum(s);
    uint32_t sqNum = GooseSubscriber_getSqNum(s);
    uint32_t ttl   = GooseSubscriber_getTimeAllowedToLive(s);
    uint64_t ts    = GooseSubscriber_getTimestamp(s);
    bool     valid = GooseSubscriber_isValid(s);

    int64_t now = now_ms();
    int64_t iat = (rt->last_arrival_ms>0) ? (now - rt->last_arrival_ms) : -1;
    rt->last_arrival_ms = now;

    //Validity is always enforced
    if (!valid) {
        write_status_json(stNum, sqNum, ttl, now, false, rt->latched, rt->latched ? "latched" : NULL);
        return;
    }

    //Detect stNum change
    bool st_changed = (stNum != rt->last_stNum);

    //DataSet access
    MmsValue *values = GooseSubscriber_getDataSetValues(s);

    //FSM
    switch (rt->state) {
    case ST_IDLE:
        if (st_changed) {
            rt->state = ST_ARM_CAND;
            rt->st_change_ms = now;
            rt->burst_count = 0;
            rt->in_burst_window = true;
            rt->sq_seen_in_state = 0;
            rt->state_sq_base = sqNum;
        }
        break;

    case ST_ARM_CAND: {
        int64_t since = now - rt->st_change_ms;
        if (since <= (tl && tl->require_burst ? tl->burst_window_ms : 0)) {
            if (!tl || !tl->require_burst) {
            } else if (iat >= 0 && iat <= tl->burst_interval_max_ms) {
                rt->burst_count++;
            }
        } else {
            rt->in_burst_window = false;
        }

        //Evaluate rules for this state
        bool rules_hit=false; char reason[96]="";
        if (tl) rules_hit = trip_logic_eval_trip(tl, values, reason);

        bool st_ok    = (!tl || !tl->require_stnum_change) ? true : true;
        bool burst_ok = (!tl || !tl->require_burst) ? true : (rt->burst_count >= tl->burst_min_frames);

        if (rules_hit && st_ok && burst_ok) {
            rt->state = ST_TRIPPED;
            rt->latched = true;
            write_status_json(stNum, sqNum, ttl, ts, true, true, reason[0]?reason:"trip");
            break;
        }

        //Window elapsed without trip -> back to idle
        if (!rt->in_burst_window) rt->state = ST_IDLE;
        break;
    }

    case ST_TRIPPED:
        //LATCHED if tl->manual_reset_required==true, which NEVER auto-unlatches here
        if (st_changed) {
            bool normal_ok = (!tl) ? false : trip_logic_eval_normal(tl, values);
            if (normal_ok) {
                rt->state = ST_RESET_PEND;
                rt->normal_start_ms = now;
                rt->last_burst_like_ms = now;
                rt->sq_seen_in_state = 0;
                rt->state_sq_base = sqNum;
            }
        }
        break;

    case ST_RESET_PEND:
        //Eligibility tracking only
        //Actual unlatch occurs in main loop IF AND ONLY IF manual_reset_required==false (not your case), or after operator reset
        if (sqNum >= rt->state_sq_base) rt->sq_seen_in_state++;
        if (tl && tl->require_burst && iat >= 0 && iat <= tl->burst_interval_max_ms)
            rt->last_burst_like_ms = now;

        //Keep computing eligibility (for display/telemetry)
        (void)now;
        break;
    }

    rt->last_stNum = stNum;

    //Status JSON (trip reflects latch)
    write_status_json(stNum, sqNum, ttl, now, true, rt->latched, rt->latched ? "latched" : NULL);
}

//Runs the subscriber main loop on a given interface using SubscriptionConfig
int subscriber_run(SubscriptionConfig *cfg, const char *interface)
{
    if (!cfg || !interface) return -1;

    //Signals such as TERM stops and USR1 requests manual unlatch/reset
    signal(SIGINT,  on_sigterm);
    signal(SIGTERM, on_sigterm);
    signal(SIGUSR1, on_sigusr1);

    GooseReceiver receiver = GooseReceiver_create();
    if (!receiver) {
        fprintf(stderr, "[ERROR] GooseReceiver_create failed\n");
        return -1;
    }
    GooseReceiver_setInterfaceId(receiver, (char*)interface);

    GooseSubscriber subscriber = GooseSubscriber_create((char*)cfg->gocbRef, NULL);
    if (!subscriber) {
        fprintf(stderr, "[ERROR] GooseSubscriber_create failed\n");
        GooseReceiver_destroy(receiver);
        return -1;
    }
    GooseSubscriber_setDstMac(subscriber, cfg->dstMac);
    GooseSubscriber_setAppId(subscriber, cfg->appId);

    TripLogic tl; bool have_tl = trip_logic_load(cfg->trip_logic_path, &tl);

    TripRT rt = (TripRT){0};
    rt.state = ST_IDLE;
    rt.last_stNum = 0;

    struct {
        SubscriptionConfig *cfg;
        TripLogic          *tl;
        TripRT             *rt;
    } ctx = { cfg, (have_tl ? &tl : NULL), &rt };

    GooseSubscriber_setListener(subscriber, subscriber_listener, &ctx);
    GooseReceiver_addSubscriber(receiver, subscriber);
    GooseReceiver_start(receiver);

    const int  baseline_relearn_ms   = have_tl ? tl.baseline_relearn_ms   : 3000;

    while (running) {
        //Operator manual reset (from manager)
        if (reset_requested) {
            reset_requested = 0;
            rt.latched = false;
            rt.state   = ST_IDLE;
            rt.st_change_ms = 0;
            rt.burst_count = 0;
            rt.in_burst_window = false;
            rt.sq_seen_in_state = 0;
        }

        //Baseline re-learn so after inactivity it forgets previous stNum so next packet is "fresh"
        int64_t now = now_ms();
        if (rt.last_arrival_ms > 0 && (now - rt.last_arrival_ms) >= baseline_relearn_ms) {
            rt.last_stNum = 0;
        }

        Thread_sleep(100);
    }

    GooseReceiver_stop(receiver);
    GooseReceiver_destroy(receiver);

    char path[128];
    snprintf(path, sizeof(path), "/tmp/goose_sub_status_%d.json", (int)getpid());
    unlink(path);
    return 0;
}
