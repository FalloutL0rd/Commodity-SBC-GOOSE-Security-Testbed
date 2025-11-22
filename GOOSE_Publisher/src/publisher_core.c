/*
Implements the continuous publisher loop that sends GOOSE frames over Ethernet using libIEC61850
Also maintains live JSON status files for monitor updates
*/

#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <json-c/json.h>

#include "libiec61850/goose_publisher.h"
#include "libiec61850/hal_thread.h"
#include "libiec61850/linked_list.h"
#include "libiec61850/mms_value.h"

//HMAC forward decls
bool   auth_is_enabled(void);
int    auth_trunc_len(void);
size_t auth_make_hmac_tag(uint8_t *out, size_t out_max,
                          const char* goID, const char* gocbRef, uint16_t appId,
                          uint32_t stNum, uint32_t sqNum,
                          const void* cfg_ptr);

//Helper in mms_helpers.c
MmsValue* mms_make_octet_string_and_set(const uint8_t* bytes, size_t len);

//Structs for internal use (match config_loader.c)
typedef struct {
    char  name[64];
    char  type[16];
    char  quality[16];
    bool  bool_val;
    int   int_val;
} DataField;

typedef struct {
    uint16_t appId;
    char     gocbRef[128];
    char     datSet[128];
    char     goID[128];
    uint8_t  dstMac[6];
    int      vlanId;
    int      vlanPriority;
    int      timeAllowedToLive;
    int      confRev;
    bool     ndsCom;
    bool     test;
    int      heartbeat_ms;
    int      dataset_count;
    DataField dataset[32];
} PublicationConfig;

//External MMS builder
extern LinkedList build_mms_dataset_from_config(const PublicationConfig *cfg);

static volatile int running = 1;
static void on_sig(int sig){ (void)sig; running = 0; }

static void write_status_json(uint32_t stNum, uint32_t sqNum)
{
    pid_t pid = getpid();
    char path[128];
    snprintf(path, sizeof(path), "/tmp/goose_status_%d.json", (int)pid);

    struct json_object *root = json_object_new_object();
    json_object_object_add(root, "pid", json_object_new_int((int)pid));
    json_object_object_add(root, "stNum", json_object_new_int((int)stNum));
    json_object_object_add(root, "sqNum", json_object_new_int((int)sqNum));
    json_object_object_add(root, "lastPublish", json_object_new_int64((int64_t)time(NULL)));
    json_object_to_file_ext(path, root, JSON_C_TO_STRING_PLAIN);
    json_object_put(root);
}

int publisher_run(PublicationConfig *cfg, const char *interface) {
    if (!cfg || !interface) return -1;

    signal(SIGINT, on_sig);
    signal(SIGTERM, on_sig);

    //Eth params
    CommParameters p; memset(&p, 0, sizeof(p));
    p.appId = cfg->appId;
    memcpy(p.dstAddress, cfg->dstMac, 6);
    p.vlanId = cfg->vlanId;
    p.vlanPriority = cfg->vlanPriority;

    GoosePublisher pub = GoosePublisher_create(&p, (char*)interface);
    if (!pub) return -1;

    //Apply fixed configuration first
    GoosePublisher_setGoCbRef(pub, (char*)cfg->gocbRef);
    GoosePublisher_setConfRev(pub, cfg->confRev);
    GoosePublisher_setTimeAllowedToLive(pub, cfg->timeAllowedToLive);

    //Build values from config
    LinkedList values = build_mms_dataset_from_config(cfg);

    uint32_t stNum = 1;
    uint32_t sqNum = 0;
    int hb = (cfg->heartbeat_ms > 0) ? cfg->heartbeat_ms : 1000;

    //HMAC tag state
    uint8_t  tagbuf[32];
    int      taglen_conf = auth_trunc_len(); if (taglen_conf<=0) taglen_conf = 16;
    MmsValue *tagVal = NULL;

    //Append tag element (if enabled) BEFORE binding DataSetRef so the library locks to the current list length (3 items)
    if (auth_is_enabled()) {
        size_t L = auth_make_hmac_tag(tagbuf, sizeof(tagbuf),
                                      cfg->goID, cfg->gocbRef, cfg->appId,
                                      stNum, sqNum, cfg);
        if (L > 0) {
            tagVal = mms_make_octet_string_and_set(tagbuf, (size_t)L);
            if (tagVal) LinkedList_add(values, tagVal);
        }
    }

    //Bind the dataset reference normally (realistic) AFTER values list is final
    if (cfg->datSet[0]) {
        GoosePublisher_setDataSetRef(pub, (char*)cfg->datSet);
    }

    //First publish
    GoosePublisher_publish(pub, values);
    write_status_json(stNum, sqNum);

    //Heartbeat loop
    while (running) {
        Thread_sleep(hb);
        if (!running) break;

        if (auth_is_enabled() && tagVal) {
            size_t L = auth_make_hmac_tag(tagbuf, sizeof(tagbuf),
                                          cfg->goID, cfg->gocbRef, cfg->appId,
                                          stNum, (sqNum + 1), cfg);
            if (L > 0) {
                MmsValue_setOctetString(tagVal, tagbuf, (int)L);
            }
        }

        GoosePublisher_publish(pub, values);
        sqNum++;
        write_status_json(stNum, sqNum);
    }

    GoosePublisher_destroy(pub);
    LinkedList_destroyDeep(values, (LinkedListValueDeleteFunction) MmsValue_delete);

    char path[128];
    snprintf(path, sizeof(path), "/tmp/goose_status_%d.json", (int)getpid());
    unlink(path);

    return 0;
}
