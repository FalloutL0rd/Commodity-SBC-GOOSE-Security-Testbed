/*
Responsible for reading and parsing JSON configuration files for each GOOSE publication
Loads into PublicationConfig struct
This file handles everything about dataset setup and parameters
*/

#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <json-c/json.h>

//Data structures for publication configuration
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

//Helper to parse a MAC address string into bytes
static bool parse_hex_mac(const char *s, uint8_t mac[6]) {
    if (!s) return false;
    int v[6];
    if (sscanf(s, "%x:%x:%x:%x:%x:%x", &v[0], &v[1], &v[2], &v[3], &v[4], &v[5]) != 6)
        return false;
    for (int i=0;i<6;i++) mac[i] = (uint8_t)v[i];
    return true;
}

//Helper to safely copy JSON strings
static void jstrcpy(struct json_object *j, const char *key, char *dst, size_t n) {
    struct json_object *x = NULL;
    if (json_object_object_get_ex(j, key, &x)) {
        const char *s = json_object_get_string(x);
        if (s) { snprintf(dst, n, "%s", s); }
    }
}

//Reads the JSON file into a PublicationConfig struct
int load_publication_config(const char *path, PublicationConfig *cfg) {
    if (!path || !cfg) return -1;
    memset(cfg, 0, sizeof(*cfg));

    struct json_object *root = json_object_from_file(path);
    if (!root) {
        fprintf(stderr, "Config error: cannot parse %s\n", path);
        return -1;
    }

    struct json_object *x = NULL;

    //Core GOOSE metadata
    if (json_object_object_get_ex(root, "appId", &x))
        cfg->appId = (uint16_t) json_object_get_int(x);
    jstrcpy(root, "gocbRef", cfg->gocbRef, sizeof(cfg->gocbRef));
    if (cfg->gocbRef[0]=='\0') jstrcpy(root, "goCbRef", cfg->gocbRef, sizeof(cfg->gocbRef));
    jstrcpy(root, "datSet", cfg->datSet, sizeof(cfg->datSet));
    if (cfg->datSet[0]=='\0') jstrcpy(root, "dataSetRef", cfg->datSet, sizeof(cfg->datSet));
    jstrcpy(root, "goID", cfg->goID, sizeof(cfg->goID));
    if (cfg->goID[0]=='\0' && cfg->gocbRef[0]!='\0')
        snprintf(cfg->goID, sizeof(cfg->goID), "%s", cfg->gocbRef);

    //Destination MAC (required)
    if (json_object_object_get_ex(root, "dstMac", &x)) {
        const char *macs = json_object_get_string(x);
        if (!parse_hex_mac(macs, cfg->dstMac)) {
            fprintf(stderr, "Config error: invalid dstMac\n"); json_object_put(root); return -1;
        }
    } else {
        uint8_t def[6] = {0x01,0x0c,0xcd,0x01,0x00,0x01}; memcpy(cfg->dstMac, def, 6);
    }

    //VLAN and timing parameters
    if (json_object_object_get_ex(root, "vlanId", &x))       cfg->vlanId = json_object_get_int(x);
    if (json_object_object_get_ex(root, "vlanPriority", &x)) cfg->vlanPriority = json_object_get_int(x);
    if (json_object_object_get_ex(root, "timeAllowedToLive", &x))
        cfg->timeAllowedToLive = json_object_get_int(x);
    else if (json_object_object_get_ex(root, "timeAllowedToLive_ms", &x))
        cfg->timeAllowedToLive = json_object_get_int(x);
    if (json_object_object_get_ex(root, "confRev", &x)) cfg->confRev = json_object_get_int(x);
    if (json_object_object_get_ex(root, "ndsCom", &x))  cfg->ndsCom = json_object_get_boolean(x);
    if (json_object_object_get_ex(root, "test", &x))    cfg->test   = json_object_get_boolean(x);
    if (json_object_object_get_ex(root, "heartbeat_ms", &x)) cfg->heartbeat_ms = json_object_get_int(x);

    //Default sensible values
    if (cfg->timeAllowedToLive <= 0) cfg->timeAllowedToLive = 2000;
    if (cfg->confRev <= 0)           cfg->confRev = 1;
    if (cfg->heartbeat_ms <= 0)      cfg->heartbeat_ms = 1000;

    //Parse dataset fields
    cfg->dataset_count = 0;
    if (json_object_object_get_ex(root, "dataset", &x) && json_object_is_type(x, json_type_array)) {
        int n = json_object_array_length(x);
        for (int i=0; i<n && cfg->dataset_count<32; i++) {
            struct json_object *e = json_object_array_get_idx(x, i);
            struct json_object *jt = NULL;

            DataField *df = &cfg->dataset[cfg->dataset_count];
            memset(df, 0, sizeof(*df));
            jstrcpy(e, "name", df->name, sizeof(df->name));
            jstrcpy(e, "type", df->type, sizeof(df->type));
            jstrcpy(e, "quality", df->quality, sizeof(df->quality));

            if (json_object_object_get_ex(e, "value", &jt)) {
                if (strcasecmp(df->type,"boolean")==0) df->bool_val = json_object_get_boolean(jt);
                else if (strcasecmp(df->type,"integer")==0) df->int_val = json_object_get_int(jt);
            }

            if (df->name[0]=='\0') snprintf(df->name,sizeof(df->name),"field%d", i);
            if (df->type[0]=='\0') snprintf(df->type,sizeof(df->type),"integer");
            cfg->dataset_count++;
        }
    }

    json_object_put(root);
    return 0;
}
