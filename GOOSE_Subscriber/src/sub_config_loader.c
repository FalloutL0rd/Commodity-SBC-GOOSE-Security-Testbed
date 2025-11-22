/*
Loads a subscription JSON into SubscriptionConfig
*/

#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <json-c/json.h>

typedef struct {
    char     name[64];
    uint16_t appId;
    char     gocbRef[128];
    uint8_t  dstMac[6];

    int      data_values_count;
    char     trip_logic_path[256];
} SubscriptionConfig;

static bool parse_hex_mac(const char *s, uint8_t mac[6]) {
    if (!s) return false;
    int v[6];
    if (sscanf(s, "%x:%x:%x:%x:%x:%x", &v[0], &v[1], &v[2], &v[3], &v[4], &v[5]) != 6)
        return false;
    for (int i=0;i<6;i++) mac[i] = (uint8_t)v[i];
    return true;
}

static void jstrcpy(struct json_object *j, const char *key, char *dst, size_t n) {
    struct json_object *x = NULL;
    if (json_object_object_get_ex(j, key, &x)) {
        const char *s = json_object_get_string(x);
        if (s) snprintf(dst, n, "%s", s);
    }
}

int load_subscription_config(const char *path, SubscriptionConfig *cfg) {
    if (!path || !cfg) return -1;
    memset(cfg, 0, sizeof(*cfg));
    cfg->data_values_count = -1;

    struct json_object *root = json_object_from_file(path);
    if (!root) {
        fprintf(stderr, "Config error: cannot parse %s\n", path);
        return -1;
    }

    struct json_object *x = NULL;

    jstrcpy(root, "name", cfg->name, sizeof(cfg->name));

    if (json_object_object_get_ex(root, "appId", &x))
        cfg->appId = (uint16_t) json_object_get_int(x);

    jstrcpy(root, "gocbRef", cfg->gocbRef, sizeof(cfg->gocbRef));

    if (json_object_object_get_ex(root, "dstMac", &x)) {
        const char *macs = json_object_get_string(x);
        if (!parse_hex_mac(macs, cfg->dstMac)) {
            fprintf(stderr, "Invalid dstMac in %s\n", path);
            json_object_put(root);
            return -1;
        }
    }

    if (json_object_object_get_ex(root, "data_values_count", &x))
        cfg->data_values_count = json_object_get_int(x);

    jstrcpy(root, "trip_logic", cfg->trip_logic_path, sizeof(cfg->trip_logic_path));

    if (cfg->appId == 0 || cfg->gocbRef[0] == '\0') {
        fprintf(stderr, "Missing appId or gocbRef in %s\n", path);
        json_object_put(root);
        return -1;
    }

    json_object_put(root);
    return 0;
}
