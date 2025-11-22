/*
INTERNAL BINARY (not user-facing)
----------------------------------
Loads a subscription JSON and runs the subscriber loop
Launched by subscription_manager as a background process
*/

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

//Mirror struct to avoid header deps (must match loader/core)
typedef struct {
    char     name[64];
    uint16_t appId;
    char     gocbRef[128];
    uint8_t  dstMac[6];

    int      data_values_count;
    char     trip_logic_path[256];
} SubscriptionConfig;

//Prototypes
int load_subscription_config(const char *path, SubscriptionConfig *cfg);
int subscriber_run(SubscriptionConfig *cfg, const char *interface);

//Prints internal usage
static void usage(const char *prog){
    printf("INTERNAL: %s <config.json> <iface>\n", prog);
}

int main(int argc, char **argv)
{
    if (argc < 3) { usage(argv[0]); return 1; }
    const char *cfgpath = argv[1];
    const char *iface   = argv[2];

    SubscriptionConfig cfg;
    if (load_subscription_config(cfgpath, &cfg) != 0) {
        fprintf(stderr, "subscriber_engine: failed to load config: %s\n", cfgpath);
        return 1;
    }

    printf("[INFO] Subscribing to AppID=%u, GoCB=%s on %s\n", cfg.appId, cfg.gocbRef, iface);
    return subscriber_run(&cfg, iface);
}
