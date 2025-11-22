/*
INTERNAL BINARY (not user-facing)
----------------------------------
This program is launched automatically by publication_manager as a background process
It loads a JSON config file and runs a steady-state GOOSE publisher using libIEC61850

Purpose:
  - Provides a controlled environment for each publication
  - Keeps the publisher modular and daemon-friendly
  - Writes live status updates to /tmp/goose_status_<pid>.json

Users should NEVER run this directly
*/

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

//Structs duplicated from config_loader.c and publisher_core.c to avoid header dependencies
typedef struct {
    unsigned short appId;
    char gocbRef[128];
    char datSet[128];
    char goID[128];
    unsigned char dstMac[6];
    int  vlanId;
    int  vlanPriority;
    int  timeAllowedToLive;
    int  confRev;
    _Bool ndsCom;
    _Bool test;
    int  heartbeat_ms;
    int  dataset_count;
    struct {
        char name[64];
        char type[16];
        char quality[16];
        _Bool bool_val;
        int   int_val;
    } dataset[32];
} PublicationConfig;

//Function prototypes (declared elsewhere)
int load_publication_config(const char *path, PublicationConfig *cfg);
int publisher_run(PublicationConfig *cfg, const char *interface);

//Prints internal usage help for developers
static void usage(const char *prog){
    printf("INTERNAL: %s <config.json> <iface>\n", prog);
}

//Engine entry point that loads config and starts publishing
int main(int argc, char **argv)
{
    if (argc < 3) { usage(argv[0]); return 1; }
    const char *cfgpath = argv[1];
    const char *iface   = argv[2];

    PublicationConfig cfg;
    if (load_publication_config(cfgpath, &cfg) != 0) {
        fprintf(stderr, "publisher_engine: failed to load config: %s\n", cfgpath);
        return 1;
    }

    //Launch the steady publisher loop
    //(Will continue indefinitely until SIGTERM/SIGINT)
    return publisher_run(&cfg, iface);
}
