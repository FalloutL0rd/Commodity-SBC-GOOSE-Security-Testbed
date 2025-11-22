/*
Converts the loaded dataset from PublicationConfig into MMS values for use in GOOSE message publication
*/

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include "libiec61850/linked_list.h"
#include "libiec61850/mms_value.h"

//Simplified structs for context
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


//Converts each dataset entry into an MmsValue pointer
LinkedList build_mms_dataset_from_config(const PublicationConfig *cfg)
{
    LinkedList list = LinkedList_create();
    for (int i=0; i<cfg->dataset_count; i++) {
        const DataField *df = &cfg->dataset[i];
        MmsValue *v = NULL;

        if (strcasecmp(df->type,"boolean")==0)      v = MmsValue_newBoolean(df->bool_val ? 1 : 0);
        else if (strcasecmp(df->type,"integer")==0) v = MmsValue_newIntegerFromInt32(df->int_val);
        else if (strcasecmp(df->type,"binarytime")==0) v = MmsValue_newBinaryTime(false);
        else v = MmsValue_newIntegerFromInt32(0);

        if (v) LinkedList_add(list, v);
    }
    return list;
}

MmsValue* mms_make_octet_string_and_set(const uint8_t* bytes, size_t len)
{
    if (!bytes || len == 0) return NULL;
    MmsValue* v = MmsValue_newOctetString((int)len, (int)len);
    if (!v) return NULL;
    MmsValue_setOctetString(v, (uint8_t*)bytes, (int)len);
    return v;
}
