#include <stdint.h>
#include <string.h>
#include <strings.h>
#include <stdbool.h>
#include <stdio.h>

typedef struct {
    char  name[64];
    char  type[16];
    char  quality[16];
    bool  bool_val;
    int   int_val;
} DataFieldMini;

typedef struct {
    uint16_t appId;
    char     gocbRef[128];
    char     datSet[128];
    char     goID[128];
    unsigned char dstMac[6];
    int      vlanId;
    int      vlanPriority;
    int      timeAllowedToLive;
    int      confRev;
    bool     ndsCom;
    bool     test;
    int      heartbeat_ms;
    int      dataset_count;
    DataFieldMini dataset[32];
} PublicationConfigMini;

//Build dataset bytes (bool/int only)
size_t auth_dataset_bytes_from_cfg(uint8_t *buf, size_t buf_max, const void* cfg_ptr)
{
    const PublicationConfigMini *cfg = (const PublicationConfigMini*)cfg_ptr;
    size_t w=0;
    for (int i=0; i<cfg->dataset_count; i++) {
        const DataFieldMini *df = &cfg->dataset[i];
        uint8_t t = (strcasecmp(df->type,"boolean")==0) ? 0x01 : 0x02;
        if (w+2 >= buf_max) break;
        buf[w++] = t;
        if (t==0x01) {
            buf[w++] = 1; if (w+1>buf_max) break; buf[w++] = df->bool_val ? 1 : 0;
        } else {
            buf[w++] = 4; if (w+4>buf_max) break;
            uint32_t u = (uint32_t)df->int_val;
            buf[w++] = (u>>24)&0xFF; buf[w++] = (u>>16)&0xFF; buf[w++] = (u>>8)&0xFF; buf[w++] = (u)&0xFF;
        }
    }
    return w;
}

static size_t put_str(uint8_t *b, size_t m, size_t w, const char* s){
    size_t L = strlen(s?s:"");
    if (w+2+L > m) L = (m> w+2) ? (m - (w+2)) : 0;
    b[w++] = 0xF0; b[w++] = (uint8_t)L; memcpy(b+w, s?s:"", L); return w+L;
}
static size_t put_u16(uint8_t *b, size_t m, size_t w, uint16_t v){
    if (w+1+2 > m) return w;
    b[w++] = 0xF1; b[w++] = 2; b[w++] = (v>>8)&0xFF; b[w++] = (v)&0xFF; return w;
}
static size_t put_u32(uint8_t *b, size_t m, size_t w, uint32_t v){
    if (w+1+4 > m) return w;
    b[w++] = 0xF2; b[w++] = 4;
    b[w++] = (v>>24)&0xFF; b[w++] = (v>>16)&0xFF; b[w++] = (v>>8)&0xFF; b[w++] = (v)&0xFF; return w;
}
static size_t put_blob(uint8_t *b, size_t m, size_t w, const uint8_t* d, size_t L){
    if (w+2+L > m) L = (m> w+2) ? (m - (w+2)) : 0;
    b[w++] = 0xF3; b[w++] = (uint8_t)L; memcpy(b+w, d, L); return w+L;
}

size_t auth_build_canonical_blob(uint8_t *buf, size_t buf_max,
                                 const char* goID, const char* gocbRef, uint16_t appId,
                                 uint32_t stNum, uint32_t sqNum,
                                 const void* dataset_bytes, size_t dataset_len)
{
    size_t w=0;
    w = put_str(buf,buf_max,w,"GOOSE");
    w = put_str(buf,buf_max,w,goID);
    w = put_str(buf,buf_max,w,gocbRef);
    w = put_u16(buf,buf_max,w,appId);
    w = put_u32(buf,buf_max,w,stNum);
    w = put_u32(buf,buf_max,w,sqNum);
    w = put_blob(buf,buf_max,w,(const uint8_t*)dataset_bytes,dataset_len);
    return w;
}
