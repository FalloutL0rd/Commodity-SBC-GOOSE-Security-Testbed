#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <json-c/json.h>

typedef struct {
    bool   enabled;
    char   mode[32];
    uint8_t k_device[32];
    char   infoFmt[128];
    int    trunc_bytes;
} HmacConfig;

static HmacConfig g_hmac;
static bool g_loaded = false;

static bool hex2bin(const char* hex, uint8_t* out, size_t outlen) {
    size_t L = strlen(hex);
    if (L != outlen*2) return false;
    for (size_t i=0;i<outlen;i++){
        unsigned v; if (sscanf(hex+2*i, "%2x", &v)!=1) return false; out[i]=(uint8_t)v;
    }
    return true;
}

static const char* find_hmac_path(void) {
    static char path[PATH_MAX];

    const char *envp = getenv("HMAC_CONFIG");
    if (envp && access(envp, R_OK) == 0) return envp;

    if (access("security/hmac.json", R_OK) == 0) return "security/hmac.json";
    if (access("../security/hmac.json", R_OK) == 0) return "../security/hmac.json";

    ssize_t n = readlink("/proc/self/exe", path, sizeof(path)-1);
    if (n > 0) {
        path[n] = '\0';
        char *slash = strrchr(path, '/');
        if (slash) {
            *slash = '\0';
            snprintf(slash, sizeof(path) - (slash - path), "/../security/hmac.json");
            if (access(path, R_OK) == 0) return path;
        }
    }
    return NULL;
}

static void jstrcpy(struct json_object *j, const char *key, char *dst, size_t n) {
    struct json_object *x=NULL;
    if (json_object_object_get_ex(j,key,&x)) {
        const char *s = json_object_get_string(x);
        if (s) snprintf(dst,n,"%s",s);
    }
}

//HKDF/HMAC
void hkdf_sha256_extract(const uint8_t *salt, size_t salt_len,
                         const uint8_t *ikm, size_t ikm_len,
                         uint8_t *prk, size_t prk_len);
void hkdf_sha256_expand(const uint8_t *prk, size_t prk_len,
                        const uint8_t *info, size_t info_len,
                        uint8_t *okm, size_t okm_len);
void hmac_sha256(const uint8_t *key, size_t key_len,
                 const uint8_t *data, size_t data_len,
                 uint8_t *out32);

//Canon blob + dataset bytes
size_t auth_build_canonical_blob(uint8_t *buf, size_t buf_max,
                                 const char* goID, const char* gocbRef, uint16_t appId,
                                 uint32_t stNum, uint32_t sqNum,
                                 const void* dataset_bytes, size_t dataset_len);
size_t auth_dataset_bytes_from_cfg(uint8_t *buf, size_t buf_max, const void* cfg);

static void build_info(char *out, size_t n, const char* tmpl,
                       const char* goID, const char* gocbRef, uint16_t appId)
{
    const char *p = tmpl; size_t used=0;
    while (*p && used+1<n) {
        if (p[0]=='{') {
            if      (strncmp(p,"{goID}",6)==0)   { used+=snprintf(out+used,n-used,"%s",goID);   p+=6; continue; }
            else if (strncmp(p,"{gocbRef}",9)==0){ used+=snprintf(out+used,n-used,"%s",gocbRef);p+=9; continue; }
            else if (strncmp(p,"{appId}",8)==0)  { used+=snprintf(out+used,n-used,"%u",appId);  p+=8; continue; }
        }
        out[used++] = *p++;
    }
    out[used]='\0';
}

static void auth_load_once(void)
{
    if (g_loaded) return;
    g_loaded = true;

    memset(&g_hmac, 0, sizeof(g_hmac));
    g_hmac.enabled = false;
    snprintf(g_hmac.mode, sizeof(g_hmac.mode), "hmac-sha256-16");
    snprintf(g_hmac.infoFmt, sizeof(g_hmac.infoFmt), "GOOSE|{goID}|{gocbRef}|{appId}");
    g_hmac.trunc_bytes = 16;

    const char *cfgPath = find_hmac_path();
    if (!cfgPath) {
        fprintf(stderr,"[auth] HMAC disabled (security/hmac.json not found; set HMAC_CONFIG to override)\n");
        return;
    }

    struct json_object *root = json_object_from_file(cfgPath);
    if (!root) {
        fprintf(stderr,"[auth] HMAC disabled (failed to parse %s)\n", cfgPath);
        return;
    }
    fprintf(stderr,"[auth] loading %s\n", cfgPath);

    struct json_object *x=NULL,*kdf=NULL,*jkey=NULL,*jtr=NULL;
    if (json_object_object_get_ex(root,"enabled",&x))
        g_hmac.enabled = json_object_get_boolean(x);
    jstrcpy(root, "mode", g_hmac.mode, sizeof(g_hmac.mode));

    if (json_object_object_get_ex(root,"key_device_hex",&jkey)) {
        const char* hex = json_object_get_string(jkey);
        if (!hex || !hex2bin(hex, g_hmac.k_device, sizeof(g_hmac.k_device))) {
            fprintf(stderr,"[auth] invalid key_device_hex in %s\n", cfgPath);
            g_hmac.enabled = false;
        }
    } else {
        g_hmac.enabled = false;
    }

    if (json_object_object_get_ex(root,"kdf",&kdf)) {
        jstrcpy(kdf,"infoFmt", g_hmac.infoFmt, sizeof(g_hmac.infoFmt));
    }
    if (json_object_object_get_ex(root,"truncate_bytes",&jtr))
        g_hmac.trunc_bytes = json_object_get_int(jtr);

    json_object_put(root);

    if (g_hmac.enabled)
        fprintf(stderr,"[auth] HMAC enabled (mode=%s, trunc=%d, placement=dataset:last)\n",
                g_hmac.mode, g_hmac.trunc_bytes);
    else
        fprintf(stderr,"[auth] HMAC disabled by config\n");
}

bool auth_is_enabled(void) { auth_load_once(); return g_hmac.enabled; }
int  auth_trunc_len(void)  { auth_load_once(); return g_hmac.trunc_bytes; }

size_t auth_make_hmac_tag(uint8_t *out, size_t out_max,
                          const char* goID, const char* gocbRef, uint16_t appId,
                          uint32_t stNum, uint32_t sqNum,
                          const void* cfg_ptr)
{
    auth_load_once();
    if (!g_hmac.enabled) return 0;

    uint8_t ds[1024]; size_t ds_len = auth_dataset_bytes_from_cfg(ds,sizeof(ds),cfg_ptr);
    uint8_t canon[2048];
    size_t cn = auth_build_canonical_blob(canon,sizeof(canon),
                                          goID,gocbRef,appId,stNum,sqNum,ds,ds_len);

    uint8_t prk[32]={0};
    hkdf_sha256_extract(NULL,0,g_hmac.k_device,sizeof(g_hmac.k_device),prk,sizeof(prk));

    char infoStr[256]; build_info(infoStr,sizeof(infoStr),g_hmac.infoFmt,goID,gocbRef,appId);
    uint8_t okm[32]; hkdf_sha256_expand(prk,sizeof(prk),(const uint8_t*)infoStr,strlen(infoStr),okm,sizeof(okm));

    uint8_t mac[32]; hmac_sha256(okm,sizeof(okm),canon,cn,mac);

    size_t L = (g_hmac.trunc_bytes>0 && g_hmac.trunc_bytes<=32) ? (size_t)g_hmac.trunc_bytes : 16;
    if (L > out_max) L = out_max;
    memcpy(out, mac, L);
    return L;
}
