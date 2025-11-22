#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <json-c/json.h>

//This headerless declaration must match bitw_engine.c's Policy
typedef struct {
  char deviceId[64];
  uint8_t k_device[32];
  char kdfInfoFmt[128];
} Device;

typedef struct {
  char  name[64];
  uint16_t appId;
  char  goID[128];
  char  gocbRef[128];
  bool  allowUnsigned;
} Stream;

typedef struct {
  //Mode of "monitor" or "enforce"
  char mode[16];
  bool stripTag;
  int  ttl_ms;
  int  maxSqGap;
  int  maxAge_ms;
  Device dev;
  Stream strm;
} Policy;

static bool hex2bin(const char* h, uint8_t* out, size_t n){
  if (!h) return false;
  size_t L = strlen(h);
  if (L != 2*n) return false;
  for (size_t i=0;i<n;i++){
    unsigned v;
    if (sscanf(h + 2*i, "%2x", &v) != 1) return false;
    out[i] = (uint8_t)v;
  }
  return true;
}

static const char* sget(struct json_object* o, const char* key){
  struct json_object *x=NULL;
  if (json_object_object_get_ex(o, key, &x) && json_object_is_type(x, json_type_string))
    return json_object_get_string(x);
  return NULL;
}
static int iget(struct json_object* o, const char* key, int defv){
  struct json_object *x=NULL;
  if (json_object_object_get_ex(o, key, &x) && json_object_is_type(x, json_type_int))
    return json_object_get_int(x);
  return defv;
}
static bool bget(struct json_object* o, const char* key, bool defv){
  struct json_object *x=NULL;
  if (json_object_object_get_ex(o, key, &x) && (json_object_is_type(x, json_type_boolean) || json_object_is_type(x, json_type_int)))
    return json_object_get_boolean(x);
  return defv;
}

bool load_policy(const char* path, Policy* P)
{
  memset(P, 0, sizeof(*P));
  //Defaults
  snprintf(P->mode, sizeof(P->mode), "enforce");
  P->stripTag = true;
  P->ttl_ms   = 2000;
  P->maxSqGap = 8;
  P->maxAge_ms= 5000;
  snprintf(P->dev.kdfInfoFmt, sizeof(P->dev.kdfInfoFmt), "GOOSE|{goID}|{gocbRef}|{appId}");

  struct json_object* root = json_object_from_file(path);
  if (!root){
    fprintf(stderr, "[policy] cannot read '%s'\n", path);
    return false;
  }

  //Global switches
  {
    const char* m = sget(root, "mode");
    if (m) snprintf(P->mode, sizeof(P->mode), "%s", m);
    P->stripTag = bget(root, "stripTag", P->stripTag);
    P->ttl_ms   = iget(root, "timeAllowedToLive_ms", P->ttl_ms);

    struct json_object* win=NULL;
    if (json_object_object_get_ex(root, "window", &win) && json_object_is_type(win, json_type_object)){
      P->maxSqGap = iget(win, "maxSqGap", P->maxSqGap);
      P->maxAge_ms= iget(win, "maxAge_ms", P->maxAge_ms);
    }
  }

  //Prefer new schema devices[0].streams[0].match
  struct json_object *devs=NULL;
  if (json_object_object_get_ex(root, "devices", &devs) && json_object_is_type(devs, json_type_array) && json_object_array_length(devs) > 0){
    struct json_object* dj = json_object_array_get_idx(devs, 0);
    if (!dj){ json_object_put(root); return false; }
    const char* id = sget(dj,"deviceId");
    if (id) snprintf(P->dev.deviceId, sizeof(P->dev.deviceId), "%s", id);
    const char* fmt = sget(dj,"kdfInfoFmt");
    if (fmt) snprintf(P->dev.kdfInfoFmt, sizeof(P->dev.kdfInfoFmt), "%s", fmt);
    const char* khex = sget(dj,"k_device_hex");
    if (!khex || !hex2bin(khex, P->dev.k_device, 32)){
      fprintf(stderr, "[policy] bad k_device_hex\n");
      json_object_put(root); return false;
    }

    struct json_object *arr=NULL;
    if (!(json_object_object_get_ex(dj,"streams",&arr) && json_object_is_type(arr,json_type_array) && json_object_array_length(arr)>0)){
      fprintf(stderr, "[policy] no streams[] in devices[0]\n");
      json_object_put(root); return false;
    }
    struct json_object *sj = json_object_array_get_idx(arr, 0);
    if (!sj){ json_object_put(root); return false; }

    P->strm.allowUnsigned = bget(sj,"allowUnsigned", false);
    const char* nm = sget(sj,"name");
    if (nm) snprintf(P->strm.name,sizeof(P->strm.name),"%s",nm);

    struct json_object *match=NULL;
    if (!(json_object_object_get_ex(sj, "match", &match) && json_object_is_type(match, json_type_object))){
      fprintf(stderr, "[policy] stream.match missing\n");
      json_object_put(root); return false;
    }
    P->strm.appId = (uint16_t)iget(match,"appId",0);
    const char* go  = sget(match,"goID");
    const char* cb  = sget(match,"gocbRef");
    if (go) snprintf(P->strm.goID,   sizeof(P->strm.goID),   "%s", go);
    if (cb) snprintf(P->strm.gocbRef,sizeof(P->strm.gocbRef),"%s", cb);

    json_object_put(root);
    return (P->strm.appId != 0 && P->strm.goID[0] && P->strm.gocbRef[0]);
  }

  //FALLBACK: old flat schema
  {
    const char* khex = sget(root, "k_device_hex");
    if (khex && hex2bin(khex, P->dev.k_device, 32)){
      const char* fmt = sget(root, "kdfInfoFmt");
      if (fmt) snprintf(P->dev.kdfInfoFmt, sizeof(P->dev.kdfInfoFmt), "%s", fmt);
    }
    P->strm.appId = (uint16_t)iget(root,"appId",0);
    const char* go  = sget(root,"goID");
    const char* cb  = sget(root,"gocbRef");
    if (go) snprintf(P->strm.goID,   sizeof(P->strm.goID),   "%s", go);
    if (cb) snprintf(P->strm.gocbRef,sizeof(P->strm.gocbRef),"%s", cb);
    P->strm.allowUnsigned = bget(root,"allowUnsigned", false);

    json_object_put(root);
    return (P->strm.appId != 0 && P->strm.goID[0] && P->strm.gocbRef[0] && P->dev.k_device[0] + 1);
  }
}
