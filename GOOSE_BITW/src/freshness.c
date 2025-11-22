#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>
#include <stdio.h>

//Very small per-stream state (single stream MVP)
typedef struct {
  uint32_t lastSt;
  uint32_t lastSq;
  uint64_t lastSeenMs;
} Win;

static Win W={0,0,0};

static uint64_t now_ms(void){
  struct timespec ts; clock_gettime(CLOCK_REALTIME,&ts);
  return (uint64_t)ts.tv_sec*1000ULL + ts.tv_nsec/1000000ULL;
}

//Return 0 = fresh, else nonzero (reject)
int freshness_check(uint32_t st, uint32_t sq, int ttl_ms, int maxSqGap, int maxAge_ms) {
  uint64_t t = now_ms();
  if (W.lastSeenMs==0) { W.lastSt=st; W.lastSq=sq; W.lastSeenMs=t; return 0; }

  if (st < W.lastSt) return 1;
  if (st == W.lastSt) {
    if (sq <= W.lastSq) return 2;
    if (sq - W.lastSq > (uint32_t)maxSqGap) return 3;
  } else {
    //Allow reset of sqNum on new state
    if (sq > (uint32_t)maxSqGap) return 4;
  }

  if ((int)(t - W.lastSeenMs) > maxAge_ms) return 5;
  W.lastSt = st; W.lastSq = sq; W.lastSeenMs = t;
  return 0;
}

int ttl_check(uint64_t ingress_ms, int ttl_ms) {
  uint64_t t = now_ms();
  return ((int)(t - ingress_ms) > ttl_ms) ? 1 : 0;
}
