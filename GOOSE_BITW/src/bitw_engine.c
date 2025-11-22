/*
INTERNAL BINARY (not user-facing)
----------------------------------
  - Strict enforce to drop unless verified
  - Proper BER length handling
*/

#define _GNU_SOURCE
#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <signal.h>
#include <stdlib.h>
#include <time.h>
#include <errno.h>
#include <sys/select.h>
#include <sys/time.h>

//Policy + types (local decls)
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
  //Mode select "monitor" or "enforce"
  char mode[16];   
  bool stripTag;
  int  ttl_ms;
  int  maxSqGap;
  int  maxAge_ms;
  Device dev;
  Stream strm;
} Policy;

//Externs implemented in other .c files
extern bool   load_policy(const char* path, Policy* P);
extern int    goose_extract_meta(const uint8_t* frame, size_t flen, void* M_out);
extern void   hkdf_sha256_extract(const uint8_t *salt, size_t salt_len,
                                  const uint8_t *ikm, size_t ikm_len,
                                  uint8_t *prk, size_t prk_len);
extern void   hkdf_sha256_expand(const uint8_t *prk, size_t prk_len,
                                 const uint8_t *info, size_t info_len,
                                 uint8_t *okm, size_t okm_len);
extern void   hmac_sha256(const uint8_t *key, size_t key_len,
                          const uint8_t *data, size_t data_len,
                          uint8_t *out32);
extern int    freshness_check(uint32_t st, uint32_t sq, int ttl_ms, int maxSqGap, int maxAge_ms);
extern int    strip_last_octet_tag(uint8_t* frame, size_t* p_flen, int tag_pos, int tag_len);

//Helpers
static volatile int running = 1;
static void on_sig(int s) { (void)s; running = 0; }

static inline uint16_t be16(const uint8_t* p){ return (uint16_t)(p[0]<<8)|p[1]; }

//BER length decoder
static bool ber_len_read(const uint8_t* b, size_t end, size_t pos, size_t *len, size_t *nlen)
{
  if (pos >= end) return false;
  uint8_t L0 = b[pos];
  if ((L0 & 0x80) == 0) { *len=L0; *nlen=1; return (pos+1)<=end; }
  uint8_t n = (uint8_t)(L0 & 0x7F);
  if (n==0 || n>3) return false;
  if (pos + 1 + n > end) return false;
  size_t v=0; for (uint8_t i=0;i<n;i++) v=(v<<8)|b[pos+1+i];
  *len = v; *nlen = (size_t)1 + n; return true;
}

//Decode ether/vlan to decide if this is GOOSE and report APDU offset
static inline int parse_eth(const uint8_t* pkt, size_t len, int* out_is_goose, size_t* out_apdu_off, int* out_vlan)
{
  if (len < 22) { *out_is_goose=0; return -1; }
  uint16_t et = ((uint16_t)pkt[12]<<8) | pkt[13];
  if (et == 0x8100) {
    if (len < 26) { *out_is_goose=0; return -2; }
    uint16_t inner = ((uint16_t)pkt[16]<<8) | pkt[17];
    *out_is_goose = (inner == 0x88b8);
    *out_apdu_off = 26;
    *out_vlan = 1;
    return 0;
  } else {
    *out_is_goose = (et == 0x88b8);
    *out_apdu_off = 22;
    *out_vlan = 0;
    return 0;
  }
}

//Find seq (0x61) value region and optional allData(0xAB) region
static int locate_seq_and_allData(const uint8_t* f, size_t flen, size_t apdu_off,
                                  size_t* seqV, size_t* seqE, size_t* allV, size_t* allE)
{
  if (apdu_off + 2 > flen || f[apdu_off] != 0x61) return -1;
  size_t L,nL; if (!ber_len_read(f, flen, apdu_off+1, &L, &nL)) return -2;
  size_t V = apdu_off + 1 + nL;
  size_t E = V + L; if (E > flen) return -3;

  if (seqV) { *seqV = V; }
  if (seqE) { *seqE = E; }
  if (allV) { *allV = 0; }
  if (allE) { *allE = 0; }

  //Search for 0xAB within seq
  for (size_t p=V; p+2<=E; ) {
    size_t L2,nL2; if (!ber_len_read(f, E, p+1, &L2, &nL2)) break;
    if (f[p] == 0xAB) { if (allV) *allV = p + 1 + nL2; if (allE) *allE = (p + 1 + nL2 + L2); break; }
    size_t nx = p + 1 + nL2 + L2; if (nx<=p || nx>E) break; p = nx;
  }
  return 0;
}

//FALLBACK: Find a TLV ending exactly at flen, with value len 8..64
static int find_tail_tlv_as_tag(const uint8_t* frame, size_t flen, size_t apdu_off, int* tag_pos, int* tag_len)
{
  for (ssize_t p = (ssize_t)flen - 2; p >= (ssize_t)apdu_off; --p) {
    if ((size_t)p + 2 > flen) continue;
    size_t L=0, nL=0;
    if (!ber_len_read(frame, flen, (size_t)p+1, &L, &nL)) continue;
    size_t tot = 1 + nL + L;
    if ((size_t)p + tot != flen) continue;
    if (L < 8 || L > 64) continue;
    if ((size_t)p < apdu_off) continue;
    *tag_pos = (int)p; *tag_len = (int)tot;
    return 0;
  }
  return -1;
}

//Helpers to match the publisher's canonicalization exactly
static size_t make_dataset_canon_from_frame(uint8_t *out, size_t out_max,
                                            const uint8_t* f, size_t flen,
                                            size_t apdu_off, int tag_pos)
{
  size_t seqV=0, seqE=0, allV=0, allE=0;
  if (locate_seq_and_allData(f, flen, apdu_off, &seqV, &seqE, &allV, &allE) != 0 || !allV) return 0;

  size_t w=0, p=allV; int idx=0;
  while ((int)p < tag_pos && p + 2 <= allE) {
    size_t L,nL; if (!ber_len_read(f,allE,p+1,&L,&nL)) break;
    const uint8_t* val = f + p + 1 + nL;

    if (idx == 0) {
      if (w+3 > out_max) return w;
      out[w++] = 0x01; out[w++] = 0x01;
      uint8_t b = (L>0 && val[L-1]!=0) ? 1 : 0;
      out[w++] = b;
    } else if (idx == 1) {
      if (w+6 > out_max) return w;
      out[w++] = 0x02; out[w++] = 0x04;
      uint32_t u=0; for (size_t k=0;k<L;k++) u=(u<<8)|val[k];
      out[w++] = (uint8_t)(u>>24);
      out[w++] = (uint8_t)(u>>16);
      out[w++] = (uint8_t)(u>>8);
      out[w++] = (uint8_t)(u);
    } else {
      break;
    }

    idx++;
    p = p + 1 + nL + L;
    if ((int)p >= tag_pos) break;
  }
  return w;
}

static size_t put_strF(uint8_t *b, size_t m, size_t w, const char* s){
  size_t L = s? strlen(s):0;
  if (w+2+L>m) return w;
  b[w++]=0xF0; b[w++]=(uint8_t)L;
  if (L){memcpy(b+w,s,L); w+=L;}
  return w;
}
static size_t put_u16F(uint8_t *b, size_t m, size_t w, uint16_t v){
  if (w+4>m) return w;
  b[w++]=0xF1; b[w++]=2;
  b[w++]=(uint8_t)((v>>8)&0xFF);
  b[w++]=(uint8_t)(v&0xFF);
  return w;
}
static size_t put_u32F(uint8_t *b, size_t m, size_t w, uint32_t v){
  if (w+6>m) return w;
  b[w++]=0xF2; b[w++]=4;
  b[w++]=(uint8_t)((v>>24)&0xFF);
  b[w++]=(uint8_t)((v>>16)&0xFF);
  b[w++]=(uint8_t)((v>>8)&0xFF);
  b[w++]=(uint8_t)(v&0xFF);
  return w;
}
static size_t put_blobF(uint8_t *b, size_t m, size_t w, const uint8_t *d, size_t L){
  if (w+2+L>m) return w;
  b[w++]=0xF3; b[w++]=(uint8_t)L;
  if (L){memcpy(b+w,d,L); w+=L;}
  return w;
}
static size_t build_pub_canon(uint8_t *out, size_t out_max,
                              const char* goID, const char* gocbRef, uint16_t appId,
                              uint32_t stNum, uint32_t sqNum,
                              const uint8_t* ds, size_t ds_len)
{
  size_t w=0;
  w=put_strF(out,out_max,w,"GOOSE");
  w=put_strF(out,out_max,w,goID);
  w=put_strF(out,out_max,w,gocbRef);
  w=put_u16F(out,out_max,w,appId);
  w=put_u32F(out,out_max,w,stNum);
  w=put_u32F(out,out_max,w,sqNum);
  w=put_blobF(out,out_max,w,ds,ds_len);
  return w;
}

static void build_info_simple(char *out, size_t n, const char* fmt,
                              const char* goID, const char* gocbRef, uint16_t appId)
{
  size_t u=0;
  while (*fmt && u+1<n) {
    if (fmt[0]=='{' && strncmp(fmt,"{goID}",6)==0)    { u+=snprintf(out+u, n-u, "%s", goID);    fmt+=6; continue; }
    if (fmt[0]=='{' && strncmp(fmt,"{gocbRef}",9)==0) { u+=snprintf(out+u, n-u, "%s", gocbRef); fmt+=9; continue; }
    if (fmt[0]=='{' && strncmp(fmt,"{appId}",8)==0)   { u+=snprintf(out+u, n-u, "%u", (unsigned)appId); fmt+=8; continue; }
    out[u++] = *fmt++;
  }
  out[u] = '\0';
}

static inline bool tag_match_any16(const uint8_t* mac32, const uint8_t* tag16) {
  return memcmp(mac32, tag16, 16) == 0 || memcmp(mac32+16, tag16, 16) == 0;
}

//Verifier + freshness (STRICT, correct BER length)
static int verify_hmac_and_freshness(const Policy* P,
                                     const uint8_t* frame, size_t flen,
                                     uint32_t* out_stNum, uint32_t* out_sqNum,
                                     int* out_tag_pos, int* out_tag_len)
{
  struct { uint16_t appId; uint32_t stNum; uint32_t sqNum; int tag_pos; int tag_len; } M;
  int mrc = goose_extract_meta(frame, flen, &M);
  if (mrc != 0) return 10;

  *out_stNum  = M.stNum;
  *out_sqNum  = M.sqNum;
  *out_tag_pos= M.tag_pos;
  *out_tag_len= M.tag_len;

  if (M.appId != P->strm.appId) return 11;

  if (P->strm.allowUnsigned && M.tag_pos < 0) {
    return freshness_check(M.stNum, M.sqNum, P->ttl_ms, P->maxSqGap, P->maxAge_ms);
  }
  if (M.tag_pos < 0) return 12;
  //Tag length + #len-octets for correct V pointer
  size_t tagVlen=0, nL=0;
  if (!ber_len_read(frame, flen, (size_t)M.tag_pos+1, &tagVlen, &nL)) return 12;
  if (tagVlen != 16 && tagVlen != 32) return 12;
  const uint8_t* tagV = frame + (size_t)M.tag_pos + 1 + nL;

  //Compute APDU offset
  size_t apdu_off = 22;
  uint16_t et = be16(frame + 12);
  if (et == 0x8100) apdu_off = 26;

  //Dataset canonicalization (matches publisher)
  uint8_t ds[256];
  size_t ds_len = make_dataset_canon_from_frame(ds, sizeof(ds), frame, flen, apdu_off, M.tag_pos);

  //Publisher-style canonical blob
  uint8_t pub[512];
  size_t pub_len = build_pub_canon(pub, sizeof(pub),
                             P->strm.goID, P->strm.gocbRef, P->strm.appId,
                             M.stNum, M.sqNum, ds, ds_len);

  //Additional raw candidates up to the tag
  size_t seqV=0, seqE=0, allV=0, allE=0;
  locate_seq_and_allData(frame, flen, apdu_off, &seqV, &seqE, &allV, &allE);

  uint8_t v_all[2048]; size_t v_all_len = 0;
  if (allV && (size_t)M.tag_pos > allV && (size_t)M.tag_pos <= allE) {
    size_t L = (size_t)M.tag_pos - allV;
    if (L > sizeof(v_all)) L = sizeof(v_all);
    memcpy(v_all, frame + allV, L); v_all_len = L;
  }

  uint8_t v_seq[4096]; size_t v_seq_len = 0;
  if (seqV && (size_t)M.tag_pos > seqV && (size_t)M.tag_pos <= seqE) {
    size_t L = (size_t)M.tag_pos - seqV;
    if (L > sizeof(v_seq)) L = sizeof(v_seq);
    memcpy(v_seq, frame + seqV, L); v_seq_len = L;
  }

  //HKDF/OKM
  char info[256];
  build_info_simple(info, sizeof(info), P->dev.kdfInfoFmt,
                    P->strm.goID, P->strm.gocbRef, P->strm.appId);
  uint8_t prk[32]={0}, okm[32];
  hkdf_sha256_extract(NULL, 0, P->dev.k_device, 32, prk, 32);
  hkdf_sha256_expand(prk, 32, (const uint8_t*)info, strlen(info), okm, 32);

  //Try pub, allData, seq
  struct { const uint8_t* buf; size_t len; } cand[3] = {
    {pub,    pub_len},
    {v_all,  v_all_len},
    {v_seq,  v_seq_len}
  };
  uint8_t mac[32];

  for (int i=0;i<3;i++) {
    if (!cand[i].len) continue;
    hmac_sha256(okm, 32, cand[i].buf, cand[i].len, mac);
    if (tagVlen==32 && memcmp(mac, tagV, 32)==0) {
      int fr = freshness_check(M.stNum, M.sqNum, P->ttl_ms, P->maxSqGap, P->maxAge_ms);
      return (fr==0) ? 0 : (20 + fr);
    }
    if (tagVlen==16 && tag_match_any16(mac, tagV)) {
      int fr = freshness_check(M.stNum, M.sqNum, P->ttl_ms, P->maxSqGap, P->maxAge_ms);
      return (fr==0) ? 0 : (20 + fr);
    }
  }
  return 13;
}

//One place that handles verdict + stripping (with fallback)
static void process_and_forward(pcap_t* rx, pcap_t* tx, const Policy* P)
{
  while (running) {
    struct pcap_pkthdr *hdr = NULL; const u_char *pkt = NULL;
    int rc = pcap_next_ex(rx, &hdr, &pkt);
    if (rc <= 0) break;

    //PTP passthrough (0x88f7 incl. VLAN)
    int is_ptp = 0;
    if (hdr->caplen >= 14) {
      uint16_t et = ((uint16_t)pkt[12] << 8) | pkt[13];
      if (et == 0x88f7) {
        is_ptp = 1;
      } else if (et == 0x8100 && hdr->caplen >= 18) {
        uint16_t inner = ((uint16_t)pkt[16] << 8) | pkt[17];
        if (inner == 0x88f7) is_ptp = 1;
      }
    }
    if (is_ptp) {
      int inj = pcap_inject(tx, pkt, (int)hdr->caplen);
      if (inj != (int)hdr->caplen)
        fprintf(stderr, "[inject-ptp] %s\n", pcap_geterr(tx));
      continue;
    }

    int is_goose=0, vlan=0; size_t apdu_off=0;
    parse_eth(pkt, hdr->caplen, &is_goose, &apdu_off, &vlan);

    //STRICT drop non-GOOSE too
    if (!is_goose) {
      fprintf(stderr, "[drop non-goose] len=%u\n", (unsigned)hdr->caplen);
      continue;
    }

    uint32_t st=0, sq=0; int tag_pos=-1, tag_len=0;
    int ver = verify_hmac_and_freshness(P, pkt, hdr->caplen, &st, &sq, &tag_pos, &tag_len);

    //Enforce only forward verified frames
    bool pass = (strcmp(P->mode,"enforce")==0) ? (ver == 0) : true;
    if (!pass) {
      fprintf(stderr, "[drop] ver=%d st=%u sq=%u\n", ver, st, sq);
      continue;
    }

    const uint8_t* outp = pkt; size_t outlen = hdr->caplen;
    uint8_t* buf = NULL;

    if (P->stripTag) {
      int pos = tag_pos, len = tag_len;

      //If parser didn’t give a tag, try tail fallback (BER-correct)
      if (!(pos > 0 && len > 0)) {
        if (find_tail_tlv_as_tag(pkt, hdr->caplen, apdu_off, &pos, &len) == 0)
          fprintf(stderr, "[tail-fallback] pos=%d len=%d\n", pos, len);
      }

      if (pos > 0 && len > 0) {
        buf = (uint8_t*) malloc(outlen);
        memcpy(buf, pkt, outlen);
        size_t before = outlen;
        int sr = strip_last_octet_tag(buf, &outlen, pos, len);
        if (sr == 0) {
          fprintf(stderr, "[strip] pos=%d len=%d delta=%zd\n",
                  pos, len, (ssize_t)before - (ssize_t)outlen);
          outp = buf;
        } else {
          fprintf(stderr, "[strip] skipped rc=%d\n", sr);
          free(buf); buf = NULL;
        }
      } else {
        fprintf(stderr, "[strip] no tag candidate (pos=%d len=%d)\n", pos, len);
      }
    }

    int inj = pcap_inject(tx, outp, (int)outlen);
    if (inj != (int)outlen) fprintf(stderr, "[inject] %s\n", pcap_geterr(tx));
    if (buf) free(buf);
  }
}

int main(int argc, char** argv)
{
  //Expected by the manager: ./bitw_engine <policy.json> <ifA> <ifB>
  if (argc < 4) {
    fprintf(stderr, "Usage: %s <policy.json> <ifA> <ifB>\n", argv[0]);
    return 1;
  }
  const char* pol = argv[1];
  const char* ifA = argv[2];
  const char* ifB = argv[3];

  Policy P;
  if (!load_policy(pol, &P)) {
    fprintf(stderr, "[bitw] failed to load policy '%s'\n", pol);
    return 2;
  }
  fprintf(stderr, "[bitw] mode=%s stripTag=%s ttl=%dms sqGap=%d maxAge=%dms appId=%u\n",
          P.mode, P.stripTag ? "true" : "false",
          P.ttl_ms, P.maxSqGap, P.maxAge_ms, (unsigned)P.strm.appId);

  char errbuf[PCAP_ERRBUF_SIZE] = {0};
  pcap_t* capA = pcap_open_live(ifA, 65535, 1, 1, errbuf);
  if (!capA) { fprintf(stderr, "pcap_open_live(%s): %s\n", ifA, errbuf); return 3; }
  pcap_t* capB = pcap_open_live(ifB, 65535, 1, 1, errbuf);
  if (!capB) { fprintf(stderr, "pcap_open_live(%s): %s\n", ifB, errbuf); return 4; }

  //Low latency + responsive Ctrl-C
  if (pcap_setnonblock(capA, 1, errbuf) == -1)
    fprintf(stderr, "setnonblock(%s): %s\n", ifA, errbuf);
  if (pcap_setnonblock(capB, 1, errbuf) == -1)
    fprintf(stderr, "setnonblock(%s): %s\n", ifB, errbuf);
  pcap_set_immediate_mode(capA, 1);
  pcap_set_immediate_mode(capB, 1);

  /*
  NOTE: no BPF filter. We capture all traffic then:
     - fast-path PTP (0x88f7) across
     - run strict policy/HMAC on GOOSE (0x88b8)
     - drop everything else
  */

  signal(SIGINT, on_sig);
  signal(SIGTERM, on_sig);

  //No set direction so it can read both ways explicitly
  while (running) {
    process_and_forward(capA, capB, &P); /* A -> B */
    process_and_forward(capB, capA, &P); /* B -> A */
    struct timespec ts = { .tv_sec = 0, .tv_nsec = 5 * 1000 * 1000 };
    nanosleep(&ts, NULL);
  }

  pcap_close(capA);
  pcap_close(capB);
  return 0;
}
