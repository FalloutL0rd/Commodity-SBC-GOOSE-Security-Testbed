#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>

static inline uint16_t be16(const uint8_t* p){ return (uint16_t)(p[0]<<8)|p[1]; }
static inline void     set_be16(uint8_t* p, uint16_t v){ p[0]=(uint8_t)(v>>8); p[1]=(uint8_t)(v&0xFF); }

//General BER length
static bool ber_len_read(const uint8_t* b, size_t end, size_t pos, size_t *len, size_t *nlen)
{
    if (pos >= end) return false;
    uint8_t L0 = b[pos];
    if ((L0 & 0x80) == 0) {
        *len  = L0;
        *nlen = 1;
        return (pos + 1 <= end);
    }
    uint8_t n = (uint8_t)(L0 & 0x7F);
    if (n == 0 || n > 3) return false;
    if (pos + 1 + n > end) return false;
    size_t v = 0;
    for (uint8_t i=0;i<n;i++) v = (v<<8) | b[pos+1+i];
    *len  = v;
    *nlen = (size_t)1 + n;
    return true;
}

//Write BER length back
static void ber_len_write_same(uint8_t* b, size_t pos, size_t newLen, size_t nLen)
{
    if (nLen == 1) {
        b[pos] = (uint8_t)newLen;
    } else {
        uint8_t n = (uint8_t)(nLen - 1);
        b[pos] = (uint8_t)(0x80 | n);
        size_t v = newLen;
        for (int i=(int)n-1; i>=0; --i) { b[pos+1+i] = (uint8_t)(v & 0xFF); v >>= 8; }
    }
}

//Advance over a TLV using BER (short/long)
//Returns next pos or 0 on error/out-of-bounds
static size_t tlv_next_ber(const uint8_t* b, size_t end, size_t pos)
{
    if (pos + 2 > end) return 0;
    size_t L, nL;
    if (!ber_len_read(b, end, pos+1, &L, &nL)) return 0;
    size_t nx = pos + 1 + nL + L;
    return (nx <= end) ? nx : 0;
}

typedef struct {
  uint16_t appId;
  uint32_t stNum;
  uint32_t sqNum;
  int      tag_pos;
  int      tag_len;
} GooseMeta;

//Meta extraction
int goose_extract_meta(const uint8_t* frame, size_t flen, GooseMeta* M)
{
  memset(M, 0, sizeof(*M));
  M->tag_pos = -1; M->tag_len = 0;
  if (flen < 42) return -1;

  //EtherType and offsets
  uint16_t et = be16(frame + 12);
  size_t apdu_off = 0;
  if (et == 0x8100) {
    if (flen < 26 || be16(frame+16) != 0x88b8) return -2;
    M->appId = be16(frame + 18);
    apdu_off = 26;
  } else if (et == 0x88b8) {
    M->appId = be16(frame + 14);
    apdu_off = 22;
  } else return -3;

  //Dive into outer SEQUENCE (0x61)
  if (apdu_off + 2 > flen || frame[apdu_off] != 0x61) return -4;
  size_t seq_L=0, seq_nL=0;
  if (!ber_len_read(frame, flen, apdu_off+1, &seq_L, &seq_nL)) return -4;
  size_t seq_V = apdu_off + 1 + seq_nL;
  size_t seq_E = seq_V + seq_L;
  if (seq_E > flen) return -4;

  //Scan SEQUENCE to find stNum/sqNum with flexible tags
  int foundSt=0, foundSq=0;
  for (size_t i = seq_V; i + 2 <= seq_E; ) {
    uint8_t T = frame[i];
    size_t L,nL; if (!ber_len_read(frame, seq_E, i+1, &L, &nL)) break;
    if (L <= 4) {
      if (!foundSt && (T==0x85 || T==0x87 || T==0x02)) {
        uint32_t v=0; for (size_t k=0;k<L;k++) v=(v<<8)|frame[i+1+nL+k];
        M->stNum = v; foundSt=1;
      } else if (foundSt && !foundSq && (T==0x86 || T==0x88 || T==0x02)) {
        uint32_t v=0; for (size_t k=0;k<L;k++) v=(v<<8)|frame[i+1+nL+k];
        M->sqNum = v; foundSq=1;
      }
    }
    size_t nx = i + 1 + nL + L; if (nx<=i) break; i = nx;
    if (foundSt && foundSq) break;
  }
  if (!foundSt || !foundSq) return -4;

  //Find allData (0xAB) using full BER stepping
  size_t all_Lpos=0, all_Vpos=0, all_end=0, all_nL=0, all_Lval=0;
  for (size_t i = seq_V; i + 2 <= seq_E; ) {
    if (frame[i] == 0xAB) {
      if (!ber_len_read(frame, seq_E, i+1, &all_Lval, &all_nL)) break;
      all_Lpos = i+1; all_Vpos = i+1+all_nL; all_end = all_Vpos + all_Lval;
      break;
    }
    size_t nx = tlv_next_ber(frame, seq_E, i); if (!nx) break; i = nx;
  }
  if (!all_Vpos || all_end > seq_E || all_end <= all_Vpos) return 0;

  //Inside allData select the LAST TLV (whatever its tag)
  int last_pos=-1, last_len=0;
  for (size_t p = all_Vpos; p + 2 <= all_end; ) {
    size_t L,nL; if (!ber_len_read(frame, all_end, p+1, &L, &nL)) break;
    size_t tlv_total = 1 + nL + L; size_t nx = p + tlv_total;
    if (nx > all_end) break;
    last_pos = (int)p; last_len = (int)tlv_total;
    p = nx;
  }
  if (last_pos >= 0) { M->tag_pos = last_pos; M->tag_len = last_len; }
  return 0;
}

//Strip the last TLV & fix lengths
int strip_last_octet_tag(uint8_t* frame, size_t* p_flen, int tag_pos, int tag_len)
{
  if (!frame || !p_flen || *p_flen < 42 || tag_pos <= 0 || tag_len < 2) return -1;
  size_t flen = *p_flen;

  //EtherType and offsets
  uint16_t et = be16(frame + 12);
  size_t app_len_off = 0, apdu_off = 0;
  if (et == 0x8100) {
    if (flen < 26 || be16(frame+16) != 0x88b8) return -2;
    app_len_off = 20;
    apdu_off    = 26;
  } else if (et == 0x88b8) {
    app_len_off = 16;
    apdu_off    = 22;
  } else return -3;

  if ((size_t)tag_pos < apdu_off || (size_t)(tag_pos + tag_len) > flen) return -4;

  //Locate outer SEQUENCE (0x61) first to fix its BER length later
  size_t seq_tag = apdu_off;
  size_t seq_L = 0, seq_nL = 0;
  if (!ber_len_read(frame, flen, seq_tag+1, &seq_L, &seq_nL)) return -5;
  size_t seq_V = seq_tag + 1 + seq_nL;

  //Re-find allData using full BER and choose the one that contains the tag
  size_t all_Lpos=0, all_Vpos=0, all_end=0, all_nL=0, all_Lval=0;
  bool   have_all=false;
  for (size_t i = seq_V; i + 2 <= flen; ) {
    if (frame[i] == 0xAB) {
      size_t L,nL; if (!ber_len_read(frame, flen, i+1, &L, &nL)) return -6;
      size_t V = i+1+nL, E = V + L;
      if (E > flen) return -7;
      if ((size_t)tag_pos >= V && (size_t)(tag_pos + tag_len) <= E) {
        all_Lpos = i+1; all_Vpos = V; all_end = E; all_nL = nL; all_Lval = L;
        have_all = true;
        break;
      }
      i = i + 1 + nL + L;
      continue;
    }
    size_t nx = tlv_next_ber(frame, flen, i); if (!nx) break; i = nx;
  }

  //1) Remove the final TLV with one memmove
  size_t tail_src = (size_t)tag_pos + (size_t)tag_len;
  size_t tail_len = flen - tail_src;
  memmove(frame + tag_pos, frame + tail_src, tail_len);
  flen -= (size_t)tag_len;

  //2) Shrink allData length (if we found it)
  if (have_all) {
    size_t new_all_L = all_Lval - (size_t)tag_len;
    ber_len_write_same(frame, all_Lpos, new_all_L, all_nL);
  }

  //3) Shrink outer SEQUENCE(0x61) BER length unconditionally
  size_t new_seq_L = seq_L - (size_t)tag_len;
  ber_len_write_same(frame, seq_tag+1, new_seq_L, seq_nL);

  //4) Shrink APPID Length (2-byte BE)
  uint16_t app_len = be16(frame + app_len_off);
  app_len = (uint16_t)(app_len - (uint16_t)tag_len);
  set_be16(frame + app_len_off, app_len);

  *p_flen = flen;
  return 0;
}
