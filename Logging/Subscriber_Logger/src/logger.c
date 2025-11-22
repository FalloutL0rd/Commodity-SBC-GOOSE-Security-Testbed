/*
Passive GOOSE logger
---------------------
Purpose:
  - Run: ./publisher_logger <iface>
  - Program immediately forks (parent exits, child daemonizes)
  - Daemon waits until top of next minute, logs EXACTLY 60 seconds of GOOSE frames, writes CSV logs/<prefix>_YYYYMMDD_HHMM.csv, then exits

CSV columns (per packet):
  - epoch,appId,stNum,sqNum where epoch is microseconds since Unix epoch
*/

#define _POSIX_C_SOURCE 200809L

//Define legacy BSD-style integer types that libpcap/bpf.h expects
#ifndef u_char
#define u_char  unsigned char
#endif

#ifndef u_short
#define u_short unsigned short
#endif

#ifndef u_int
#define u_int   unsigned int
#endif

#ifndef u_long
#define u_long  unsigned long
#endif

#include <pcap.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>

static int ensure_logs_dir(void)
{
    struct stat st;
    if (stat("logs", &st) == 0) {
        if (S_ISDIR(st.st_mode))
            return 0;
        return -1;
    }
    if (mkdir("logs", 0777) != 0) {
        return -1;
    }
    return 0;
}

//Small BER length parser
//Advances *p and returns length, or 0 on error
static size_t ber_read_length(const u_char **p, const u_char *end)
{
    if (*p >= end)
        return 0;

    u_char lb = **p;
    (*p)++;

    if ((lb & 0x80) == 0) {
        //Short form
        return lb;
    } else {
        int num = lb & 0x7f;
        if (num <= 0 || num > 4)
            return 0;
        if (*p + num > end)
            return 0;

        size_t len = 0;
        for (int i = 0; i < num; i++)
            len = (len << 8) | (*p)[i];

        *p += num;
        return len;
    }
}

//Decode a positive INTEGER (1..4 bytes) into uint32_t
static int ber_read_uint(const u_char *v, size_t vlen, uint32_t *out)
{
    if (vlen == 0 || vlen > 4)
        return -1;

    uint32_t val = 0;
    for (size_t i = 0; i < vlen; i++)
        val = (val << 8) | v[i];

    *out = val;
    return 0;
}

//Parse Ethernet + GOOSE to extract appId/stNum/sqNum
//Returns 0 on success, -1 on failure / not GOOSE
static int parse_goose(const u_char *packet, int len,
                       unsigned *appId, unsigned *stNum, unsigned *sqNum)
{
    //Minimum for non-VLAN GOOSE
    if (len < 22)
        return -1;

    //EtherType and offsets
    u_int16_t ethertype = ((u_int16_t)packet[12] << 8) | packet[13];
    int appid_offset = 0;
    int apdu_offset  = 0;

    if (ethertype == 0x8100) {
        //VLAN tagged
        if (len < 26)
            return -1;
        u_int16_t inner = ((u_int16_t)packet[16] << 8) | packet[17];
        if (inner != 0x88b8)
            return -1;
        appid_offset = 18;
        apdu_offset  = 26;
    } else if (ethertype == 0x88b8) {
        //No VLAN
        if (len < 22)
            return -1;
        appid_offset = 14;
        apdu_offset  = 22;
    } else {
        return -1;
    }

    if (appid_offset + 2 > len)
        return -1;

    *appId = ((unsigned)packet[appid_offset] << 8) |
             (unsigned)packet[appid_offset + 1];

    if (apdu_offset + 2 > len)
        return -1;

    const u_char *apdu = packet + apdu_offset;
    int apdu_len = len - apdu_offset;

    //GOOSE APDU starts with SEQUENCE tag 0x61
    if (apdu[0] != 0x61 || apdu_len < 2)
        return -1;

    const u_char *p   = apdu + 1;
    const u_char *end = apdu + apdu_len;

    size_t seq_len = ber_read_length(&p, end);
    if (seq_len == 0)
        return -1;
    if (p + seq_len > end)
        seq_len = end - p;

    const u_char *seq_end = p + seq_len;

    int have_st = 0;
    int have_sq = 0;
    unsigned st = 0;
    unsigned sq = 0;

    while (p < seq_end && (!have_st || !have_sq)) {
        u_char tag = *p++;
        if (p >= seq_end)
            break;

        size_t vlen = ber_read_length(&p, seq_end);
        if (vlen == 0 || p + vlen > seq_end)
            break;

        const u_char *v = p;

        if (tag == 0x85 && !have_st) {
            uint32_t val;
            if (ber_read_uint(v, vlen, &val) == 0) {
                st = val;
                have_st = 1;
            }
        } else if (tag == 0x86 && !have_sq) {
            uint32_t val;
            if (ber_read_uint(v, vlen, &val) == 0) {
                sq = val;
                have_sq = 1;
            }
        }

        p += vlen;
    }

    if (!have_st || !have_sq)
        return -1;

    *stNum = st;
    *sqNum = sq;
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <interface>\n", argv[0]);
        return 1;
    }

    const char *iface = argv[1];

    if (ensure_logs_dir() != 0)
        return 1;

    //Fork so we immediately return the shell prompt
    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return 1;
    }
    if (pid > 0) {
        //Parent tells user and exits.
        printf("Logger started in background (PID %d) on interface %s\n", pid, iface);
        fflush(stdout);
        return 0;
    }

    //Child becomes session leader and detaches from terminal
    if (setsid() < 0) {
        _exit(1);
    }

    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    //Daemon body
    struct timeval now;
    if (gettimeofday(&now, NULL) != 0) {
        _exit(1);
    }

    time_t now_sec     = now.tv_sec;
    time_t next_minute = (now_sec / 60 + 1) * 60;
    long long usec_wait = (long long)(next_minute - now_sec) * 1000000LL
                        - (long long)now.tv_usec;

    if (usec_wait > 0) {
        struct timespec ts;
        ts.tv_sec  = usec_wait / 1000000LL;
        ts.tv_nsec = (usec_wait % 1000000LL) * 1000LL;
        nanosleep(&ts, NULL);
    }

    if (gettimeofday(&now, NULL) != 0) {
        _exit(1);
    }

    long long start_us = (long long)now.tv_sec * 1000000LL + now.tv_usec;
    long long end_us   = start_us + 60LL * 1000000LL;

    time_t start_sec = now.tv_sec;
    struct tm tm_local;
    localtime_r(&start_sec, &tm_local);

    char filename[256];
    snprintf(filename, sizeof(filename),
             "logs/subscriber_%04d%02d%02d_%02d%02d.csv",
             tm_local.tm_year + 1900,
             tm_local.tm_mon + 1,
             tm_local.tm_mday,
             tm_local.tm_hour,
             tm_local.tm_min);

    FILE *out = fopen(filename, "w");
    if (!out) {
        _exit(1);
    }

    //Header epoch time is in microseconds.
    fprintf(out, "epoch,appId,stNum,sqNum\n");

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(iface, 65535, 1, 1000, errbuf);
    if (!handle) {
        fclose(out);
        _exit(1);
    }

    struct bpf_program fp;
    const char filter_exp[] = "ether proto 0x88b8 or (vlan and ether[16:2]=0x88b8)";

    if (pcap_compile(handle, &fp, filter_exp, 1, PCAP_NETMASK_UNKNOWN) == -1) {
        pcap_close(handle);
        fclose(out);
        _exit(1);
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        pcap_freecode(&fp);
        pcap_close(handle);
        fclose(out);
        _exit(1);
    }

    pcap_freecode(&fp);

    //Capture loop for 60 seconds
    while (1) {
        struct timeval tv_now;
        if (gettimeofday(&tv_now, NULL) != 0) {
            break;
        }

        long long now_us2 = (long long)tv_now.tv_sec * 1000000LL + tv_now.tv_usec;
        if (now_us2 >= end_us)
            break;

        struct pcap_pkthdr *hdr;
        const u_char *pkt;
        int rc = pcap_next_ex(handle, &hdr, &pkt);

        if (rc == 1) {
            unsigned appId = 0;
            unsigned stNum = 0;
            unsigned sqNum = 0;

            if (parse_goose(pkt, (int)hdr->caplen, &appId, &stNum, &sqNum) == 0) {
                long long epoch_us = (long long)hdr->ts.tv_sec * 1000000LL
                                   + (long long)hdr->ts.tv_usec;

                fprintf(out, "%lld,%u,%u,%u\n",
                        epoch_us, appId, stNum, sqNum);
            }
        } else if (rc == 0) {
            continue;
        } else {
            break;
        }
    }

    pcap_close(handle);
    fclose(out);
    _exit(0);
}
