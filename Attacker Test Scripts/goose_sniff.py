#!/usr/bin/env python3
"""
goose_sniff.py

Windows/Linux GOOSE traffic sniffer using tshark/pyshark

Created By Ashton Ruesch

Features
==============
* Live capture on Windows or Linux (PyShark + TShark)
* VLAN-aware BPF (up to N nested 802.1Q tags)
* Optional pcap dump (-w)          -> Wireshark-ready
* Offline replay (-r FILE)         -> runs same logic on a saved pcap
* Periodic stats (--stats-interval N)
* Unique-event log to .log / .csv / .json
* ANSI colours via colourama (if installed)

CLI Quick Help
================
-l   | --list-interfaces       list adapters & exit
-i IFACE                       live capture on that interface
-r PCAP                        offline replay from pcap file
-w PCAP                        dump raw frames while capturing
-s N | --stats-interval N      summary every N seconds (0 = off)
-m N | --max-tags N            nested VLAN depth for BPF (default 2)
-n   | --no-bpf                skip BPF; filter later in tshark
-o none|log|csv|json           unique-event output format
-v  -vv  -vvv                  verbosity levels
Ctrl-C                         exit cleanly

Verbosity Levels
================
0: APPID, stNum, sqNum, datSet
1: + ConfRev, Test
2: + lastSeen
3: + srcMAC, dstMAC, VLAN

Dependencies
================
* pyshark
* tshark
* colorama (Optional)

Example Usage
================
# Live capture, stats every 30 seconds, save raw packets
sudo python3 goose_sniff.py -i eth0 -s 30 -w session.pcap

# Offline replay
python3 goose_sniff.py -r session.pcap -v

Known Issues
================
- Capturing packets via server fails
"""

import argparse
import asyncio
import csv
import json
import os
import shutil
import signal
import subprocess
import sys
import time
from collections import OrderedDict
from datetime import datetime
from typing import List

# --------------------- ASCII ART ---------------------
GOOSE_ART = r"""
                                                                                    
                                                          @@@@@@@@@@                      
                                                        @@@@@@@@@@@@@@                    
                                                       @@@@@@ @  @@@@@                    
                                                      @@@@@@@@@@@@@@ @@@                  
                Sniffing                             @@@@@@@@@@@@@@ @@@@ @               
                For GOOSE                            @@@@@@@@@@@@@@@    @@@@@@@           *sniff*
                 Traffic                            @@@@@@@@@@@@@@@ @@@@    @@@@         
                                                    @@@@@@@@@@@@@@                              *sniff*
                                                    @@@@@@@@@@@@                     *sniff*     
                                                   @@@@@@@@@@@@                           
                                                   @@@@@@@@@@@                            
                                                   @@@@@@@@@@                             
                                                  @@@@@@@@@@@                             
                                                  @@@@@@@@@@@                             
                                                 @@@@@@@@@@@@                             
                                                 @@@@@@@@@@@@                             
                                               @@@@@@@@@@@@@@                             
                                           @@@@@@@@@@@@@@@@@@                             
                                       @@@@@@@@@@@@@@@@@@@@@@                             
                                  @@@@@@@@@@@@@@@@@@@@@@@@@@@                             
                             @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@                             
                        =@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@                             
          @@        @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@                             
         @ @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@                             
         @ @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@                             
         @@ @@@@@@@@  @@@@@@@@@@@@@@@@@@@@@@@@@@@ @@@@@@@@@@                              
          @@ @@@@@ @@@   @@@@@@@@@@@@@@@@@@@@@@@ @@@@@@@@@@@                              
          @@@ @@@@@  @@@@@     @@@@@@@@@@@@@@@  @@@@@@@@@@@                               
           @@@  @@@@@   @@@@@@@@@@@@*@@@@@@@@ @@@@@@@@@@@@%                               
            @@@@  @@@@@@@         .@@@@@@@@  @@@@@@@@@@@@@                                
             @@@@@  *@@@@@@@@@@@@@@@@@@@  @@@@@@@@@@@@@@                                  
              @@@@@@@    @@@@@@@@@@@   @@@@@@@@@@@@@@@@                                   
                @@@@@@@@@@        @@@@@@@@@@@@@@@@@@@                                     
                  @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@                                       
                     @@@@@@@@@@@@@@@@@@@@@@@@@@@@                                         
                        @@@@@@@@@@@@@@@@@@@@@                                             
                               @@@@@@@                                                    
                                  +  @@@                                                  
                                 .@@ @@:                                                  
                                 =@@ @@@                                                  
                                 *@@ @@@                                                  
                                 *@@ @@=                                                  
                                 @@@ @@@@                                                 
                                                                                                                                                                                       
"""

# ------- Optional color setup (colorama) ------------------------------
try:
    from colorama import init as c_init, Fore, Style
    c_init()
    CLR_ID = Fore.YELLOW + Style.BRIGHT
    CLR_ST = Fore.MAGENTA + Style.BRIGHT
    CLR_SQ = Fore.CYAN   + Style.BRIGHT
    CLR_DS = Fore.GREEN  + Style.BRIGHT
    CLR_HDR = Fore.CYAN  + Style.BRIGHT
    CLR_RST = Style.RESET_ALL
except ImportError:                       # Colorama not installed
    CLR_ID = CLR_ST = CLR_SQ = CLR_DS = CLR_HDR = CLR_RST = ""

# ------- Locate tshark -------------------------------------------------
def _find_tshark() -> str:
    if shutil.which("tshark"):
        return "tshark"
    if os.name == "nt":
        for p in (r"C:\Program Files\Wireshark\tshark.exe",
                  r"C:\Program Files (x86)\Wireshark\tshark.exe"):
            if os.path.isfile(p):
                return p
    sys.exit("Error: 'tshark' binary not found.")
TSHARK = _find_tshark()

# ------- Import pyshark ------------------------------------------------
try:
    import pyshark
except ImportError:
    sys.exit("Error: pip install pyshark")

# ------- Silence PyShark EOFError spam on Ctrl-C -----------------------
loop = asyncio.new_event_loop()
asyncio.set_event_loop(loop)
def _ignore(loop, ctx):
    if isinstance(ctx.get("exception"), EOFError):
        return
    loop.default_exception_handler(ctx)
loop.set_exception_handler(_ignore)

# ------- Interface helpers ---------------------------------------------
def list_interfaces():
    out = subprocess.check_output([TSHARK, "-D"], text=True, errors="ignore")
    print("\nAvailable interfaces:\n" + out)

def map_name(name: str) -> str:
    out = subprocess.check_output([TSHARK, "-D"], text=True, errors="ignore")
    for line in out.splitlines():
        if name.lower() in line.lower():
            return line.split(". ", 1)[1].split(" (", 1)[0].strip()
    return name

# ------- Build dynamic BPF for GOOSE through VLAN tags ----------------
def build_goose_bpf(max_tags: int = 2) -> str:
    """Return a libpcap-friendly BPF that matches GOOSE behind up to `max_tags` VLAN tags."""
    clauses: List[str] = ["ether proto 0x88B8"]  # Untagged
    for depth in range(1, max_tags + 1):
        vlan_chain = "vlan and " * depth
        clauses.append(f"({vlan_chain}ether proto 0x88B8)")
    return " or ".join(clauses)

# ------- Main capture + redraw loop ------------------------------------
def capture(dev: str, args, log_file="goose_unique.log"):
    v = args.v

    # Choose live or offline capture
    if args.read_pcap:
        cap = pyshark.FileCapture(args.read_pcap, display_filter="goose",
                                  tshark_path=TSHARK)
        packet_iter = cap
        mode = "pcap-replay"
    else:
        kwargs = {"interface": dev}
        if not args.no_bpf:
            kwargs["bpf_filter"] = build_goose_bpf(args.max_tags)
        if args.write_pcap:
            kwargs["output_file"] = args.write_pcap      # No display filter!
        else:
            kwargs["display_filter"] = "goose"
        if "tshark_path" in pyshark.LiveCapture.__init__.__code__.co_varnames:
            kwargs["tshark_path"] = TSHARK
        cap = pyshark.LiveCapture(**kwargs)
        packet_iter = cap.sniff_continuously()
        mode = "live"

    # Column layout
    cols = [("APPID","appid",6), ("stNum","stNum",6),
            ("sqNum","sqNum",8), ("datSet","datSet",20)]
    if v>=1: cols += [("ConfRev","ConfRev",7), ("Test","Test",4)]
    if v>=2: cols += [("lastSeen","lastSeen",8)]
    if v>=3: cols += [("srcMAC","srcMAC",17), ("dstMAC","dstMAC",17), ("VLAN","VLAN",4)]

    # Optional output files
    log_fh = csv_writer = json_fh = None
    if args.output == "log":
        log_fh = open(log_file, "a", encoding="utf-8", buffering=1)
        if os.stat(log_file).st_size == 0:
            hdr = "  ".join(n.ljust(w) for n,_,w in cols)
            log_fh.write(hdr+"\n"+"-"*len(hdr)+"\n")
    elif args.output == "csv":
        csv_fh = open(log_file.replace(".log",".csv"), "a", newline="", encoding="utf-8")
        first = csv_fh.tell() == 0
        csv_writer = csv.writer(csv_fh)
        if first:
            csv_writer.writerow([n for n,_,_ in cols])
    elif args.output == "json":
        json_fh = open(log_file.replace(".log",".json"), "a", encoding="utf-8")

    def write_unique(ev):
        if args.output=="none":
            return
        if args.output=="log":
            log_fh.write("  ".join(str(ev[k]).ljust(w) for _,k,w in cols)+"\n")
        elif args.output=="csv":
            csv_writer.writerow([ev[k] for _,k,_ in cols])
        elif args.output=="json":
            json_fh.write(json.dumps({n:ev[k] for n,k,_ in cols})+"\n")

    # Stats counters
    interval = args.stats_interval
    last_stat_ts = time.time()
    total_pkts = 0
    new_int = 0
    last_line = ""      # Shown under table

    uniques: OrderedDict = OrderedDict()
    stop = False
    signal.signal(signal.SIGINT, lambda *_: globals().update(stop=True))

    def redraw():
        os.system("cls" if os.name=="nt" else "clear")
        print(GOOSE_ART)
        hdr = "  ".join(n.ljust(w) for n,_,w in cols)
        print(f"{CLR_HDR}GOOSE Sniff - {dev}  (mode={mode}, v={v}, fmt={args.output}){CLR_RST}\n")
        print(hdr+"\n"+"-"*len(hdr))
        for ev in uniques.values():
            row=[]
            for _,k,w in cols:
                raw=str(ev.get(k,"")).ljust(w)
                col={"appid":CLR_ID,"stNum":CLR_ST,"sqNum":CLR_SQ,"datSet":CLR_DS}.get(k,"")
                row.append(f"{col}{raw}{CLR_RST}")
            print("  ".join(row))
        # Persistent stats panel
        # Persistent stats panel
        if last_line:
            stats_hdr = f"{CLR_HDR}Stats{CLR_RST}"
            print(f"\n{stats_hdr}")
            print("-" * len(hdr))              # Same length as table dash line
            print(f"{CLR_ST}{last_line}{CLR_RST}")   # Color the numbers

    redraw()
    for pkt in packet_iter:
        if stop:
            break
        total_pkts += 1
        try:
            g = pkt["GOOSE"]
            ev = {
                "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "appid": f"0x{int(g.appid,0):04X}",
                "stNum": int(g.stnum,0),
                "sqNum": int(g.sqnum,0),
                "datSet": g.get_field_value("goose.datSet") or "",
                "ConfRev": g.get_field_value("goose.confRev") or "",
                "Test": g.get_field_value("goose.Test") or "",
                "lastSeen": datetime.now().strftime("%H:%M:%S"),
                "srcMAC": getattr(pkt.eth,"src",""),
                "dstMAC": getattr(pkt.eth,"dst",""),
                "VLAN": g.get_field_value("vlan.id") or "",
            }
        except Exception:
            continue

        key = (ev["appid"], ev["stNum"], ev["datSet"])
        first = key not in uniques
        uniques[key] = ev
        uniques.move_to_end(key)
        if first:
            new_int += 1
            write_unique(ev)
        redraw()

        # Periodic stats update
        if interval and time.time()-last_stat_ts >= interval:
            ts = datetime.now().strftime("%H:%M:%S")
            last_line = (f"{ts}  pkts={total_pkts}  unique={len(uniques)}  "
                         f"new_since_last={new_int}")
            new_int = 0
            last_stat_ts = time.time()
            redraw()

    try:
        cap.close()
    except Exception:
        pass
    if log_fh:
        log_fh.close()
    if json_fh:
        json_fh.close()

# ------- Command-line interface ----------------------------------------
if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("-l","--list-interfaces", action="store_true",
                   help="List adapters and exit")
    p.add_argument("-i","--iface", metavar="IFACE",
                   help="Interface to sniff (e.g. eth0)")
    p.add_argument("-r","--read-pcap", metavar="PCAP",
                   help="Replay packets from pcap instead of live capture")
    p.add_argument("-w","--write-pcap", metavar="PCAP",
                   help="Also write raw frames to this pcap")
    p.add_argument("-o","--output",
                   choices=("none","log","csv","json"),
                   default="none", help="Unique-event output")
    p.add_argument("-s","--stats-interval", type=int, default=0,
                   help="Print summary every N seconds (0 = off)")
    p.add_argument("-m","--max-tags", type=int, default=2,
                   help="Nested VLAN depth for BPF")
    p.add_argument("-n","--no-bpf", action="store_true",
                   help="Skip BPF; filter later in tshark")
    p.add_argument("-v", action="count", default=0,
                   help="Verbosity (-vv, -vvv, ...)")
    args = p.parse_args()

    if args.list_interfaces:
        list_interfaces()
        sys.exit(0)
    if not args.iface and not args.read_pcap:
        sys.exit("Specify -i IFACE for live capture or -r PCAP for replay.")
    dev = map_name(args.iface) if args.iface else args.read_pcap
    capture(dev, args)