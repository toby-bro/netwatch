#!/usr/bin/env python3
import time
import threading
import curses
import argparse
import socket
import subprocess
import shutil
import os
from datetime import datetime
from queue import Queue, Empty
from scapy.all import sniff, ARP, IP, IPv6, UDP, TCP, ICMP, DNS, Ether, DNSRR, get_if_list, get_if_addr, conf
from collections import defaultdict, Counter

# --- Configuration ---
TIMEOUT = 60  # Memory duration in seconds
PASSIVE_MODE = False 
SHOW_QUESTIONS = False 

# --- State Management ---
data = defaultdict(dict)
data_lock = threading.Lock()
SCROLL_OFFSET = 0
STATUS_MSG = ""
STATUS_TIME = 0

# IP Management
MY_IPS = set()
IP_ACTIVITY = Counter() # Track packet count per local IP to find the "Main" one

# Name Resolution
RESOLVED_NAMES = {} 
RESOLVED_LOCK = threading.Lock()
RESOLVER_QUEUE = Queue()

def get_mac_vendor(mac):
    if mac.startswith("00:04:96") or mac.startswith("00:e0:2b"): return "Extreme Networks"
    if mac.startswith("0e:"): return "Extreme Protocol (EDP)"
    if "cisco" in mac.lower(): return "Cisco"
    return "Unknown Vendor"

def clean_mdns_name(name_input):
    try:
        # Handle bytes or string input safely
        if isinstance(name_input, bytes):
            name = name_input.decode('utf-8', errors='ignore')
        else:
            name = str(name_input)

        if name.endswith('.'): name = name[:-1]
        
        # Extract the human part from "Name._service._tcp.local"
        if "._" in name: 
            name = name.split("._")[0]
            
        if name.endswith(".local"): name = name[:-6]
        
        # Cleanup quotes sometimes found in TXT/Strings
        name = name.strip('"')
        
        if len(name) < 2 or name.startswith("_"): return None
        return name
    except:
        return None

def detect_local_ips():
    """Enumerates all network interfaces to find local IPs."""
    global MY_IPS
    try:
        for iface in get_if_list():
            ip = get_if_addr(iface)
            if ip and ip != "0.0.0.0" and not ip.startswith("127."):
                MY_IPS.add(ip)
    except:
        pass

def get_main_ip():
    """Returns the most active local IP."""
    if not MY_IPS: return "Detecting..."
    if not IP_ACTIVITY: return list(MY_IPS)[0]
    return IP_ACTIVITY.most_common(1)[0][0]

def resolver_worker():
    while True:
        try:
            ip = RESOLVER_QUEUE.get(timeout=1)
            with RESOLVED_LOCK:
                if ip in RESOLVED_NAMES: continue
            try:
                hostname, _, _ = socket.gethostbyaddr(ip)
                with RESOLVED_LOCK: RESOLVED_NAMES[ip] = hostname
            except:
                with RESOLVED_LOCK: RESOLVED_NAMES[ip] = None 
        except Empty: continue
        except: pass

def update_entry(category, key, info):
    now = time.time()
    with data_lock:
        if key not in data[category]:
            data[category][key] = {'last_seen': now, 'first_seen': now, 'count': 0, 'info': info}
        entry = data[category][key]
        entry['last_seen'] = now
        entry['count'] += 1
        if entry['info'] == "Multicast DNS" and info != "Multicast DNS":
            entry['info'] = info

def parse_packet(pkt):
    global MY_IPS
    now = time.time()
    
    # Check IP Layer (IPv4 or IPv6)
    src_ip = None
    dst_ip = None
    
    if pkt.haslayer(IP):
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
    elif pkt.haslayer(IPv6):
        src_ip = pkt[IPv6].src
        dst_ip = pkt[IPv6].dst
        
    if src_ip:
        # Passive IP detection fallback
        if src_ip not in MY_IPS and "." in src_ip: 
            if src_ip.startswith("192.168.") or src_ip.startswith("10."):
                MY_IPS.add(src_ip)

        # Track Activity
        if src_ip in MY_IPS: IP_ACTIVITY[src_ip] += 1
        if dst_ip and dst_ip in MY_IPS: IP_ACTIVITY[dst_ip] += 1

    # 1. ARP
    if pkt.haslayer(ARP):
        ident = f"{pkt[ARP].psrc} ({pkt[ARP].hwsrc})"
        update_entry('ARP_Neighbors', ident, "ARP Announcement")
        if not PASSIVE_MODE: RESOLVER_QUEUE.put(pkt[ARP].psrc)

    # 2. mDNS
    if pkt.haslayer(UDP) and pkt.dport == 5353:
        sip = pkt[IP].src if pkt.haslayer(IP) else pkt[IPv6].src if pkt.haslayer(IPv6) else "Unknown"
        category, info = "mDNS (General)", "Multicast DNS"
        
        # Force DNS decoding if Scapy missed it
        dns_layer = pkt.getlayer(DNS)
        if not dns_layer:
            try:
                dns_layer = DNS(pkt[UDP].payload)
            except:
                dns_layer = None

        if dns_layer:
            try:
                if SHOW_QUESTIONS and dns_layer.qd:
                    q_rr = dns_layer.qd
                    while q_rr:
                        qname = clean_mdns_name(q_rr.qname)
                        if qname: update_entry('mDNS Questions (Missing?)', f"{qname} [?]", f"Sought by {sip}")
                        q_rr = q_rr.payload

                raw_dns = bytes(dns_layer)
                if b'_airplay' in raw_dns or b'_companion-link' in raw_dns: category, info = "mDNS (Apple Device)", "AirPlay/Handoff"
                elif b'_googlecast' in raw_dns: category = "mDNS (Google/Android)"
                elif b'_printer' in raw_dns or b'_ipp' in raw_dns: category = "mDNS (Printer)"

                # Scan ALL records (Answers + Additional)
                scan_lists = []
                if dns_layer.an: scan_lists.append(dns_layer.an)
                if dns_layer.ar: scan_lists.append(dns_layer.ar)
                
                for rr in scan_lists:
                    while rr:
                        extracted = None
                        
                        # PTR (12): Name is in RDATA
                        if rr.type == 12: 
                            extracted = clean_mdns_name(rr.rdata)
                        
                        # TXT (16): Name is in RRNAME (The record name itself)
                        elif rr.type == 16:
                            extracted = clean_mdns_name(rr.rrname)

                        # SRV (33): Name is in RRNAME (preferred) or TARGET (fallback)
                        elif rr.type == 33:
                            extracted = clean_mdns_name(rr.rrname)
                            if not extracted:
                                extracted = clean_mdns_name(rr.target)
                            
                        # A (1) / AAAA (28): Name is in RRNAME
                        elif rr.type in [1, 28]:
                            extracted = clean_mdns_name(rr.rrname)

                        # Update if valid name found
                        if extracted: 
                            with RESOLVED_LOCK: 
                                prev = RESOLVED_NAMES.get(sip)
                                # Overwrite if new name is longer/better (e.g. switch from "Host.local" to "My MacBook")
                                if not prev or (len(extracted) > len(prev) and "._" not in extracted):
                                    RESOLVED_NAMES[sip] = extracted
                        
                        rr = rr.payload
            except: pass
        update_entry(category, sip, info)

    # 3. Windows
    if pkt.haslayer(UDP):
        sip = pkt[IP].src if pkt.haslayer(IP) else pkt[IPv6].src if pkt.haslayer(IPv6) else "Unknown"
        if pkt.dport == 1900:
            update_entry('Windows/UPnP', sip, "SSDP Discovery")
            if not PASSIVE_MODE and "." in sip: RESOLVER_QUEUE.put(sip)
        elif pkt.dport == 5355:
            update_entry('Windows/LLMNR', sip, "LLMNR Proxy Search")
            if not PASSIVE_MODE and "." in sip: RESOLVER_QUEUE.put(sip)
        elif pkt.dport == 137:
            update_entry('Windows/NetBIOS', sip, "Name Query")
            if not PASSIVE_MODE and "." in sip: RESOLVER_QUEUE.put(sip)

    # 4. Steam
    if pkt.haslayer(UDP):
        try:
            if pkt.dport == 27036 or b'STEAM' in bytes(pkt[UDP].payload):
                sip = pkt[IP].src if pkt.haslayer(IP) else pkt[IPv6].src if pkt.haslayer(IPv6) else "Unknown"
                update_entry('Steam_Gamers', sip, "Steam LAN Discovery")
                if not PASSIVE_MODE and "." in sip: RESOLVER_QUEUE.put(sip)
        except: pass

    # 5. Infra
    if pkt.haslayer(Ether):
        mac_src = pkt[Ether].src
        if "Extreme" in get_mac_vendor(mac_src) or mac_src.startswith("0e:"):
            update_entry('Infrastructure', mac_src, get_mac_vendor(mac_src))
        if pkt.haslayer("Dot3") or pkt.type == 0x88cc:
             update_entry('Infrastructure', mac_src, "Switch/Router (LLDP)")

    # 6. Ping
    if pkt.haslayer(ICMP) and pkt.haslayer(IP):
        if pkt[IP].dst in MY_IPS and pkt[ICMP].type == 8:
            update_entry('Pinging_Me', pkt[IP].src, "ICMP Echo Request")
            if not PASSIVE_MODE: RESOLVER_QUEUE.put(pkt[IP].src)

    # 7. Active & Catch-all Connections (IPv4 & IPv6)
    if src_ip and dst_ip:
        # Don't double-log things already handled by parsers above
        if pkt.haslayer(UDP) and pkt.dport in [5353, 1900, 5355, 137, 27036]: return

        # Check for Broadcast/Multicast (Ignored Traffic)
        is_ignored = False
        if dst_ip.endswith(".255") or dst_ip.startswith("224.") or dst_ip.startswith("239."): is_ignored = True
        if dst_ip.startswith("ff02:"): is_ignored = True

        proto = "TCP" if pkt.haslayer(TCP) else "UDP" if pkt.haslayer(UDP) else "IP"
        port = ""
        p_info = ""
        
        if pkt.haslayer(TCP): 
            port = f":{pkt[TCP].dport}" if src_ip in MY_IPS else f":{pkt[TCP].sport}"
            p_info = f":{pkt[TCP].sport} > :{pkt[TCP].dport}"
        elif pkt.haslayer(UDP): 
            port = f":{pkt[UDP].dport}" if src_ip in MY_IPS else f":{pkt[UDP].sport}"
            p_info = f":{pkt[UDP].sport} > :{pkt[UDP].dport}"

        if is_ignored:
            # Log as "Ignored" so user can see it
            key = f"{src_ip} > {dst_ip}"
            update_entry('~ Ignored / Broadcast', key, f"{proto} {p_info}")
            return # Don't process as active connection

        is_my_src = src_ip in MY_IPS
        is_my_dst = dst_ip in MY_IPS
        
        if is_my_src or is_my_dst:
            # Active Connection (Me involved)
            other_ip = dst_ip if is_my_src else src_ip
            if not PASSIVE_MODE and "." in other_ip: RESOLVER_QUEUE.put(other_ip)
            update_entry('Active_Connections', f"{other_ip}{port}", f"{proto} Traffic")
        else:
            # Catch-all (Interception/Promiscuous)
            key = f"{src_ip} > {dst_ip}"
            update_entry('~ Unclassified / Other Traffic', key, f"{proto} {p_info}")

def get_display_name(key):
    if ">" in key: return key 
    ip_part = key.split(':')[0].split(' ')[0]
    with RESOLVED_LOCK:
        name = RESOLVED_NAMES.get(ip_part)
        if name:
            if key == ip_part: return f"{name} ({ip_part})"
            else: return f"{name} {key.replace(ip_part, '')}"
    return key

def truncate(text, width):
    if len(text) > width: return text[:width-3] + "..."
    return text

def save_to_file(text):
    try:
        log_dir = "/tmp/net_watch"
        if not os.path.exists(log_dir): os.makedirs(log_dir)
        ts = datetime.now().strftime("%Y%m%d-%H%M%S")
        filename = f"{log_dir}/{ts}.log"
        with open(filename, "w") as f: f.write(text)
        return filename
    except: return None

def generate_table_string():
    lines = []
    lines.append(f"{'DEVICE / IP':<45} | {'INFO':<20} | {'AGE':<6} | {'PPM':<6}")
    lines.append("-" * 85)
    with data_lock:
        now = time.time()
        for cat in sorted(data.keys()):
            lines.append(f"[{cat}]")
            for key, details in data[cat].items():
                name = get_display_name(key)
                age = int(now - details['last_seen'])
                duration = max(1, now - details['first_seen'])
                ppm = int((details['count'] / duration) * 60)
                lines.append(f"  {name:<45} | {details['info']:<20} | {age:<6} | {ppm:<6}")
            lines.append("")
    return "\n".join(lines)

def cleanup_and_display(stdscr):
    global SCROLL_OFFSET, STATUS_MSG, STATUS_TIME
    curses.curs_set(0)
    stdscr.nodelay(True)
    stdscr.keypad(True) 
    W_IP, W_INFO, W_AGE, W_PPM = 45, 20, 6, 6
    while True:
        max_y, max_x = stdscr.getmaxyx()
        now = time.time()
        with data_lock:
            for category in list(data.keys()):
                for key in list(data[category].keys()):
                    if now - data[category][key]['last_seen'] > TIMEOUT:
                        del data[category][key]
                if not data[category]: del data[category]

        buffer = []
        with data_lock:
            for cat in sorted(data.keys()):
                buffer.append({'type': 'cat', 'text': f"[{cat}]"})
                for key, details in data[cat].items():
                    age = int(now - details['last_seen'])
                    duration = max(1, now - details['first_seen'])
                    ppm = int((details['count'] / duration) * 60)
                    display_key = get_display_name(key)
                    t_key = truncate(display_key, W_IP)
                    t_info = truncate(details['info'], W_INFO)
                    line_str = f"  {t_key:<{W_IP}} | {t_info:<{W_INFO}} | {age:<{W_AGE}} | {ppm:<{W_PPM}}"
                    buffer.append({'type': 'row', 'text': line_str, 'is_new': age < 5})
                buffer.append({'type': 'spacer', 'text': ''})

        try:
            ch = stdscr.getch()
            if ch == curses.KEY_DOWN:
                if SCROLL_OFFSET < len(buffer) - (max_y - 4): SCROLL_OFFSET += 1
            elif ch == curses.KEY_UP:
                if SCROLL_OFFSET > 0: SCROLL_OFFSET -= 1
            elif ch == ord('p'):
                full_table = generate_table_string()
                saved_path = save_to_file(full_table)
                if saved_path: STATUS_MSG, STATUS_TIME = f"SAVED TO {saved_path}", now
                else: STATUS_MSG, STATUS_TIME = "SAVE FAILED", now
            elif ch == ord('q'): break
        except: pass

        stdscr.erase()
        mode_str = "Passive" if PASSIVE_MODE else "Active"
        q_str = " | Showing Queries" if SHOW_QUESTIONS else ""
        main_ip = get_main_ip()
        header = f"NET MONITOR ({mode_str}{q_str}) [Press 'p' to Save Log]"
        stdscr.addstr(0, 0, header[:max_x-1], curses.A_BOLD)
        if now - STATUS_TIME < 3 and STATUS_MSG:
            stdscr.addstr(0, max_x - len(STATUS_MSG) - 1, STATUS_MSG, curses.A_REVERSE | curses.A_BOLD)
        stdscr.addstr(1, 0, f"Main IP: {main_ip} (Total IPs: {len(MY_IPS)}) | Timeout: {TIMEOUT}s | Items: {len(buffer)}", curses.A_DIM)
        cols = f"  {'DEVICE / IP':<{W_IP}} | {'INFO':<{W_INFO}} | {'AGE':<{W_AGE}} | {'PPM':<{W_PPM}}"
        stdscr.addstr(2, 0, cols[:max_x-1], curses.A_REVERSE)

        visible_h = max_y - 3
        slice_end = min(len(buffer), SCROLL_OFFSET + visible_h)
        if SCROLL_OFFSET > max(0, len(buffer) - visible_h): SCROLL_OFFSET = max(0, len(buffer) - visible_h)
        current_row = 3
        for i in range(SCROLL_OFFSET, slice_end):
            item = buffer[i]
            text = item['text']
            if len(text) > max_x - 1: text = text[:max_x-1]
            attr = curses.A_NORMAL
            if item['type'] == 'cat': attr = curses.A_BOLD | curses.A_UNDERLINE
            elif item['type'] == 'row' and item['is_new']: attr = curses.A_BOLD
            elif item['type'] == 'row': attr = curses.A_DIM
            try: stdscr.addstr(current_row, 0, text, attr)
            except: pass
            current_row += 1
            
        if len(buffer) > visible_h:
            scroll_pct = SCROLL_OFFSET / (len(buffer) - visible_h)
            scroll_pos = 3 + int(scroll_pct * (visible_h - 1))
            try: stdscr.addch(scroll_pos, max_x - 1, '█', curses.A_REVERSE)
            except: pass
        stdscr.refresh()
        time.sleep(0.1)

def start_sniffing():
    sniff(prn=parse_packet, store=0, filter="")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-n', action='store_true', help="Passive mode (No DNS Lookups)")
    parser.add_argument('-Q', action='store_true', help="Show mDNS Questions")
    args = parser.parse_args()
    PASSIVE_MODE = args.n
    SHOW_QUESTIONS = args.Q
    detect_local_ips()
    t_sniff = threading.Thread(target=start_sniffing)
    t_sniff.daemon = True
    t_sniff.start()
    if not PASSIVE_MODE:
        t_res = threading.Thread(target=resolver_worker)
        t_res.daemon = True
        t_res.start()
    try: curses.wrapper(cleanup_and_display)
    except KeyboardInterrupt: print("Stopping...")
