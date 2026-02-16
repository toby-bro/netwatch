#!/usr/bin/env python3
import argparse
import curses
import logging
import os
import re
import socket
import subprocess
import tempfile
import threading
import time
from collections import Counter, defaultdict
from datetime import datetime
from queue import Empty, Queue
from typing import Any, DefaultDict, Dict, List, Optional, Set

from scapy.all import get_if_addr, get_if_list, sniff
from scapy.layers.dns import DNS
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether

# Configure logging
logging.basicConfig(
    filename=os.path.join(tempfile.gettempdir(), 'net_watch_debug.log'),
    level=logging.ERROR,
    format='%(asctime)s - %(levelname)s - %(message)s',
)

# --- Configuration ---
TIMEOUT = 60  # Memory duration in seconds


class NetWatch:
    def __init__(self, passive_mode: bool, show_questions: bool):
        self.passive_mode = passive_mode
        self.show_questions = show_questions

        # --- State Management ---
        self.data: DefaultDict[str, Dict[str, Dict[str, Any]]] = defaultdict(dict)
        self.data_lock = threading.Lock()
        self.scroll_offset = 0
        self.status_msg = ''
        self.status_time = 0.0

        # IP Management
        self.my_ips: Set[str] = set()
        self.ip_activity: Counter[str] = Counter()  # Track packet count to find "Main" IP

        # Name Resolution
        self.resolved_names: Dict[str, Optional[str]] = {}
        self.resolved_lock = threading.Lock()
        self.resolver_queue: Queue[str] = Queue()

        # Process Resolution
        self.port_to_process: Dict[str, str] = {}  # Maps "proto:port" -> "process_name"
        self.process_lock = threading.Lock()
        self.last_process_scan = 0.0

        # Display constants
        self.w_ip, self.w_info, self.w_age, self.w_ppm, self.w_proc = 38, 18, 6, 6, 18
        self.cols_width = self.w_ip + self.w_info + self.w_age + self.w_ppm + self.w_proc + 13  # pipe chars

    def get_mac_vendor(self, mac: str) -> str:
        if mac.startswith(('00:04:96', '00:e0:2b')):
            return 'Extreme Networks'
        if mac.startswith('0e:'):
            return 'Extreme Protocol (EDP)'
        if 'cisco' in mac.lower():
            return 'Cisco'
        return 'Unknown Vendor'

    def clean_mdns_name(self, name_input: Any) -> Optional[str]:
        try:
            # Handle bytes or string input safely
            if isinstance(name_input, bytes):
                name = name_input.decode('utf-8', errors='ignore')
            else:
                name = str(name_input)

            if name.endswith('.'):
                name = name[:-1]

            # Extract the human part from "Name._service._tcp.local"
            if '._' in name:
                name = name.split('._')[0]

            if name.endswith('.local'):
                name = name[:-6]

            # Cleanup quotes sometimes found in TXT/Strings
            name = name.strip('"')

            if len(name) < 2 or name.startswith('_'):
                return None
            return name
        except Exception:
            logging.error('Error cleaning mDNS name', exc_info=True)
            return None

    def detect_local_ips(self) -> None:
        """Enumerates all network interfaces to find local IPs."""
        try:
            for iface in get_if_list():
                ip = get_if_addr(iface)
                if ip and ip != '0.0.0.0' and not ip.startswith('127.'):  # noqa: S104
                    self.my_ips.add(ip)
        except Exception:
            logging.error('Error detecting local IPs', exc_info=True)

    def get_main_ip(self) -> str:
        """Returns the most active local IP."""
        if not self.my_ips:
            return 'Detecting...'
        if not self.ip_activity:
            return next(iter(self.my_ips))
        return self.ip_activity.most_common(1)[0][0]

    def scan_processes(self) -> None:
        """Scan local ports and map them to process names using ss command."""
        try:
            # Use ss to get all connections (listening + established) with process info
            # -a: all sockets (listening and established)
            # -n: numeric (don't resolve names)
            # -t: TCP sockets
            # -u: UDP sockets
            # -p: show process information
            result = subprocess.run(
                ['/usr/bin/ss', '-antup'],
                capture_output=True,
                text=True,
                timeout=2,
                check=False,
            )

            if result.returncode != 0:
                return

            port_map = {}
            for line in result.stdout.split('\n'):
                # Parse ss output: Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port Process
                # Example: tcp ESTAB 0 0 192.168.1.100:45678 1.2.3.4:443 users:(("firefox",...))
                parts = line.split()
                if len(parts) < 5:
                    continue

                proto = parts[0].lower()
                if proto not in ['tcp', 'udp']:
                    continue

                # Extract local and remote ports
                local_addr = parts[4]
                remote_addr = parts[5] if len(parts) > 5 else ''

                if ':' in local_addr:
                    local_port = local_addr.rsplit(':', 1)[1]
                    if local_port == '*':
                        continue

                    # Extract process name
                    process = 'Unknown'
                    if len(parts) > 6:
                        # Process info is in the last field, format: users:(("name",pid=123,fd=4))
                        proc_info = ' '.join(parts[6:])
                        match = re.search(r'"([^"]+)"', proc_info)
                        if match:
                            process = match.group(1)

                    # Map both local port and (for local connections) remote port
                    key = f'{proto}:{local_port}'
                    port_map[key] = process

                    # For localhost connections, also map the remote port
                    if ':' in remote_addr:
                        remote_port = remote_addr.rsplit(':', 1)[1]
                        remote_ip = remote_addr.rsplit(':', 1)[0]
                        # Check if remote is also localhost
                        if remote_ip.startswith(('127.', '::1', '192.168.', '10.', 'fe80::')):
                            remote_key = f'{proto}:{remote_port}'
                            if remote_key not in port_map:
                                port_map[remote_key] = process

            with self.process_lock:
                self.port_to_process = port_map
                self.last_process_scan = time.time()
        except Exception:
            logging.error('Error scanning processes', exc_info=True)

    def get_process_for_port(self, proto: str, port: str) -> str:
        """Get the process name for a given protocol and port."""
        # Rescan every 5 seconds
        if time.time() - self.last_process_scan > 5:
            self.scan_processes()

        with self.process_lock:
            key = f'{proto.lower()}:{port}'
            return self.port_to_process.get(key, '')

    def resolver_worker(self) -> None:
        while True:
            try:
                ip = self.resolver_queue.get(timeout=1)
                with self.resolved_lock:
                    if ip in self.resolved_names:
                        continue
                try:
                    hostname, _, _ = socket.gethostbyaddr(ip)
                    with self.resolved_lock:
                        self.resolved_names[ip] = hostname
                except Exception:
                    with self.resolved_lock:
                        self.resolved_names[ip] = None
            except Empty:
                continue
            except Exception:
                logging.error('Error in resolver worker', exc_info=True)

    def update_entry(self, category: str, key: str, info: str, process: str = '') -> None:
        now = time.time()
        with self.data_lock:
            if key not in self.data[category]:
                self.data[category][key] = {
                    'last_seen': now,
                    'first_seen': now,
                    'count': 0,
                    'info': info,
                    'process': process,
                }
            entry = self.data[category][key]
            entry['last_seen'] = now
            entry['count'] += 1
            if entry['info'] == 'Multicast DNS' and info != 'Multicast DNS':
                entry['info'] = info
            if process and not entry.get('process'):
                entry['process'] = process

    def _extract_name_from_rr(self, rr: Any) -> Optional[str]:
        extracted = None
        # PTR (12), TXT (16), SRV (33), A (1), AAAA (28)
        if rr.type == 12:
            extracted = self.clean_mdns_name(rr.rdata)
        elif rr.type == 16 or rr.type == 33 or rr.type in [1, 28]:
            extracted = self.clean_mdns_name(rr.rrname)
            if rr.type == 33 and not extracted:
                extracted = self.clean_mdns_name(rr.target)
        return extracted

    def _update_resolved_name(self, sip: str, extracted: str) -> None:
        with self.resolved_lock:
            prev = self.resolved_names.get(sip)
            if not prev or (len(extracted) > len(prev) and '._' not in extracted):
                self.resolved_names[sip] = extracted

    def _scan_dns_records(self, dns_layer: Any, sip: str) -> None:
        scan_lists = []
        if dns_layer.an:
            scan_lists.append(dns_layer.an)
        if dns_layer.ar:
            scan_lists.append(dns_layer.ar)

        for rr_start in scan_lists:
            rr = rr_start
            while rr:
                extracted = self._extract_name_from_rr(rr)
                if extracted:
                    self._update_resolved_name(sip, extracted)
                rr = rr.payload

    def _log_dns_questions(self, dns_layer: Any, sip: str) -> None:
        if self.show_questions and dns_layer.qd:
            q_rr = dns_layer.qd
            while q_rr:
                qname = self.clean_mdns_name(q_rr.qname)
                if qname:
                    self.update_entry('mDNS Questions (Missing?)', f'{qname} [?]', f'Sought by {sip}')
                q_rr = q_rr.payload

    def _get_dns_category_info(self, dns_layer: Any) -> tuple[str, str]:
        category, info = 'mDNS (General)', 'Multicast DNS'
        raw_dns = bytes(dns_layer)
        if b'_airplay' in raw_dns or b'_companion-link' in raw_dns:
            category, info = 'mDNS (Apple Device)', 'AirPlay/Handoff'
        elif b'_googlecast' in raw_dns:
            category = 'mDNS (Google/Android)'
        elif b'_printer' in raw_dns or b'_ipp' in raw_dns:
            category = 'mDNS (Printer)'
        return category, info

    def _process_dns_layer(self, pkt: Any, sip: str, initial_category: str, initial_info: str) -> None:
        dns_layer = pkt.getlayer(DNS)
        if not dns_layer:
            try:
                dns_layer = DNS(pkt[UDP].payload)
            except Exception:
                dns_layer = None

        category, info = initial_category, initial_info
        if dns_layer:
            try:
                self._log_dns_questions(dns_layer, sip)
                category, info = self._get_dns_category_info(dns_layer)
                self._scan_dns_records(dns_layer, sip)
            except Exception:
                logging.error('Error processing DNS layer', exc_info=True)
        self.update_entry(category, sip, info)

    def _handle_arp(self, pkt: Any) -> None:
        if pkt.haslayer(ARP):
            ident = f'{pkt[ARP].psrc} ({pkt[ARP].hwsrc})'
            self.update_entry('ARP_Neighbors', ident, 'ARP Announcement')
            if not self.passive_mode:
                self.resolver_queue.put(pkt[ARP].psrc)

    def _handle_mdns(self, pkt: Any, sip: str) -> None:
        if pkt.haslayer(UDP) and (pkt.dport == 5353 or pkt.sport == 5353):
            category, info = 'mDNS (General)', 'Multicast DNS'
            self._process_dns_layer(pkt, sip, category, info)

    def _handle_windows(self, pkt: Any, sip: str) -> None:
        if pkt.haslayer(UDP):
            if pkt.dport == 1900:
                self.update_entry('Windows/UPnP', sip, 'SSDP Discovery')
            elif pkt.dport == 5355:
                self.update_entry('Windows/LLMNR', sip, 'LLMNR Proxy Search')
            elif pkt.dport == 137:
                self.update_entry('Windows/NetBIOS', sip, 'Name Query')

            if not self.passive_mode and '.' in sip and pkt.dport in [1900, 5355, 137]:
                self.resolver_queue.put(sip)

    def _handle_steam(self, pkt: Any, sip: str) -> None:
        if pkt.haslayer(UDP):
            try:
                if pkt.dport == 27036 or b'STEAM' in bytes(pkt[UDP].payload):
                    self.update_entry('Steam_Gamers', sip, 'Steam LAN Discovery')
                    if not self.passive_mode and '.' in sip:
                        self.resolver_queue.put(sip)
            except Exception:
                logging.error('Error parsing Steam packet', exc_info=True)

    def _handle_infra(self, pkt: Any) -> None:
        if pkt.haslayer(Ether):
            mac_src = pkt[Ether].src
            vendor = self.get_mac_vendor(mac_src)
            if 'Extreme' in vendor or mac_src.startswith('0e:'):
                self.update_entry('Infrastructure', mac_src, vendor)
            if pkt.haslayer('Dot3') or pkt.type == 0x88CC:
                self.update_entry('Infrastructure', mac_src, 'Switch/Router (LLDP)')

    def _handle_ping(self, pkt: Any) -> None:
        if pkt.haslayer(ICMP) and pkt.haslayer(IP):
            if pkt[IP].dst in self.my_ips and pkt[ICMP].type == 8:
                self.update_entry('Pinging_Me', pkt[IP].src, 'ICMP Echo Request')
                if not self.passive_mode:
                    self.resolver_queue.put(pkt[IP].src)

    def _handle_active_connections(self, pkt: Any, src_ip: Optional[str], dst_ip: Optional[str]) -> None:
        if src_ip and dst_ip:
            # Skip packets handled by specific protocol handlers (except DNS)
            if pkt.haslayer(UDP) and pkt.dport in [5353, 1900, 5355, 137, 27036]:
                return
            if pkt.haslayer(UDP) and pkt.sport in [5353]:  # Also skip mDNS responses
                return

            is_ignored = False
            if dst_ip.endswith('.255') or dst_ip.startswith(('224.', '239.', 'ff02:')):
                is_ignored = True

            proto = 'tcp' if pkt.haslayer(TCP) else 'udp' if pkt.haslayer(UDP) else 'ip'
            port = ''
            local_port = ''
            p_info = ''
            process = ''
            is_dns = False

            if pkt.haslayer(TCP):
                if src_ip in self.my_ips:
                    port = f':{pkt[TCP].dport}'
                    local_port = str(pkt[TCP].sport)
                else:
                    port = f':{pkt[TCP].sport}'
                    local_port = str(pkt[TCP].dport)
                p_info = f':{pkt[TCP].sport} > :{pkt[TCP].dport}'
                process = self.get_process_for_port('tcp', local_port)
            elif pkt.haslayer(UDP):
                if src_ip in self.my_ips:
                    port = f':{pkt[UDP].dport}'
                    local_port = str(pkt[UDP].sport)
                else:
                    port = f':{pkt[UDP].sport}'
                    local_port = str(pkt[UDP].dport)
                p_info = f':{pkt[UDP].sport} > :{pkt[UDP].dport}'
                process = self.get_process_for_port('udp', local_port)

                # Check if this is DNS traffic (port 53)
                if pkt[UDP].dport == 53 or pkt[UDP].sport == 53:
                    is_dns = True

            if is_ignored:
                key = f'{src_ip} > {dst_ip}'
                self.update_entry('~ Ignored / Broadcast', key, f'{proto.upper()} {p_info}', process)
                return

            is_my_src = src_ip in self.my_ips
            is_my_dst = dst_ip in self.my_ips

            if is_my_src or is_my_dst:
                other_ip = dst_ip if is_my_src else src_ip

                # For localhost-to-localhost, look up both source and destination processes
                if is_my_src and is_my_dst:
                    # Inter-process communication - get both processes
                    src_process = ''
                    dst_process = ''
                    sport = 0
                    dport = 0
                    is_local_dns = False

                    if pkt.haslayer(TCP):
                        src_process = self.get_process_for_port('tcp', str(pkt[TCP].sport))
                        dst_process = self.get_process_for_port('tcp', str(pkt[TCP].dport))
                        sport = pkt[TCP].sport
                        dport = pkt[TCP].dport
                        if sport == 53 or dport == 53:
                            is_local_dns = True
                    elif pkt.haslayer(UDP):
                        src_process = self.get_process_for_port('udp', str(pkt[UDP].sport))
                        dst_process = self.get_process_for_port('udp', str(pkt[UDP].dport))
                        sport = pkt[UDP].sport
                        dport = pkt[UDP].dport
                        if sport == 53 or dport == 53:
                            is_local_dns = True

                    # Create descriptive key and process info
                    key = f':{sport} > :{dport}'
                    src_name = src_process if src_process else 'unknown'
                    dst_name = dst_process if dst_process else 'unknown'
                    process_flow = f'{src_name} → {dst_name}'

                    # Categorize based on whether it's DNS or other IPC
                    if is_local_dns:
                        category = 'DNS Queries (Local)'
                        info = 'Local DNS'
                    else:
                        category = 'Local Inter-Process'
                        info = f'{proto.upper()} IPC'

                    # Show inter-process local traffic with both processes
                    self.update_entry(category, key, info, process_flow)
                    return

                if not self.passive_mode and '.' in other_ip and not is_dns:
                    # Don't queue DNS servers for resolution (infinite loop)
                    self.resolver_queue.put(other_ip)

                # Determine category
                category = 'Active_Connections'

                # DNS queries get their own category
                if is_dns:
                    category = 'DNS Queries'
                    info = 'DNS Lookup'
                else:
                    # Check if it's a local network device
                    with self.resolved_lock:
                        resolved_name = self.resolved_names.get(other_ip)

                    if self.is_local_network_device(other_ip, resolved_name):
                        category = 'Local Network Devices'
                    info = f'{proto.upper()} Traffic'

                self.update_entry(category, f'{other_ip}{port}', info, process)
            else:
                key = f'{src_ip} > {dst_ip}'
                self.update_entry('~ Unclassified / Other Traffic', key, f'{proto.upper()} {p_info}', process)

    def parse_packet(self, pkt: Any) -> None:
        src_ip = None
        dst_ip = None

        if pkt.haslayer(IP):
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
        elif pkt.haslayer(IPv6):
            src_ip = pkt[IPv6].src
            dst_ip = pkt[IPv6].dst

        # Add local network IPs to my_ips set
        if src_ip and src_ip not in self.my_ips and '.' in src_ip:
            if src_ip.startswith(
                (
                    '192.168.',
                    '10.',
                    '172.16.',
                    '172.17.',
                    '172.18.',
                    '172.19.',
                    '172.20.',
                    '172.21.',
                    '172.22.',
                    '172.23.',
                    '172.24.',
                    '172.25.',
                    '172.26.',
                    '172.27.',
                    '172.28.',
                    '172.29.',
                    '172.30.',
                    '172.31.',
                ),
            ):
                self.my_ips.add(src_ip)

        if dst_ip and dst_ip not in self.my_ips and '.' in dst_ip:
            if dst_ip.startswith(
                (
                    '192.168.',
                    '10.',
                    '172.16.',
                    '172.17.',
                    '172.18.',
                    '172.19.',
                    '172.20.',
                    '172.21.',
                    '172.22.',
                    '172.23.',
                    '172.24.',
                    '172.25.',
                    '172.26.',
                    '172.27.',
                    '172.28.',
                    '172.29.',
                    '172.30.',
                    '172.31.',
                ),
            ):
                self.my_ips.add(dst_ip)

        if src_ip:
            if src_ip in self.my_ips:
                self.ip_activity[src_ip] += 1
            if dst_ip and dst_ip in self.my_ips:
                self.ip_activity[dst_ip] += 1

        sip = src_ip if src_ip else 'Unknown'

        self._handle_arp(pkt)
        self._handle_mdns(pkt, sip)
        self._handle_windows(pkt, sip)
        self._handle_steam(pkt, sip)
        self._handle_infra(pkt)
        self._handle_ping(pkt)
        self._handle_active_connections(pkt, src_ip, dst_ip)

    def is_local_network_device(self, ip: str, resolved_name: Optional[str]) -> bool:
        """Check if IP/name represents a local network mDNS device."""
        # Check if IP is local network
        if not ip.startswith(('192.168.', '10.', '172.')):
            return False

        # Check if name has mDNS-like patterns
        if resolved_name:
            mdns_patterns = ['_on_', ' on ', '_mqtt_', '.local', 'mss_', '_printer_', '_iot_']
            name_lower = resolved_name.lower()
            if any(pattern in name_lower for pattern in mdns_patterns):
                return True

        return False

    def get_display_name(self, key: str) -> str:
        if '>' in key:
            return key
        ip_part = key.split(':', maxsplit=1)[0].split(' ')[0]
        with self.resolved_lock:
            name = self.resolved_names.get(ip_part)
            if name:
                if key == ip_part:
                    return f'{name} ({ip_part})'
                return f"{name} {key.replace(ip_part, '')}"
        return key

    def truncate(self, text: str, width: int) -> str:
        if len(text) > width:
            return text[: width - 3] + '...'
        return text

    def save_to_file(self, text: str) -> Optional[str]:
        try:
            log_dir = os.path.join(tempfile.gettempdir(), 'net_watch')
            if not os.path.exists(log_dir):
                os.makedirs(log_dir)

            ts = datetime.now().strftime('%Y%m%d-%H%M%S')
            filename = os.path.join(log_dir, f'{ts}.log')

            with open(filename, 'w') as f:
                f.write(text)
            return filename
        except Exception:
            logging.error('Error saving to file', exc_info=True)
            return None

    def generate_table_string(self) -> str:
        lines = []
        lines.append(f"{'DEVICE / IP':<38} | {'INFO':<18} | {'AGE':<6} | {'PPM':<6} | {'PROCESS':<18}")
        lines.append('-' * 100)
        with self.data_lock:
            now = time.time()
            for cat in sorted(self.data.keys()):
                lines.append(f'[{cat}]')
                for key, details in self.data[cat].items():
                    name = self.get_display_name(key)
                    age = int(now - details['last_seen'])
                    duration = max(1, now - details['first_seen'])
                    ppm = int((details['count'] / duration) * 60)
                    process = details.get('process', '')
                    lines.append(
                        f"  {name:<38} | {details['info']:<18} | {age:<6} | {ppm:<6} | {process:<18}",
                    )
                lines.append('')
        return '\n'.join(lines)

    def _prepare_buffer(self) -> List[Dict[str, Any]]:
        buffer = []
        now = time.time()
        with self.data_lock:
            for cat in sorted(self.data.keys()):
                buffer.append({'type': 'cat', 'text': f'[{cat}]', 'is_new': False})
                for key, details in self.data[cat].items():
                    age = int(now - details['last_seen'])
                    duration = max(1, now - details['first_seen'])
                    ppm = int((details['count'] / duration) * 60)
                    display_key = self.get_display_name(key)
                    process = details.get('process', '')
                    t_key = self.truncate(display_key, self.w_ip)
                    t_info = self.truncate(details['info'], self.w_info)
                    t_proc = self.truncate(process, self.w_proc)
                    line_str = (
                        f'  {t_key:<{self.w_ip}} | {t_info:<{self.w_info}} | '
                        f'{age:<{self.w_age}} | {ppm:<{self.w_ppm}} | {t_proc:<{self.w_proc}}'
                    )
                    buffer.append({'type': 'row', 'text': line_str, 'is_new': age < 5})
                buffer.append({'type': 'spacer', 'text': '', 'is_new': False})
        return buffer

    def _draw_header(self, stdscr: Any, buffer_len: int, now: float, max_x: int) -> None:
        try:
            mode_str = 'Passive' if self.passive_mode else 'Active'
            q_str = ' | Showing Queries' if self.show_questions else ''
            main_ip = self.get_main_ip()
            header = f"NET MONITOR ({mode_str}{q_str}) [Press 'p' to Save Log]"

            stdscr.addstr(0, 0, header[: max_x - 1], curses.A_BOLD)
            if now - self.status_time < 3 and self.status_msg:
                stdscr.addstr(0, max_x - len(self.status_msg) - 1, self.status_msg, curses.A_REVERSE | curses.A_BOLD)

            stdscr.addstr(
                1,
                0,
                f'Main IP: {main_ip} (Total IPs: {len(self.my_ips)}) | Timeout: {TIMEOUT}s | Items: {buffer_len}',
                curses.A_DIM,
            )
            cols = (
                f"  {'DEVICE / IP':<{self.w_ip}} | {'INFO':<{self.w_info}} | "
                f"{'AGE':<{self.w_age}} | {'PPM':<{self.w_ppm}} | {'PROCESS':<{self.w_proc}}"
            )
            stdscr.addstr(2, 0, cols[: max_x - 1], curses.A_REVERSE)
        except Exception:  # noqa: S110
            pass  # Small terminal

    def _get_item_attr(self, item: Dict[str, Any]) -> int:
        if item['type'] == 'cat':
            return curses.A_BOLD | curses.A_UNDERLINE
        if item['type'] == 'row' and item.get('is_new'):
            return curses.A_BOLD
        if item['type'] == 'row':
            return curses.A_DIM
        return curses.A_NORMAL

    def _draw_rows(self, stdscr: Any, buffer: List[Dict[str, Any]], max_y: int, max_x: int) -> None:
        visible_h = max_y - 3
        if self.scroll_offset > max(0, len(buffer) - visible_h):
            self.scroll_offset = max(0, len(buffer) - visible_h)

        slice_end = min(len(buffer), self.scroll_offset + visible_h)

        for i in range(self.scroll_offset, slice_end):
            row_idx = i - self.scroll_offset + 3
            if row_idx >= max_y:
                break

            item = buffer[i]
            text = item['text']
            if len(text) > max_x - 1:
                text = text[: max_x - 1]
            attr = self._get_item_attr(item)
            try:
                stdscr.addstr(row_idx, 0, text, attr)
            except Exception:  # noqa: S110
                pass

        if len(buffer) > visible_h:
            scroll_pct = self.scroll_offset / (len(buffer) - visible_h)
            scroll_pos = 3 + int(scroll_pct * (visible_h - 1))
            if scroll_pos < max_y:
                try:
                    stdscr.addch(scroll_pos, max_x - 1, '█', curses.A_REVERSE)
                except Exception:  # noqa: S110
                    pass

        stdscr.refresh()

    def _handle_input(self, stdscr: Any, buffer: List[Dict[str, Any]], max_y: int, now: float) -> bool:
        try:
            ch = stdscr.getch()
            if ch == curses.KEY_DOWN:
                if self.scroll_offset < len(buffer) - (max_y - 4):
                    self.scroll_offset += 1
            elif ch == curses.KEY_UP:
                if self.scroll_offset > 0:
                    self.scroll_offset -= 1
            elif ch == ord('p'):
                full_table = self.generate_table_string()
                saved_path = self.save_to_file(full_table)
                if saved_path:
                    self.status_msg, self.status_time = f'SAVED TO {saved_path}', now
                else:
                    self.status_msg, self.status_time = 'SAVE FAILED', now
            elif ch == ord('q'):
                return False
        except Exception:  # noqa: S110
            pass
        return True

    def cleanup_and_display(self, stdscr: Any) -> None:
        curses.curs_set(0)
        stdscr.nodelay(True)
        stdscr.keypad(True)

        while True:
            max_y, max_x = stdscr.getmaxyx()
            now = time.time()
            with self.data_lock:
                to_delete = []
                # Clean up old entries only
                for category in list(self.data.keys()):
                    for key in list(self.data[category].keys()):
                        if now - self.data[category][key]['last_seen'] > TIMEOUT:
                            del self.data[category][key]
                    if not self.data[category]:
                        to_delete.append(category)
                for cat in to_delete:
                    del self.data[cat]

            buffer = self._prepare_buffer()

            if not self._handle_input(stdscr, buffer, max_y, now):
                break

            stdscr.erase()
            self._draw_header(stdscr, len(buffer), now, max_x)
            self._draw_rows(stdscr, buffer, max_y, max_x)

            time.sleep(0.1)

    def run(self) -> None:
        self.detect_local_ips()
        t_sniff = threading.Thread(target=lambda: sniff(prn=self.parse_packet, store=0, filter=''))
        t_sniff.daemon = True
        t_sniff.start()

        if not self.passive_mode:
            t_res = threading.Thread(target=self.resolver_worker)
            t_res.daemon = True
            t_res.start()

        try:
            curses.wrapper(self.cleanup_and_display)
        except KeyboardInterrupt:
            print('Stopping...')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-n', action='store_true', help='Passive mode (No DNS Lookups)')
    parser.add_argument('-Q', action='store_true', help='Show mDNS Questions')
    args = parser.parse_args()

    app = NetWatch(passive_mode=args.n, show_questions=args.Q)
    app.run()
