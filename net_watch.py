#!/usr/bin/env python3
import argparse
import contextlib
import curses
import functools
import logging
import os
import re
import socket
import subprocess
import tempfile
import threading
import time
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from queue import Empty, Queue
from typing import Any

from scapy.all import get_if_addr, get_if_list, sniff
from scapy.layers.dns import DNS
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Packet

# Configure logging
logging.basicConfig(
    filename=os.path.join(tempfile.gettempdir(), 'net_watch_debug.log'),
    level=logging.ERROR,
    format='%(asctime)s - %(levelname)s - %(message)s',
)

# --- Configuration ---
TIMEOUT = 60  # Memory duration in seconds

# RFC1918 private network regex patterns
PRIVATE_IP_PATTERN = re.compile(
    r'^(?:10\.|192\.168\.|172\.(?:1[6-9]|2[0-9]|3[01])\.)',
)


@functools.lru_cache(maxsize=512)
def is_private_ip_cached(ip: str) -> bool:
    """Cached check if IP is in RFC1918 private address space."""
    return PRIVATE_IP_PATTERN.match(ip) is not None


@functools.lru_cache(maxsize=256)
def clean_mdns_name_cached(name: str) -> str | None:
    """Cached clean mDNS name. Takes string only for caching."""
    try:
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
    except Exception:
        logging.error('Error cleaning mDNS name', exc_info=True)
        return None
    else:
        return name


@functools.lru_cache(maxsize=1024)
def resolve_hostname_cached(ip: str) -> str | None:
    """Cached DNS resolution - module level for lock-free async access."""
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
    except (socket.herror, socket.gaierror, OSError):
        return None
    else:
        return hostname


@functools.lru_cache(maxsize=128)
def get_mac_vendor(mac: str) -> str:
    """Get MAC vendor information."""
    if mac.startswith(('00:04:96', '00:e0:2b')):
        return 'Extreme Networks'
    if mac.startswith('0e:'):
        return 'Extreme Protocol (EDP)'
    if 'cisco' in mac.lower():
        return 'Cisco'
    return 'Unknown Vendor'


class PerformanceMonitor:
    """Track packet processing performance."""

    def __init__(self) -> None:
        self.packet_count = 0
        self.start_time = time.time()
        self.process_times: list[float] = []

    def record_packet(self, process_time: float) -> None:
        """Record a packet processing time."""
        self.packet_count += 1
        self.process_times.append(process_time)
        # Keep only last 1000 samples
        if len(self.process_times) > 1000:
            self.process_times.pop(0)

    def get_stats(self) -> dict[str, float]:
        """Get performance statistics."""
        if not self.process_times:
            return {'pps': 0.0, 'avg_ms': 0.0, 'max_ms': 0.0}

        elapsed = time.time() - self.start_time
        pps = self.packet_count / elapsed if elapsed > 0 else 0.0
        avg_ms = sum(self.process_times) / len(self.process_times) * 1000
        max_ms = max(self.process_times) * 1000

        return {'pps': pps, 'avg_ms': avg_ms, 'max_ms': max_ms}


class NetWatch:
    def __init__(self, passive_mode: bool, show_questions: bool):
        self.passive_mode = passive_mode
        self.show_questions = show_questions

        # --- State Management (Single Writer Pattern) ---
        self.data: defaultdict[str, dict[str, dict[str, Any]]] = defaultdict(dict)
        # NO LOCK - only single writer thread modifies data
        # UI thread only reads (safe without lock)

        self.scroll_offset = 0
        self.status_msg = ''
        self.status_time = 0.0

        # IP Management
        self.my_ips: set[str] = set()
        self.ip_activity: Counter[str] = Counter()  # Track packet count to find "Main" IP

        # Name Resolution (now using cached function)
        self.resolved_names: dict[str, str | None] = {}
        self.dns_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix='dns')

        # Process Resolution
        self.port_to_process: dict[str, str] = {}  # Maps "proto:port" -> "process_name"
        self.last_process_scan = 0.0
        # Note: No process_lock - dict reads/writes are atomic in CPython

        # Connection-based process cache for efficiency
        # (src_ip, src_port, dst_ip, dst_port, proto) -> process
        self.connection_cache: dict[tuple[str, str, str, str, str], str] = {}
        # Note: No lock needed - dict ops are atomic in CPython

        # Single writer command queue - all mutations go here
        self.command_queue: Queue[dict[str, Any]] = Queue()

        # Display constants
        self.w_ip, self.w_info, self.w_age, self.w_ppm, self.w_proc = 38, 18, 6, 6, 18
        self.cols_width = self.w_ip + self.w_info + self.w_age + self.w_ppm + self.w_proc + 13  # pipe chars

        # Performance monitoring
        self.perf_monitor = PerformanceMonitor()

        # Layer cache for packet processing (no lock needed - single threaded access in parse_packet)
        self._layer_cache: dict[int, dict[str, Any]] = {}  # packet id -> layer dict

    @staticmethod
    def is_private_ip(ip: str) -> bool:
        """Check if IP is in RFC1918 private address space."""
        return is_private_ip_cached(ip)

    def clean_mdns_name(self, name_input: bytes | str) -> str | None:
        """Wrapper to handle bytes/any input before caching."""
        try:
            # Handle bytes or string input safely
            name = name_input.decode('utf-8', errors='ignore') if isinstance(name_input, bytes) else str(name_input)
            return clean_mdns_name_cached(name)
        except Exception:
            logging.error('Error cleaning mDNS name wrapper', exc_info=True)
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

    def _parse_ss_line(self, line: str, port_map: dict[str, str]) -> None:
        """Parse a single ss output line and update port_map."""
        parts = line.split()
        if len(parts) < 5:
            return

        proto = parts[0].lower()
        if proto not in ['tcp', 'udp']:
            return

        local_addr = parts[4]
        if ':' not in local_addr:
            return

        local_port = local_addr.rsplit(':', 1)[1]
        if local_port == '*':
            return

        # Extract process name from proc info
        process = 'Unknown'
        if len(parts) > 6:
            proc_info = ' '.join(parts[6:])
            if match := re.search(r'"([^"]+)"', proc_info):
                process = match.group(1)

        # Map local port
        port_map[f'{proto}:{local_port}'] = process

        # For local connections, also map remote port
        if len(parts) > 5 and ':' in parts[5]:
            remote_addr = parts[5]
            remote_port = remote_addr.rsplit(':', 1)[1]
            remote_ip = remote_addr.rsplit(':', 1)[0]
            if remote_ip.startswith(('127.', '::1')) or self.is_private_ip(remote_ip):
                remote_key = f'{proto}:{remote_port}'
                if remote_key not in port_map:
                    port_map[remote_key] = process

    def scan_processes(self) -> None:
        """Scan local ports and map them to process names using ss command."""
        try:
            result = subprocess.run(
                ['/usr/bin/ss', '-antup'],
                capture_output=True,
                text=True,
                timeout=2,
                check=False,
            )

            if result.returncode != 0:
                return

            port_map: dict[str, str] = {}
            for line in result.stdout.split('\n'):
                self._parse_ss_line(line, port_map)

            # Atomic dict replacement - no lock needed
            self.port_to_process = port_map
            self.last_process_scan = time.time()
        except Exception:
            logging.error('Error scanning processes', exc_info=True)

    def get_process_for_port(self, proto: str, port: str) -> str:
        """Get the process name for a given protocol and port."""
        # Rescan every 10 seconds (increased from 5 for less overhead)
        if time.time() - self.last_process_scan > 10:
            self.scan_processes()

        # Lock-free read - dict access is atomic in CPython
        key = f'{proto.lower()}:{port}'
        return self.port_to_process.get(key, '')

    def get_process_for_connection(
        self,
        src_ip: str,
        src_port: str,
        dst_ip: str,
        dst_port: str,
        proto: str,
    ) -> str:
        """Get process for a connection tuple with caching."""
        cache_key = (src_ip, src_port, dst_ip, dst_port, proto)

        # Check cache first - lock-free read for existing keys
        cached = self.connection_cache.get(cache_key)
        if cached is not None:
            return cached

        # Not in cache, determine which port to lookup
        is_my_src = src_ip in self.my_ips
        local_port = src_port if is_my_src else dst_port
        process = self.get_process_for_port(proto, local_port)

        # Lock-free write - dict assignment is atomic in CPython
        self.connection_cache[cache_key] = process

        # Periodically clean cache (only on every 100th addition)
        cache_size = len(self.connection_cache)
        if cache_size > 1000 and cache_size % 100 == 0:
            # Create new dict with recent entries - atomic replacement
            items = list(self.connection_cache.items())
            self.connection_cache = dict(items[-800:])  # Keep most recent 800

        return process

    def async_resolve_hostname(self, ip: str) -> None:
        """Asynchronously resolve hostname using cached function."""
        if ip in self.resolved_names:
            return

        # Submit to thread pool for async resolution
        def resolve_and_store() -> None:
            result = resolve_hostname_cached(ip)
            self.resolved_names[ip] = result

        self.dns_executor.submit(resolve_and_store)

    def update_entry(
        self,
        category: str,
        key: str,
        info: str,
        process: str = '',
    ) -> None:
        """Queue an update for single writer thread."""
        self.command_queue.put(
            {
                'cmd': 'update',
                'category': category,
                'key': key,
                'info': info,
                'process': process,
                'timestamp': time.time(),
            },
        )

    def single_writer_worker(self) -> None:
        """Single writer thread - ONLY thread that modifies self.data.

        All mutations go through command queue. This eliminates lock contention
        because UI only reads (safe without locks in single-writer pattern).
        """
        batch = []

        while True:
            try:
                # Collect commands in batches for efficiency
                try:
                    cmd = self.command_queue.get(timeout=0.05)
                    batch.append(cmd)
                except Empty:
                    if batch:
                        self._process_command_batch(batch)
                        batch = []
                    continue

                # Drain queue
                while len(batch) < 100:  # Max batch size
                    try:
                        batch.append(self.command_queue.get_nowait())
                    except Empty:
                        break

                # Process batch
                if batch:
                    self._process_command_batch(batch)
                    batch = []

            except Exception:
                logging.error('Error in single writer', exc_info=True)
                time.sleep(0.01)

    def _process_command_batch(self, commands: list[dict[str, Any]]) -> None:
        """Process batch of commands - NO LOCKS NEEDED (single writer)."""
        # Merge duplicate updates and collect cleanups
        updates: dict[tuple[str, str], dict[str, Any]] = {}
        cleanups = []

        for cmd in commands:
            if cmd['cmd'] == 'update':
                self._merge_update(updates, cmd)
            elif cmd['cmd'] == 'cleanup':
                cleanups.append(cmd)

        # Apply updates
        for cat_key, upd in updates.items():
            self._apply_single_update(cat_key, upd)

        # Process cleanups
        for cleanup in cleanups:
            self._do_cleanup(cleanup['now'])

    def _merge_update(self, updates: dict[tuple[str, str], dict[str, Any]], cmd: dict[str, Any]) -> None:
        """Merge update command into updates dict."""
        cat_key = (cmd['category'], cmd['key'])
        if cat_key not in updates:
            updates[cat_key] = {
                'category': cmd['category'],
                'key': cmd['key'],
                'info': cmd['info'],
                'process': cmd['process'],
                'timestamp': cmd['timestamp'],
                'count': 1,
            }
        else:
            existing = updates[cat_key]
            existing['timestamp'] = max(existing['timestamp'], cmd['timestamp'])
            existing['count'] += 1
            if existing['info'] == 'Multicast DNS' and cmd['info'] != 'Multicast DNS':
                existing['info'] = cmd['info']
            if cmd['process'] and not existing['process']:
                existing['process'] = cmd['process']

    def _apply_single_update(self, cat_key: tuple[str, str], upd: dict[str, Any]) -> None:
        """Apply a single merged update."""
        category, key = cat_key
        now = upd['timestamp']
        inc_count = upd['count']

        entry = self.data[category].get(key)
        if entry is None:
            self.data[category][key] = {
                'last_seen': now,
                'first_seen': now,
                'count': inc_count,
                'info': upd['info'],
                'process': upd['process'],
            }
        else:
            entry['last_seen'] = now
            entry['count'] += inc_count
            if entry['info'] == 'Multicast DNS' and upd['info'] != 'Multicast DNS':
                entry['info'] = upd['info']
            if upd['process'] and not entry.get('process'):
                entry['process'] = upd['process']

    def _do_cleanup(self, now: float) -> None:
        """Cleanup expired entries - called by single writer only."""
        expired = []
        for category in list(self.data.keys()):
            for key, details in list(self.data[category].items()):
                if now - details['last_seen'] > TIMEOUT:
                    expired.append((category, key))

        for category, key in expired:
            if key in self.data.get(category, {}):
                del self.data[category][key]

        # Remove empty categories
        for category in list(self.data.keys()):
            if not self.data[category]:
                del self.data[category]

    def _extract_name_from_rr(self, rr: Packet) -> str | None:
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
        # Lock-free read then conditional write
        prev = self.resolved_names.get(sip)
        if not prev or (len(extracted) > len(prev) and '._' not in extracted):
            # Lock-free write - dict assignment is atomic
            self.resolved_names[sip] = extracted

    def _scan_dns_records(self, dns_layer: DNS, sip: str) -> None:
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

    def _log_dns_questions(self, dns_layer: DNS, sip: str) -> None:
        if self.show_questions and dns_layer.qd:
            q_rr = dns_layer.qd
            while q_rr:
                qname = self.clean_mdns_name(q_rr.qname)
                if qname:
                    self.update_entry(
                        'mDNS Questions (Missing?)',
                        f'{qname} [?]',
                        f'Sought by {sip}',
                    )
                q_rr = q_rr.payload

    def _get_dns_category_info(self, dns_layer: DNS) -> tuple[str, str]:
        category, info = 'mDNS (General)', 'Multicast DNS'
        raw_dns = bytes(dns_layer)
        if b'_airplay' in raw_dns or b'_companion-link' in raw_dns:
            category, info = 'mDNS (Apple Device)', 'AirPlay/Handoff'
        elif b'_googlecast' in raw_dns:
            category = 'mDNS (Google/Android)'
        elif b'_printer' in raw_dns or b'_ipp' in raw_dns:
            category = 'mDNS (Printer)'
        return category, info

    def _process_dns_layer(
        self,
        pkt: Packet,
        sip: str,
        initial_category: str,
        initial_info: str,
    ) -> None:
        dns_layer_raw = pkt.getlayer(DNS)
        if not dns_layer_raw:
            try:
                dns_layer_raw = DNS(pkt[UDP].payload)
            except (ValueError, IndexError, AttributeError):
                dns_layer_raw = None

        category, info = initial_category, initial_info
        if dns_layer_raw:
            # Type-cast for mypy - we know it's DNS if not None
            dns_layer: DNS = dns_layer_raw  # type: ignore[assignment]
            try:
                self._log_dns_questions(dns_layer, sip)
                category, info = self._get_dns_category_info(dns_layer)
                self._scan_dns_records(dns_layer, sip)
            except Exception:
                logging.error('Error processing DNS layer', exc_info=True)
        self.update_entry(category, sip, info)

    def _handle_arp(self, pkt: Packet) -> None:
        if pkt.haslayer(ARP):
            ident = f'{pkt[ARP].psrc} ({pkt[ARP].hwsrc})'
            self.update_entry('ARP_Neighbors', ident, 'ARP Announcement')
            if not self.passive_mode:
                self.async_resolve_hostname(pkt[ARP].psrc)

    def _handle_mdns(self, pkt: Packet, sip: str) -> None:
        if pkt.haslayer(UDP) and (pkt.dport == 5353 or pkt.sport == 5353):
            category, info = 'mDNS (General)', 'Multicast DNS'
            self._process_dns_layer(pkt, sip, category, info)

    def _handle_windows(self, pkt: Packet, sip: str) -> None:
        if pkt.haslayer(UDP):
            if pkt.dport == 1900:
                self.update_entry('Windows/UPnP', sip, 'SSDP Discovery')
            elif pkt.dport == 5355:
                self.update_entry('Windows/LLMNR', sip, 'LLMNR Proxy Search')
            elif pkt.dport == 137:
                self.update_entry('Windows/NetBIOS', sip, 'Name Query')

            if not self.passive_mode and '.' in sip and pkt.dport in [1900, 5355, 137]:
                self.async_resolve_hostname(sip)

    def _handle_steam(self, pkt: Packet, sip: str) -> None:
        if pkt.haslayer(UDP):
            try:
                if pkt.dport == 27036 or b'STEAM' in bytes(pkt[UDP].payload):
                    self.update_entry('Steam_Gamers', sip, 'Steam LAN Discovery')
                    if not self.passive_mode and '.' in sip:
                        self.async_resolve_hostname(sip)
            except Exception:
                logging.error('Error parsing Steam packet', exc_info=True)

    def _handle_infra(self, pkt: Packet) -> None:
        if pkt.haslayer(Ether):
            mac_src = pkt[Ether].src
            vendor = get_mac_vendor(mac_src)
            if 'Extreme' in vendor or mac_src.startswith('0e:'):
                self.update_entry('Infrastructure', mac_src, vendor)
            if pkt.haslayer('Dot3') or pkt.type == 0x88CC:
                self.update_entry('Infrastructure', mac_src, 'Switch/Router (LLDP)')

    def _handle_ping(self, pkt: Packet) -> None:
        if pkt.haslayer(ICMP) and pkt.haslayer(IP) and pkt[IP].dst in self.my_ips and pkt[ICMP].type == 8:
            self.update_entry('Pinging_Me', pkt[IP].src, 'ICMP Echo Request')
            if not self.passive_mode:
                self.async_resolve_hostname(pkt[IP].src)

    def _extract_tcp_info(
        self,
        src_ip: str,
        dst_ip: str,
        tcp_layer: TCP,
    ) -> tuple[str, str, str, str]:
        """Extract TCP connection info."""
        is_my_src = src_ip in self.my_ips
        sport, dport = tcp_layer.sport, tcp_layer.dport
        port = f':{dport}' if is_my_src else f':{sport}'
        p_info = f':{sport} > :{dport}'
        # Use connection cache for efficiency
        process = self.get_process_for_connection(
            src_ip,
            str(sport),
            dst_ip,
            str(dport),
            'tcp',
        )
        return port, str(sport if is_my_src else dport), p_info, process

    def _extract_udp_info(
        self,
        src_ip: str,
        dst_ip: str,
        udp_layer: UDP,
    ) -> tuple[str, str, str, str, bool]:
        """Extract UDP connection info and DNS flag."""
        is_my_src = src_ip in self.my_ips
        sport, dport = udp_layer.sport, udp_layer.dport
        port = f':{dport}' if is_my_src else f':{sport}'
        p_info = f':{sport} > :{dport}'
        # Use connection cache for efficiency
        process = self.get_process_for_connection(
            src_ip,
            str(sport),
            dst_ip,
            str(dport),
            'udp',
        )
        is_dns = sport == 53 or dport == 53
        return port, str(sport if is_my_src else dport), p_info, process, is_dns

    def _handle_local_ipc(
        self,
        proto: str,
        layers: dict[str, Any],
    ) -> None:
        """Handle inter-process communication on localhost."""
        tcp_layer = layers.get('tcp')
        udp_layer = layers.get('udp')
        if tcp_layer:
            sport, dport = tcp_layer.sport, tcp_layer.dport
            src_process = self.get_process_for_port('tcp', str(sport))
            dst_process = self.get_process_for_port('tcp', str(dport))
            is_local_dns = sport == 53 or dport == 53
        elif udp_layer:
            sport, dport = udp_layer.sport, udp_layer.dport
            src_process = self.get_process_for_port('udp', str(sport))
            dst_process = self.get_process_for_port('udp', str(dport))
            is_local_dns = sport == 53 or dport == 53
        else:
            return

        if is_local_dns:
            # Group all local DNS into a single entry
            self.update_entry(
                'DNS Queries (Local)',
                'Local DNS',
                'Local DNS Queries',
                'Various',
            )
        else:
            # Show detailed port-to-port info for other IPC
            key = f':{sport} > :{dport}'
            src_name = src_process if src_process else 'unknown'
            dst_name = dst_process if dst_process else 'unknown'
            process_flow = f'{src_name} → {dst_name}'
            self.update_entry(
                'Local Inter-Process',
                key,
                f'{proto.upper()} IPC',
                process_flow,
            )

    def _handle_active_connections(
        self,
        src_ip: str | None,
        dst_ip: str | None,
        layers: dict[str, Any],
    ) -> None:
        if not (src_ip and dst_ip):
            return

        tcp_layer = layers.get('tcp')
        udp_layer = layers.get('udp')

        # Skip packets handled by specific protocol handlers
        if self._should_skip_udp_packet(udp_layer):
            return

        # Check for broadcast/multicast
        if self._is_broadcast_or_multicast(dst_ip):
            self._handle_broadcast(src_ip, dst_ip, tcp_layer, udp_layer)
            return

        is_my_src = src_ip in self.my_ips
        is_my_dst = dst_ip in self.my_ips

        # Handle local inter-process communication
        if is_my_src and is_my_dst:
            proto = 'tcp' if tcp_layer else 'udp' if udp_layer else 'ip'
            self._handle_local_ipc(proto, layers)
            return

        # Handle connections involving this machine
        if is_my_src or is_my_dst:
            self._handle_external_connection(src_ip, dst_ip, is_my_src, tcp_layer, udp_layer)

    def _should_skip_udp_packet(self, udp_layer: UDP | None) -> bool:
        """Check if UDP packet should be skipped."""
        if not udp_layer:
            return False
        return udp_layer.dport in [5353, 1900, 5355, 137, 27036] or udp_layer.sport in [5353]

    def _is_broadcast_or_multicast(self, dst_ip: str) -> bool:
        """Check if destination is broadcast or multicast."""
        return dst_ip.endswith('.255') or dst_ip.startswith(('224.', '239.', 'ff02:'))

    def _handle_broadcast(
        self,
        src_ip: str,
        dst_ip: str,
        tcp_layer: TCP | None,
        udp_layer: UDP | None,
    ) -> None:
        """Handle broadcast/multicast packets."""
        proto = 'tcp' if tcp_layer else 'udp' if udp_layer else 'ip'
        if tcp_layer:
            p_info = f':{tcp_layer.sport} > :{tcp_layer.dport}'
            process = self.get_process_for_connection(
                src_ip,
                str(tcp_layer.sport),
                dst_ip,
                str(tcp_layer.dport),
                'tcp',
            )
        elif udp_layer:
            p_info = f':{udp_layer.sport} > :{udp_layer.dport}'
            process = self.get_process_for_connection(
                src_ip,
                str(udp_layer.sport),
                dst_ip,
                str(udp_layer.dport),
                'udp',
            )
        else:
            p_info, process = '', ''
        self.update_entry(
            '~ Ignored / Broadcast',
            f'{src_ip} > {dst_ip}',
            f'{proto.upper()} {p_info}',
            process,
        )

    def _handle_external_connection(
        self,
        src_ip: str,
        dst_ip: str,
        is_my_src: bool,
        tcp_layer: TCP | None,
        udp_layer: UDP | None,
    ) -> None:
        """Handle connections to/from external hosts."""
        other_ip = dst_ip if is_my_src else src_ip
        proto = 'tcp' if tcp_layer else 'udp' if udp_layer else 'ip'
        is_dns = False

        if tcp_layer:
            port, _, _, process = self._extract_tcp_info(src_ip, dst_ip, tcp_layer)
        elif udp_layer:
            port, _, _, process, is_dns = self._extract_udp_info(src_ip, dst_ip, udp_layer)
        else:
            port, process = '', ''

        # Queue for resolution if not DNS
        if not self.passive_mode and '.' in other_ip and not is_dns:
            self.async_resolve_hostname(other_ip)

        # Determine category
        if is_dns:
            category, info = 'DNS Queries', 'DNS Lookup'
        else:
            resolved_name = self.resolved_names.get(other_ip)
            if self.is_local_network_device(other_ip, resolved_name):
                category = 'Local Network Devices'
            else:
                category = 'Active_Connections'
            info = f'{proto.upper()} Traffic'

        self.update_entry(category, f'{other_ip}{port}', info, process)

    def parse_packet(self, pkt: Packet) -> None:
        """Parse a packet and update state."""
        start_time = time.time()
        try:
            self._parse_packet_internal(pkt)
        finally:
            self.perf_monitor.record_packet(time.time() - start_time)

    def _parse_packet_internal(self, pkt: Packet) -> None:
        """Internal packet parsing logic with layer caching."""
        # Extract all layers once at the start (optimization phase 3)
        layers = {
            'ip': pkt.getlayer(IP),
            'ipv6': pkt.getlayer(IPv6),
            'tcp': pkt.getlayer(TCP),
            'udp': pkt.getlayer(UDP),
            'arp': pkt.getlayer(ARP),
            'dns': pkt.getlayer(DNS),
            'ether': pkt.getlayer(Ether),
            'icmp': pkt.getlayer(ICMP),
        }

        src_ip = None
        dst_ip = None

        if layers['ip']:
            src_ip = layers['ip'].src
            dst_ip = layers['ip'].dst
        elif layers['ipv6']:
            src_ip = layers['ipv6'].src
            dst_ip = layers['ipv6'].dst

        # Add local network IPs to my_ips set
        if src_ip and src_ip not in self.my_ips and '.' in src_ip and self.is_private_ip(src_ip):
            self.my_ips.add(src_ip)

        if dst_ip and dst_ip not in self.my_ips and '.' in dst_ip and self.is_private_ip(dst_ip):
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
        self._handle_active_connections(src_ip, dst_ip, layers)

    def is_local_network_device(self, ip: str, resolved_name: str | None) -> bool:
        """Check if IP/name represents a local network mDNS device."""
        # Check if IP is local network
        if not self.is_private_ip(ip):
            return False

        # Check if name has mDNS-like patterns
        if resolved_name:
            mdns_patterns = [
                '_on_',
                ' on ',
                '_mqtt_',
                '.local',
                'mss_',
                '_printer_',
                '_iot_',
            ]
            name_lower = resolved_name.lower()
            if any(pattern in name_lower for pattern in mdns_patterns):
                return True

        return False

    def get_display_name(self, key: str) -> str:
        """Get display name - uses cached resolver, never blocks."""
        if '>' in key:
            return key
        ip_part = key.split(':', maxsplit=1)[0].split(' ')[0]

        # Attempt async resolution if not already resolved
        if ip_part not in self.resolved_names and not self.passive_mode:
            self.async_resolve_hostname(ip_part)

        # Use cached result if available
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

    def save_to_file(self, text: str) -> str | None:
        try:
            log_dir = os.path.join(tempfile.gettempdir(), 'net_watch')
            if not os.path.exists(log_dir):
                os.makedirs(log_dir)

            ts = datetime.now().strftime('%Y%m%d-%H%M%S')
            filename = os.path.join(log_dir, f'{ts}.log')

            with open(filename, 'w') as f:
                f.write(text)
        except OSError:
            logging.error('Error saving to file', exc_info=True)
            return None
        else:
            return filename

    def generate_table_string(self) -> str:
        """Generate table for file export - lock-free read (single writer pattern)."""
        lines = []
        lines.append(
            f"{'DEVICE / IP':<38} | {'INFO':<18} | {'AGE':<6} | {'PPM':<6} | {'PROCESS':<18}",
        )
        lines.append('-' * 100)

        # No lock needed - single writer guarantees consistency
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

    def _prepare_buffer_and_cleanup(self, now: float) -> list[dict[str, Any]]:
        """Prepare display buffer - lock-free read, async cleanup.

        Single writer pattern: UI thread ONLY reads, never writes.
        Cleanup is queued to single writer thread.
        """
        # Queue cleanup command to single writer thread
        self.command_queue.put({'cmd': 'cleanup', 'now': now})

        # Read data without lock - safe because only single writer modifies
        snapshot: list[tuple] = []
        for category in sorted(self.data.keys()):
            snapshot.append(('cat', category))
            for key, details in self.data[category].items():
                snapshot.append(
                    (
                        'row',
                        key,
                        details['last_seen'],
                        details['first_seen'],
                        details['count'],
                        details['info'],
                        details.get('process', ''),
                    ),
                )
            snapshot.append(('spacer',))

        # Format buffer - zero contention
        buffer = []
        for item in snapshot:
            if item[0] == 'cat':
                buffer.append({'type': 'cat', 'text': f'[{item[1]}]', 'is_new': False})
            elif item[0] == 'row':
                _, key, last_seen, first_seen, count, info, process = item
                age = int(now - last_seen)
                duration = max(1, now - first_seen)
                ppm = int((count / duration) * 60)
                display_key = self.get_display_name(key)

                t_key = self.truncate(display_key, self.w_ip)
                t_info = self.truncate(info, self.w_info)
                t_proc = self.truncate(process, self.w_proc)

                buffer.append(
                    {
                        'type': 'row',
                        'text': (
                            f'  {t_key:<{self.w_ip}} | {t_info:<{self.w_info}} | '
                            f'{age:<{self.w_age}} | {ppm:<{self.w_ppm}} | {t_proc:<{self.w_proc}}'
                        ),
                        'is_new': age < 5,
                    },
                )
            else:
                buffer.append({'type': 'spacer', 'text': '', 'is_new': False})

        return buffer

    def _draw_header(
        self,
        stdscr: curses.window,
        buffer_len: int,
        now: float,
        max_x: int,
    ) -> None:
        try:
            mode_str = 'Passive' if self.passive_mode else 'Active'
            q_str = ' | Showing Queries' if self.show_questions else ''
            main_ip = self.get_main_ip()
            header = f"NET MONITOR ({mode_str}{q_str}) [Press 'p' to Save Log]"

            stdscr.addstr(0, 0, header[: max_x - 1], curses.A_BOLD)
            if now - self.status_time < 3 and self.status_msg:
                stdscr.addstr(
                    0,
                    max_x - len(self.status_msg) - 1,
                    self.status_msg,
                    curses.A_REVERSE | curses.A_BOLD,
                )

            # Add performance stats
            perf_stats = self.perf_monitor.get_stats()
            perf_info = f'Main IP: {main_ip} | Items: {buffer_len} | '
            perf_info += f"PPS: {perf_stats['pps']:.1f} | Avg: {perf_stats['avg_ms']:.2f}ms | "
            perf_info += f"Max: {perf_stats['max_ms']:.1f}ms"
            stdscr.addstr(1, 0, perf_info[: max_x - 1], curses.A_DIM)
            cols = (
                f"  {'DEVICE / IP':<{self.w_ip}} | {'INFO':<{self.w_info}} | "
                f"{'AGE':<{self.w_age}} | {'PPM':<{self.w_ppm}} | {'PROCESS':<{self.w_proc}}"
            )
            stdscr.addstr(2, 0, cols[: max_x - 1], curses.A_REVERSE)
        except curses.error:
            pass  # Small terminal

    def _get_item_attr(self, item: dict[str, Any]) -> int:
        if item['type'] == 'cat':
            return curses.A_BOLD | curses.A_UNDERLINE
        if item['type'] == 'row' and item.get('is_new'):
            return curses.A_BOLD
        if item['type'] == 'row':
            return curses.A_DIM
        return curses.A_NORMAL

    def _draw_rows(
        self,
        stdscr: curses.window,
        buffer: list[dict[str, Any]],
        max_y: int,
        max_x: int,
    ) -> None:
        visible_h = max_y - 3
        self.scroll_offset = min(self.scroll_offset, max(0, len(buffer) - visible_h))

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
            with contextlib.suppress(curses.error):
                stdscr.addstr(row_idx, 0, text, attr)

        if len(buffer) > visible_h:
            scroll_pct = self.scroll_offset / (len(buffer) - visible_h)
            scroll_pos = 3 + int(scroll_pct * (visible_h - 1))
            if scroll_pos < max_y:
                with contextlib.suppress(curses.error):
                    stdscr.addch(scroll_pos, max_x - 1, '█', curses.A_REVERSE)

        stdscr.refresh()

    def _handle_input(
        self,
        stdscr: curses.window,
        buffer: list[dict[str, Any]],
        max_y: int,
        now: float,
    ) -> bool:
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
        except curses.error:
            pass
        return True

    def cleanup_and_display(self, stdscr: curses.window) -> None:
        curses.curs_set(0)
        stdscr.nodelay(True)
        stdscr.keypad(True)

        while True:
            max_y, max_x = stdscr.getmaxyx()
            now = time.time()

            # Single lock for both cleanup and buffer prep
            buffer = self._prepare_buffer_and_cleanup(now)

            if not self._handle_input(stdscr, buffer, max_y, now):
                break

            stdscr.erase()
            self._draw_header(stdscr, len(buffer), now, max_x)
            self._draw_rows(stdscr, buffer, max_y, max_x)

            time.sleep(0.15)  # Slower refresh = less lock contention

    def run(self) -> None:
        self.detect_local_ips()

        # Start SINGLE WRITER thread - only thread that modifies self.data
        t_writer = threading.Thread(target=self.single_writer_worker, name='SingleWriter')
        t_writer.daemon = True
        t_writer.start()

        # BPF filter optimization: filter common protocols at kernel level
        bpf_filter = 'tcp or udp or arp or icmp or icmp6'
        t_sniff = threading.Thread(
            target=lambda: sniff(prn=self.parse_packet, store=0, filter=bpf_filter),
            name='PacketCapture',
        )
        t_sniff.daemon = True
        t_sniff.start()

        # DNS resolution now uses async thread pool + cached function
        if not self.passive_mode:
            # Pre-warm cache with local IPs
            for ip in self.my_ips:
                self.async_resolve_hostname(ip)

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
