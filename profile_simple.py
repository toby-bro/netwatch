#!/usr/bin/env python3
"""Simple packet capture profiling without curses UI."""
import cProfile
import signal
import sys
import time
from pathlib import Path

from net_watch import NetWatch


def simple_capture_profile(duration: int = 30):
    """Capture and profile packets for a specified duration."""
    print(f'Profiling packet capture for {duration} seconds...')
    print('This will capture packets without the UI to get cleaner profiling data')
    print('-' * 60)

    app = NetWatch(passive_mode=False, show_questions=False)
    app.detect_local_ips()

    # Setup packet capture
    from scapy.all import sniff

    packet_count = 0
    start_time = time.time()

    def packet_callback(pkt):
        nonlocal packet_count
        app.parse_packet(pkt)
        packet_count += 1
        if packet_count % 100 == 0:
            elapsed = time.time() - start_time
            print(
                f'\rProcessed: {packet_count} packets | Rate: {packet_count/elapsed:.1f} pps | Elapsed: {elapsed:.1f}s',
                end='',
                flush=True,
            )

    # Profile the sniffing
    profiler = cProfile.Profile()

    def timeout_handler(signum, frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGALRM, timeout_handler)
    signal.alarm(duration)

    profiler.enable()
    try:
        sniff(prn=packet_callback, store=0, filter='')
    except KeyboardInterrupt:
        pass
    finally:
        profiler.disable()

    print(f'\n\n✓ Captured {packet_count} packets in {time.time() - start_time:.1f} seconds')

    # Save and display stats
    output_file = Path('net_watch_profile.prof')
    profiler.dump_stats(str(output_file))
    print(f'✓ Profile data saved to: {output_file}')

    # Print statistics
    import pstats

    print('\n' + '=' * 80)
    print('TOP 30 FUNCTIONS BY CUMULATIVE TIME (where the program spends most time)')
    print('=' * 80)
    stats = pstats.Stats(profiler, stream=sys.stdout)
    stats.sort_stats('cumulative')
    stats.print_stats(30)

    print('\n' + '=' * 80)
    print('TOP 30 FUNCTIONS BY INTERNAL TIME (actual function execution time)')
    print('=' * 80)
    stats.sort_stats('tottime')
    stats.print_stats(30)

    print('\n' + '=' * 80)
    print('VISUALIZATION:')
    print(f'  snakeviz {output_file}')
    print('\nKEY METRICS:')
    print(f'  Total packets: {packet_count}')
    print(f'  Duration: {time.time() - start_time:.1f}s')
    print(f'  Avg rate: {packet_count/(time.time() - start_time):.1f} packets/sec')
    perf = app.perf_monitor.get_stats()
    print(f"  Avg processing time: {perf['avg_ms']:.3f}ms per packet")
    print(f"  Max processing time: {perf['max_ms']:.3f}ms per packet")
    print('=' * 80)


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='Profile net_watch packet processing')
    parser.add_argument('-t', '--time', type=int, default=30, help='Profiling duration in seconds (default: 30)')
    args = parser.parse_args()

    try:
        simple_capture_profile(args.time)
    except PermissionError:
        print('\n❌ Error: This script requires root privileges to capture packets')
        print('Run with: sudo python3 profile_simple.py')
        sys.exit(1)
