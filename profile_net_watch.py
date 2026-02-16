#!/usr/bin/env python3
"""Profile net_watch.py to identify performance bottlenecks."""
import cProfile
import pstats
import sys
from pathlib import Path

# Import the main module
import net_watch


def profile_net_watch():
    """Run net_watch with profiling enabled."""
    # Parse command line args
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument('-n', action='store_true', help='Passive mode (No DNS Lookups)')
    parser.add_argument('-Q', action='store_true', help='Show mDNS Questions')
    parser.add_argument('-t', '--time', type=int, default=30, help='Profiling duration in seconds (default: 30)')
    args = parser.parse_args()

    print(f'Starting profiling for {args.time} seconds...')
    print('Press Ctrl+C after the program starts to stop early and save profile data')
    print('-' * 60)

    # Create the app instance
    app = net_watch.NetWatch(passive_mode=args.n, show_questions=args.Q)

    # Profile the execution
    profiler = cProfile.Profile()
    profiler.enable()

    try:
        # Run with a timeout
        import signal

        def timeout_handler(signum, frame):
            raise TimeoutError('Profiling duration reached')

        signal.signal(signal.SIGALRM, timeout_handler)
        signal.alarm(args.time)

        try:
            app.run()
        except TimeoutError:
            print('\nProfiling duration reached, stopping...')
        except KeyboardInterrupt:
            print('\nStopped by user...')
    finally:
        profiler.disable()

        # Save profile data
        output_file = Path('net_watch_profile.prof')
        profiler.dump_stats(str(output_file))
        print(f'\n✓ Profile data saved to: {output_file}')

        # Print statistics
        print('\n' + '=' * 60)
        print('Top 20 functions by cumulative time:')
        print('=' * 60)
        stats = pstats.Stats(profiler, stream=sys.stdout)
        stats.sort_stats('cumulative')
        stats.print_stats(20)

        print('\n' + '=' * 60)
        print('Top 20 functions by total time:')
        print('=' * 60)
        stats.sort_stats('tottime')
        stats.print_stats(20)

        print('\n' + '=' * 60)
        print('To visualize with snakeviz, run:')
        print(f'  snakeviz {output_file}')
        print('=' * 60)


if __name__ == '__main__':
    profile_net_watch()
