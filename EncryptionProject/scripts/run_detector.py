# EncryptionProject/scripts/run_detector.py #

import argparse
import os
import time
import asyncio
from concurrent.futures import ThreadPoolExecutor
import multiprocessing
import sys
from password_detector_package.detector import PasswordProtectionDetector


async def _run_detection_logic(detector, args):
    """
    Asynchronous function that handles the core detection logic.
    Supports both single file and batch scanning modes.
    """
    if args.batch and os.path.isdir(args.path):
        print(f"Scanning directory: {args.path}\n")
        results = await detector.scan_directory(args.path)
        for result in results:
            if result:
                status = "PASSWORD PROTECTED" if result['password_protected'] else "NOT PASSWORD PROTECTED"
                # Encoding output to prevent UnicodeEncodeError #
                output_line = (
                    f"{result['file']}: {status} "
                    f"(Encrypted: {result['encrypted']}, "
                    f"Confidence: {result['confidence']:.2f}, "
                    f"Time: {result['duration']:.4f}s)\n"
                )
                sys.stdout.buffer.write(output_line.encode('utf-8', errors='replace'))
    elif os.path.isfile(args.path):
        print(f"Scanning file: {args.path}")
        result = await detector.analyze_file(args.path)
        status = "PASSWORD PROTECTED" if result['password_protected'] else "NOT PASSWORD PROTECTED"
        output_line = (
            f"Result: {status} "
            f"(Encrypted: {result['encrypted']}, "
            f"Confidence: {result['confidence']:.2f}, "
            f"Time: {result['duration']:.4f}s)\n"
        )
        sys.stdout.buffer.write(output_line.encode('utf-8', errors='replace'))
    else:
        output_line = (
            "Error: Invalid path provided.\n"
            "Please provide either:\n"
            "1. A valid file path, or\n"
            "2. A directory path with --batch flag for scanning multiple files\n"
        )
        sys.stderr.buffer.write(output_line.encode('utf-8', errors='replace'))


def main_cli():
    """Command line interface main entry point."""
    total_start_time = time.perf_counter()

    parser = argparse.ArgumentParser(
        description='Password Protection & Encryption Detector - '
        'Scans files for password protection and encryption'
    )
    parser.add_argument(
        'path', 
        help='File or directory path to scan (required)'
    )
    parser.add_argument(
        '--batch', 
        action='store_true',
        help='Enable batch mode for scanning entire directories'
    )
    parser.add_argument(
        '--sync',
        action='store_true',
        help='Run in synchronous (blocking) mode using asyncio.run'
    )
    args = parser.parse_args()

    num_cpu_cores = multiprocessing.cpu_count()
    max_workers = max(32, num_cpu_cores * 2 + 4) 
    
    # ThreadPoolExecutor is used for running blocking I/O tasks in separate threads #
    # in both async and sync modes #
    with ThreadPoolExecutor(max_workers=max_workers) as global_executor:
        detector = PasswordProtectionDetector(executor=global_executor)

        if args.sync:
            print("Running in synchronous (blocking) mode...")
            # For sync mode, we run the async logic directly with asyncio.run #
            # This starts a single blocking event loop and waits for completion #
            asyncio.run(_run_detection_logic(detector, args))
        else:
            print("Running in asynchronous mode...")
            # For async mode, we start the async logic normally with asyncio.run #
            asyncio.run(_run_detection_logic(detector, args))

    total_end_time = time.perf_counter()
    final_output = f"\nTotal execution time: {total_end_time - total_start_time:.4f}s\n"
    sys.stdout.buffer.write(final_output.encode('utf-8', errors='replace'))


if __name__ == "__main__":
    main_cli()