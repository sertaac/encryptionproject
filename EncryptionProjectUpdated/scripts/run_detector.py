# EncryptionProject/scripts/run_detector.py

import argparse
import os
import time
import asyncio
from concurrent.futures import ThreadPoolExecutor
import multiprocessing
import sys

from password_detector_package.detector import PasswordProtectionDetector
from password_detector_package.sync_detector import SynchronousPasswordProtectionDetector


def main_cli():
    """Komut satırı arayüzü ana giriş noktası."""
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
        help='Run in synchronous mode (uses a synchronous wrapper around the async core)'
    )
    args = parser.parse_args()

    num_cpu_cores = multiprocessing.cpu_count()
    max_workers = max(32, num_cpu_cores * 2 + 4) 
    
    with ThreadPoolExecutor(max_workers=max_workers) as global_executor:
        if args.sync:
            print("Running in explicit SYNCHRONOUS mode (using SynchronousPasswordProtectionDetector)...")
            # Synchronous dedektör sınıfını başlatıyoruz
            detector = SynchronousPasswordProtectionDetector(executor=global_executor)
            
            # Çağrılar artık doğrudan senkron metotlar gibi yapılır
            if args.batch and os.path.isdir(args.path):
                results = detector.scan_directory(args.path)
            elif os.path.isfile(args.path):
                results = [detector.analyze_file(args.path)]
            else:
                sys.stderr.buffer.write(b"Error: Invalid path provided.\n")
                results = [] 
            
            for result in results:
                if result:
                    status = "PASSWORD PROTECTED" if result['password_protected'] else "NOT PASSWORD PROTECTED"
                    output_line = (
                        f"{result['file']}: {status} "
                        f"(Encrypted: {result['encrypted']}, "
                        f"Confidence: {result['confidence']:.2f}, "
                        f"Time: {result['duration']:.4f}s)\n"
                    )
                    sys.stdout.buffer.write(output_line.encode('utf-8', errors='replace'))

        else:
            print("Running in ASYNCHRONOUS mode (using PasswordProtectionDetector)...")
            detector = PasswordProtectionDetector(executor=global_executor)
            
            async def _run_async_logic():
                if args.batch and os.path.isdir(args.path):
                    return await detector.scan_directory(args.path)
                elif os.path.isfile(args.path):
                    return [await detector.analyze_file(args.path)]
                else:
                    sys.stderr.buffer.write(b"Error: Invalid path provided.\n")
                    return []

            results = asyncio.run(_run_async_logic())
            
            for result in results:
                if result:
                    status = "PASSWORD PROTECTED" if result['password_protected'] else "NOT PASSWORD PROTECTED"
                    output_line = (
                        f"{result['file']}: {status} "
                        f"(Encrypted: {result['encrypted']}, "
                        f"Confidence: {result['confidence']:.2f}, "
                        f"Time: {result['duration']:.4f}s)\n"
                    )
                    sys.stdout.buffer.write(output_line.encode('utf-8', errors='replace'))


    total_end_time = time.perf_counter()
    final_output = f"\nTotal execution time: {total_end_time - total_start_time:.4f}s\n"
    sys.stdout.buffer.write(final_output.encode('utf-8', errors='replace'))


if __name__ == "__main__":
    main_cli()
