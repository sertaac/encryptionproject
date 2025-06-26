# password_detector/main.py #

import argparse
import os
import time
import asyncio 
from concurrent.futures import ThreadPoolExecutor 
import multiprocessing 

from detector import PasswordProtectionDetector

async def main(): 
    """
    Main entry point for the Password Protection & Encryption Detector.
    
    Handles command-line arguments, initializes the detector, and processes files/directories
    based on user input. Outputs results to the console.
    """
    
    total_start_time = time.perf_counter()
    
    # --- Argument Parsing --- #
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
    args = parser.parse_args()

    # Determine optimal number of workers for ThreadPoolExecutor #
    num_cpu_cores = multiprocessing.cpu_count()
    # A common heuristic for I/O-bound tasks is 2x CPU cores + 4, or a fixed large number like 32 #
    max_workers = max(32, num_cpu_cores * 2 + 4) 
    
    # --- Detector Initialization --- #
    # Initialize ThreadPoolExecutor once and pass it to the detector #
    with ThreadPoolExecutor(max_workers=max_workers) as global_executor:
        detector = PasswordProtectionDetector(executor=global_executor) # Pass the executor #

        # --- Processing Logic --- #
        
        # Batch mode processing (directory scan) #
        if args.batch and os.path.isdir(args.path):
            print(f"Scanning directory: {args.path}\n")
            
            # Scan all files in directory recursively #
            results = await detector.scan_directory(args.path) # Await here #
            
            for result in results:
                if result: # Ensure result is not None if any analysis failed #
                    status = "PASSWORD PROTECTED" if result['password_protected'] else "NOT PASSWORD PROTECTED"
                    # Format output to include the individual file's analysis duration #
                    print(
                        f"{result['file']}: {status} "
                        f"(Encrypted: {result['encrypted']}, "
                        f"Confidence: {result['confidence']:.2f}, "
                        f"Time: {result['duration']:.4f}s)"
                    )
        
        # Single file processing #
        elif os.path.isfile(args.path):
            print(f"Scanning file: {args.path}")
            
            # Analyze the single file #
            result = await detector.analyze_file(args.path) # Await here #
            
            status = "PASSWORD PROTECTED" if result['password_protected'] else "NOT PASSWORD PROTECTED"
            
            # Format output to include the file's analysis duration #
            print(
                f"Result: {status} "
                f"(Encrypted: {result['encrypted']}, "
                f"Confidence: {result['confidence']:.2f}, "
                f"Time: {result['duration']:.4f}s)"
            )
        
        # Invalid path handling #
        else:
            print(
                "Error: Invalid path provided.\n"
                "Please provide either:\n"
                "1. A valid file path, or\n"
                "2. A directory path with --batch flag for scanning multiple files"
            )
        
        # Record end time for total execution #
        total_end_time = time.perf_counter()
        print(f"\nTotal execution time: {total_end_time - total_start_time:.4f}s")

if __name__ == "__main__":
    asyncio.run(main()) # Run the async main function #