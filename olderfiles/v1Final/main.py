# password_detector/main.py #

import argparse
import os
import time  # For timing operations
from detector import PasswordProtectionDetector

def main():
    """
    Main entry point for the Password Protection & Encryption Detector.
    
    Handles command-line arguments, initializes the detector, and processes files/directories
    based on user input. Outputs results to the console.
    """
    
    # Record start time for total execution
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

    # --- Detector Initialization --- #
    detector = PasswordProtectionDetector()

    # --- Processing Logic --- #
    
    # Batch mode processing (directory scan) #
    if args.batch and os.path.isdir(args.path):
        print(f"Scanning directory: {args.path}\n")
        
        # Scan all files in directory recursively #
        results = detector.scan_directory(args.path)
        
        # Print results for each file #
        for result in results:
            status = "PASSWORD PROTECTED" if result['password_protected'] else "NOT PASSWORD PROTECTED"
            
            # Format output to include the individual file's analysis duration
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
        result = detector.analyze_file(args.path)
        
        status = "PASSWORD PROTECTED" if result['password_protected'] else "NOT PASSWORD PROTECTED"
        
        # Format output to include the file's analysis duration
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
    
    # Record end time for total execution
    total_end_time = time.perf_counter()
    print(f"\nTotal execution time: {total_end_time - total_start_time:.4f} seconds.")


# Standard Python idiom for executing main function #
if __name__ == "__main__":
    main()