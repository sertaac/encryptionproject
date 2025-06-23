# password_detector/main.py #

import argparse
import os
from detector import PasswordProtectionDetector

def main():
    """
    Main entry point for the Password Protection & Encryption Detector.
    
    Handles command-line arguments, initializes the detector, and processes files/directories
    based on user input. Outputs results to the console.
    """
    
    # --- Argument Parsing --- #
    # Set up command-line argument parser with description and expected arguments #
    parser = argparse.ArgumentParser(
        description='Password Protection & Encryption Detector - '
        'Scans files for password protection and encryption'
    )
    
    # Required positional argument for file/directory path #
    parser.add_argument(
        'path', 
        help='File or directory path to scan (required)'
    )
    
    # Optional flag for batch directory scanning #
    parser.add_argument(
        '--batch', 
        action='store_true',  # Sets to True when flag is present #
        help='Enable batch mode for scanning entire directories'
    )
    
    # Parse the command-line arguments #
    args = parser.parse_args()

    # --- Detector Initialization --- #
    # Create an instance of the password protection detector #
    detector = PasswordProtectionDetector()

    # --- Processing Logic --- #
    
    # Batch mode processing (directory scan) #
    if args.batch and os.path.isdir(args.path):
        print(f"Scanning directory: {args.path}")
        
        # Scan all files in directory recursively #
        results = detector.scan_directory(args.path)
        
        # Print results for each file #
        for result in results:
            # Determine protection status #
            status = "PASSWORD PROTECTED" if result['password_protected'] else "NOT PASSWORD PROTECTED"
            
            # Format output with file path, status, encryption flag, and confidence score #
            print(
                f"{result['file']}: {status} "
                f"(Encrypted: {result['encrypted']}, "
                f"Confidence: {result['confidence']:.2f})"
            )
    
    # Single file processing #
    elif os.path.isfile(args.path):
        print(f"Scanning file: {args.path}")
        
        # Analyze the single file #
        result = detector.analyze_file(args.path)
        
        # Determine protection status #
        status = "PASSWORD PROTECTED" if result['password_protected'] else "NOT PASSWORD PROTECTED"
        
        # Format output with status, encryption flag, and confidence score #
        print(
            f"Result: {status} "
            f"(Encrypted: {result['encrypted']}, "
            f"Confidence: {result['confidence']:.2f})"
        )
    
    # Invalid path handling #
    else:
        print(
            "Error: Invalid path provided.\n"
            "Please provide either:\n"
            "1. A valid file path, or\n"
            "2. A directory path with --batch flag for scanning multiple files"
        )

# Standard Python idiom for executing main function #
if __name__ == "__main__":
    main()