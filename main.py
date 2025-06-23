# password_detector/main.py
import argparse
import os
from detector import PasswordProtectionDetector

def main():
    parser = argparse.ArgumentParser(description='Password Protection & Encryption Detector')
    parser.add_argument('path', help='File or directory path to scan')
    parser.add_argument('--batch', action='store_true', help='Scan directory in batch mode')
    args = parser.parse_args()

    detector = PasswordProtectionDetector()

    if args.batch and os.path.isdir(args.path):
        results = detector.scan_directory(args.path)
        for result in results:
            status = "PASSWORD PROTECTED" if result['password_protected'] else "NOT PASSWORD PROTECTED"
            print(f"{result['file']}: {status} (Encrypted: {result['encrypted']}, Conf: {result['confidence']:.2f})")
    elif os.path.isfile(args.path):
        result = detector.analyze_file(args.path)
        status = "PASSWORD PROTECTED" if result['password_protected'] else "NOT PASSWORD PROTECTED"
        print(f"{status} (Encrypted: {result['encrypted']}, Conf: {result['confidence']:.2f})")
    else:
        print("Invalid path. Provide a file or use --batch for folder.")

if __name__ == "__main__":
    main()
