# password_detector/detector.py

import os
from typing import Dict, List

from type_utils import FileTypeDetector
from entropy import EntropyAnalyzer
from file_handlers import (
    OfficeOpenXMLHandler, OfficeLegacyHandler, PDFHandler, ZIPHandler,
    RARHandler, SevenZipHandler, SQLiteHandler, PSTHandler, MSGHandler
)


class PasswordProtectionDetector:
    """Detects password protection and encryption in files using file-type-specific handlers."""
    
    def __init__(self):
        """Initialize with a file type detector and handlers for supported formats."""
        self.type_detector = FileTypeDetector()
        self.handlers = {
            'office_openxml': OfficeOpenXMLHandler,
            'pdf': PDFHandler,
            'zip': ZIPHandler,
            'rar': RARHandler,
            '7z': SevenZipHandler,
            'sqlite': SQLiteHandler,
            'pst': PSTHandler,
            'msg': MSGHandler,
            'office_legacy': OfficeLegacyHandler,
        }

    def analyze_file(self, file_path: str) -> Dict:
        """
        Analyze a single file for password protection and encryption.
        
        Args:
            file_path (str): Path to the file to analyze.
        
        Returns:
            Dict: Results with keys 'password_protected', 'encrypted', and 'confidence'.
        """
        # Skip invalid files
        if not os.path.isfile(file_path) or os.path.getsize(file_path) == 0:
            return {
                'file': file_path,
                'password_protected': False,
                'encrypted': False,
                'confidence': 0.0
            }

        # --- File Type Detection ---
        file_type = self.type_detector.detect(file_path)

        # --- Handler-Based Analysis ---
        password_protected, encrypted_entropy, confidence = False, False, 0.0
        if file_type in self.handlers:
            try:
                handler = self.handlers[file_type]
                password_protected, encrypted_entropy, confidence = handler.is_encrypted(file_path)
            except Exception:
                pass  # Fall back to entropy analysis if handler fails

        # --- Entropy Fallback ---
        if confidence < 0.5:
            encrypted_entropy, entropy_conf = EntropyAnalyzer.analyze(file_path)
            confidence = max(confidence, entropy_conf)

        return {
            'file': file_path,
            'password_protected': password_protected,
            'encrypted': encrypted_entropy,
            'confidence': confidence
        }

    def scan_directory(self, path: str) -> List[Dict]:
        """
        Scan all files in a directory recursively.
        
        Args:
            path (str): Directory path to scan.
        
        Returns:
            List[Dict]: List of analysis results for each file.
        """
        results = []
        for root, _, files in os.walk(path):
            for file in files:
                full_path = os.path.join(root, file)
                results.append(self.analyze_file(full_path))
        return results