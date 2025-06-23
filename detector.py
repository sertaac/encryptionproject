# password_detector/detector.py #

import os
from typing import List, Dict
from type_utils import FileTypeDetector
from entropy import EntropyAnalyzer
from file_handlers import (
    OfficeOpenXMLHandler, OfficeLegacyHandler, PDFHandler, ZIPHandler,
    RARHandler, SevenZipHandler, SQLiteHandler, PSTHandler, MSGHandler,
    LibreOfficeHandler
)


class PasswordProtectionDetector:
    """Detects password protection and encryption in files using format-specific handlers and entropy analysis."""

    def __init__(self):
        """Initialize with a file type detector and handlers for supported formats."""
        self.type_detector = FileTypeDetector()
        self.handlers = {
            'office_openxml': OfficeOpenXMLHandler,
            'office_legacy': OfficeLegacyHandler,
            'pdf': PDFHandler,
            'zip': ZIPHandler,
            'rar': RARHandler,
            '7z': SevenZipHandler,
            'sqlite': SQLiteHandler,
            'pst': PSTHandler,
            'msg': MSGHandler,
            'libre_office': LibreOfficeHandler
        }

    def analyze_file(self, file_path: str) -> Dict:
        """
        Analyze a file for password protection and encryption.
        
        Args:
            file_path (str): Path to the file.
        
        Returns:
            Dict: Results with keys 'password_protected', 'encrypted', and 'confidence'.
        """
        # Skip invalid files #
        if not os.path.isfile(file_path) or os.path.getsize(file_path) == 0:
            return {
                'file': file_path,
                'password_protected': False,
                'encrypted': False,
                'confidence': 0.0
            }

        # --- File Type Detection --- #
        file_type = self.type_detector.detect(file_path)

        # --- Handler-Based Analysis --- #
        password_protected, encrypted, confidence = False, False, 0.0
        if file_type in self.handlers:
            handler = self.handlers[file_type]
            password_protected, encrypted, confidence = handler.is_encrypted(file_path)

        # --- Entropy Fallback (Low-Confidence Cases) --- #
        if confidence < 0.5:
            encrypted_entropy, entropy_conf = EntropyAnalyzer.analyze(file_path)
            if entropy_conf > confidence:
                encrypted = encrypted_entropy
                confidence = entropy_conf

        return {
            'file': file_path,
            'password_protected': password_protected,
            'encrypted': encrypted,
            'confidence': confidence
        }

    def scan_directory(self, directory: str) -> List[Dict]:
        """
        Scan all files in a directory recursively.
        
        Args:
            directory (str): Path to the directory.
        
        Returns:
            List[Dict]: List of analysis results for each file.
        """
        results = []
        for root, _, files in os.walk(directory):
            for file in files:
                full_path = os.path.join(root, file)
                results.append(self.analyze_file(full_path))
        return results