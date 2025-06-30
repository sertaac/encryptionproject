# EncryptionProject/password_detector_package/detector.py #

import os
import time  
from typing import List, Dict
import asyncio
from concurrent.futures import ThreadPoolExecutor

from .type_utils import FileTypeDetector
from .entropy import EntropyAnalyzer
from .file_handlers import (
    OfficeOpenXMLHandler, OfficeLegacyHandler, PDFHandler, ZIPHandler,
    RARHandler, SevenZipHandler, SQLiteHandler, PSTHandler, MSGHandler,
    LibreOfficeHandler
)


class PasswordProtectionDetector:
    """Detects password protection and encryption in files using format-specific handlers and entropy analysis."""

    def __init__(self, executor: ThreadPoolExecutor):
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
        self.executor = executor # Store the executor #

    async def analyze_file(self, file_path: str) -> Dict:
        """
        Analyze a file for password protection and encryption.
        
        Args:
            file_path (str): Path to the file.
        
        Returns:
            Dict: Results with keys 'password_protected', 'encrypted', 'confidence', and 'duration'.
        """
        start_time = time.perf_counter()
        
        if not os.path.isfile(file_path) or os.path.getsize(file_path) == 0:
            end_time = time.perf_counter()
            return {
                'file': file_path,
                'password_protected': False,
                'encrypted': False,
                'confidence': 0.0,
                'duration': end_time - start_time  
            }

        file_type = await self.type_detector.detect(file_path)

        password_protected, encrypted, confidence = False, False, 0.0
        try:
            if file_type in self.handlers:
                handler = self.handlers[file_type]
                password_protected, encrypted, confidence = await handler.is_encrypted(file_path)
        except Exception as e:
            # To prevent UnicodeEncodeError in error message #
            safe_file_path = file_path.encode('utf-8', 'replace').decode('utf-8')
            print(f"Error analyzing {safe_file_path}: {str(e)}")
            confidence = 0.0

        if confidence < 0.5:
            # EntropyAnalyzer.analyze is blocking so we call it with to_thread #
            encrypted_entropy, entropy_conf = await asyncio.to_thread(EntropyAnalyzer.analyze, file_path)
            if entropy_conf > confidence:
                encrypted = encrypted_entropy
                confidence = entropy_conf

        end_time = time.perf_counter() 

        return {
            'file': file_path,
            'password_protected': password_protected,
            'encrypted': encrypted,
            'confidence': confidence,
            'duration': end_time - start_time  
        }

    async def scan_directory(self, directory: str) -> List[Dict]:
        """
        Scan all files in a directory recursively.
        
        Args:
            directory (str): Path to the directory.
        
        Returns:
            List[Dict]: List of analysis results for each file.
        """
        tasks = []
        for root, _, files in os.walk(directory):
            for file in files:
                full_path = os.path.join(root, file)
                tasks.append(self.analyze_file(full_path)) 
        
        results = await asyncio.gather(*tasks)
        return results