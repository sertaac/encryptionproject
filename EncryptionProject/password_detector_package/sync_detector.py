# EncryptionProject/password_detector_package/sync_detector.py

import os
import asyncio
from typing import Dict, List
from .detector import PasswordProtectionDetector
from concurrent.futures import ThreadPoolExecutor

class SynchronousPasswordProtectionDetector:
    """
    Provides a truly synchronous interface for the PasswordProtectionDetector.
    It processes files sequentially, one at a time, to serve as a baseline
    and contrast against the concurrent asynchronous detector.
    """
    def __init__(self, executor: ThreadPoolExecutor):
        # The async detector is still needed to analyze individual files.
        self._async_detector = PasswordProtectionDetector(executor=executor)

    def analyze_file(self, file_path: str) -> Dict:
        """
        Analyze a single file for password protection and encryption in a synchronous manner.
        Internally, this creates a new event loop for each file analysis.
        """
        # This part is correct: it runs one async operation and blocks until it's done.
        return asyncio.run(self._async_detector.analyze_file(file_path))

    def scan_directory(self, directory: str) -> List[Dict]:
        """
        Scans all files in a directory recursively in a truly synchronous and
        sequential manner. Each file is analyzed one after the other.
        """
        results = []
        for root, _, files in os.walk(directory):
            for file in files:
                full_path = os.path.join(root, file)
                # Analyze each file individually and sequentially.
                # The analyze_file method blocks until its result is ready.
                result = self.analyze_file(full_path)
                results.append(result)
        return results