# EncryptionProject/password_detector_package/sync_detector.py

import asyncio
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List

from .detector import PasswordProtectionDetector

class SynchronousPasswordProtectionDetector:
    """
    Provides a synchronous interface for the asynchronous PasswordProtectionDetector.
    Each method call runs its underlying asynchronous counterpart using asyncio.run().
    """
    def __init__(self, executor: ThreadPoolExecutor):
        self._async_detector = PasswordProtectionDetector(executor=executor)

    def analyze_file(self, file_path: str) -> Dict:
        """
        Analyze a single file for password protection and encryption in a synchronous manner.
        Internally runs the asynchronous analyze_file method using asyncio.run().
        """
        return asyncio.run(self._async_detector.analyze_file(file_path))

    def scan_directory(self, directory: str) -> List[Dict]:
        """
        Scan all files in a directory recursively in a synchronous manner.
        Internally runs the asynchronous scan_directory method using asyncio.run().
        """
        return asyncio.run(self._async_detector.scan_directory(directory))
