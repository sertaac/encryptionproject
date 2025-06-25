# password_detector/type_utils.py #

import os
from magika_detector import MagikaDetector


class FileTypeDetector:
    """Detects file types using the Magika library."""

    def __init__(self):
        """Initialize with a Magika detector."""
        self.magika = MagikaDetector()

    def detect(self, file_path: str) -> str:
        """
        Detect file type using Magika.
        
        Args:
            file_path (str): Path to the file to analyze
            
        Returns:
            str: Internal file type identifier (e.g., 'pdf', 'zip')
        """
       
        file_type = self.magika.detect(file_path)
        return file_type