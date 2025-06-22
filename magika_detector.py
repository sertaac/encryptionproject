# password_detector/magika_detector.py

from magika import Magika
import os


class MagikaDetector:
    """File type detection using Magika's ML model."""
    
    def __init__(self):
        self.model = Magika()

    def detect(self, file_path: str) -> str:
        """
        Identify file type using Magika, falling back to 'unknown' on errors.
        
        Args:
            file_path (str): File to analyze.
        
        Returns:
            str: Detected file type (e.g., 'pdf', 'zip').
        """
        try:
            result = self.model.identify_path(file_path)
            mime = result.output.mime_type
        except Exception:
            return 'unknown'

        # MIME type to internal format mapping
        mime_map = {
            'application/pdf': 'pdf',
            'application/vnd.openxmlformats-officedocument.wordprocessingml.document': 'office_openxml',
            'application/vnd.ms-excel': 'office_legacy',
            'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': 'office_openxml',
            'application/zip': 'zip',
            'application/x-rar': 'rar',
            'application/x-7z-compressed': '7z',
            'application/vnd.sqlite3': 'sqlite',
            'application/vnd.ms-outlook': 'msg',
            'application/octet-stream': 'unknown',
        }

        return mime_map.get(mime, 'unknown')