# password_detector/magika_detector.py #

from magika import Magika
import os


class MagikaDetector:
    """File type detection using Google's Magika machine learning model."""
    
    def __init__(self):
        """Initialize Magika model."""
        self.model = Magika()

    def detect(self, file_path: str) -> str:
        """
        Identify file type using Magika's ML model.
        
        Args:
            file_path (str): Path to the file to analyze
            
        Returns:
            str: Internal file type identifier (e.g., 'pdf', 'zip')
                  Returns 'unknown' if detection fails
        """
        try:
            # Get Magika's prediction #
            result = self.model.identify_path(file_path)
            mime = result.output.mime_type
        except Exception:
            return 'unknown'

        # Map MIME types to our internal format identifiers #
        mime_map = {
            'application/pdf': 'pdf',
            'application/vnd.openxmlformats-officedocument.wordprocessingml.document': 'office_openxml',
            'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': 'office_openxml',
            'application/vnd.openxmlformats-officedocument.presentationml.presentation': 'office_openxml',
            'application/vnd.ms-excel': 'office_legacy',
            'application/vnd.ms-powerpoint': 'office_legacy',
            'application/msword': 'office_legacy',
            'application/zip': 'zip',
            'application/x-rar': 'rar',
            'application/x-7z-compressed': '7z',
            'application/vnd.sqlite3': 'sqlite',
            'application/vnd.ms-outlook': 'msg',
            'application/vnd.oasis.opendocument.text': 'libre_office',
            'application/vnd.oasis.opendocument.spreadsheet': 'libre_office',
            'application/vnd.oasis.opendocument.presentation': 'libre_office',
            'application/vnd.oasis.opendocument.graphics': 'libre_office',
            'application/vnd.oasis.opendocument.formula': 'libre_office',
            'application/vnd.oasis.opendocument.database': 'libre_office',
            'application/octet-stream': 'unknown',
        }

        return mime_map.get(mime, 'unknown')