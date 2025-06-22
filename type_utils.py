# password_detector/type_utils.py

import os
from magika_detector import MagikaDetector


class FileTypeDetector:
    """Detects file types using extension and Magika fallback."""
    
    def __init__(self):
        self.magika = MagikaDetector()

    def detect(self, file_path: str) -> str:
        """
        Detect file type by extension, falling back to Magika if unknown.
        
        Args:
            file_path (str): File to analyze.
        
        Returns:
            str: Internal file type identifier (e.g., 'pdf').
        """
        ext = os.path.splitext(file_path)[1].lower()

        # Extension to type mapping
        mapping = {
            '.docx': 'office_openxml',
            '.xlsx': 'office_openxml',
            # ... (rest of mapping unchanged) ...
        }

        file_type = mapping.get(ext, 'unknown')
        
        # Fallback to Magika if extension is unknown
        if file_type == 'unknown':
            file_type = self.magika.detect(file_path)

        return file_type