# password_detector/type_utils.py #

import os
from magika_detector import MagikaDetector


class FileTypeDetector:
    """Detects file types using file extensions with Magika fallback."""
    
    def __init__(self):
        """Initialize with extension mappings and Magika detector."""
        self.magika = MagikaDetector()
        
        # Mapping of file extensions to internal format identifiers #
        self.extension_map = {
            '.docx': 'office_openxml',
            '.xlsx': 'office_openxml',
            '.pptx': 'office_openxml',
            '.doc': 'office_legacy',
            '.xls': 'office_legacy',
            '.ppt': 'office_legacy',
            '.pdf': 'pdf',
            '.zip': 'zip',
            '.rar': 'rar',
            '.7z': '7z',
            '.sqlite': 'sqlite',
            '.db': 'sqlite',
            '.pst': 'pst',
            '.msg': 'msg',
            '.ods': 'libre_office',
            '.odt': 'libre_office',
            '.odp': 'libre_office'
        }

    def detect(self, file_path: str) -> str:
        """
        Detect file type by extension, falling back to Magika if unknown.
        
        Args:
            file_path (str): Path to the file to analyze
            
        Returns:
            str: Internal file type identifier (e.g., 'pdf', 'zip')
        """
        # First try to determine by file extension #
        ext = os.path.splitext(file_path)[1].lower()
        file_type = self.extension_map.get(ext, 'unknown')

        # Fallback to Magika only if extension is unknown #
        if file_type == 'unknown':
            file_type = self.magika.detect(file_path)

        return file_type