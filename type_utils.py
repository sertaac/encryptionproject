# password_detector/type_utils.py (GÜNCELLENMİŞ)

import os
from magika_detector import MagikaDetector

class FileTypeDetector:
    def __init__(self):
        self.magika = MagikaDetector()

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
        ext = os.path.splitext(file_path)[1].lower()
        file_type = self.extension_map.get(ext, 'unknown')

        # Fallback: Magika sadece gerekirse çalışır
        if file_type == 'unknown':
            file_type = self.magika.detect(file_path)

        return file_type
