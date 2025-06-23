# password_detector/detector.py (GÜNCELLENMİŞ)

import os
from typing import List, Dict
from type_utils import FileTypeDetector
from entropy import EntropyAnalyzer
from file_handlers import (
    OfficeOpenXMLHandler,
    OfficeLegacyHandler,
    PDFHandler,
    ZIPHandler,
    RARHandler,
    SevenZipHandler,
    SQLiteHandler,
    PSTHandler,
    MSGHandler,
    LibreOfficeHandler
)

class PasswordProtectionDetector:
    def __init__(self):
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
        if not os.path.isfile(file_path) or os.path.getsize(file_path) == 0:
            return {
                'file': file_path,
                'password_protected': False,
                'encrypted': False,
                'confidence': 0.0
            }

        file_type = self.type_detector.detect(file_path)

        password_protected = False
        encrypted = False
        confidence = 0.0

        if file_type in self.handlers:
            handler = self.handlers[file_type]
            password_protected, encrypted, confidence = handler.is_encrypted(file_path)

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
        results = []
        for root, _, files in os.walk(directory):
            for file in files:
                full_path = os.path.join(root, file)
                result = self.analyze_file(full_path)
                results.append(result)
        return results
