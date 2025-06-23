# password_detector/entropy.py (GÜNCELLENMİŞ)

import os
import math
from collections import Counter
from typing import Tuple

ENC_EXT = {'.gpg', '.enc', '.aes', '.crypt', '.pgp'}
HIGH_ENTROPY_FORMATS = {'.docx', '.xlsx', '.pptx', '.ods'}

class EntropyAnalyzer:
    @staticmethod
    def analyze(file_path: str, sample_size: int = 8192) -> Tuple[bool, float]:
        try:
            with open(file_path, 'rb') as f:
                data = f.read(sample_size)
        except Exception:
            return False, 0.0

        if not data:
            return False, 0.0

        counts = Counter(data)
        entropy = -sum((c / len(data)) * math.log2(c / len(data)) for c in counts.values())

        freqs = [counts.get(i, 0) for i in range(256)]
        mean = sum(freqs) / 256
        var = sum((f - mean) ** 2 for f in freqs) / 256
        skew = sum(((f - mean) / (math.sqrt(var) + 1e-8)) ** 3 for f in freqs) / 256

        # Ek analizler
        null_byte_ratio = data.count(0x00) / len(data)
        ascii_ratio = sum(32 <= b <= 126 for b in data) / len(data)
        high_byte_ratio = sum(b > 127 for b in data) / len(data)

        score = 0.0

        # Entropi eğer yüksekse puan ver
        if entropy > 7.8:
            score += 0.7
        elif entropy > 7.5:
            score += 0.5
        elif entropy > 7.2:
            score += 0.3

        # Skew düşükse dağılım düzgünse şifreli olabilir
        if abs(skew) < 0.3:
            score += 0.2

        # Null byte azsa şifreli olabilir
        if null_byte_ratio < 0.01:
            score += 0.1

        # ASCII oranı düşükse şifreli olabilir
        if ascii_ratio < 0.4:
            score += 0.1

        # High byte yoğunluğu yüksekse şifreli olabilir
        if high_byte_ratio > 0.3:
            score += 0.1

        ext = os.path.splitext(file_path)[1].lower()

        # Bazı formatlar doğası gereği yüksek entropy gösterebilir, puanı azalt
        if ext in HIGH_ENTROPY_FORMATS and entropy > 7.2:
            score -= 0.2

        # Uzantı şifreli formatlardan biriyse ekstra puan
        if ext in ENC_EXT:
            score += 0.2

        is_encrypted = score > 0.7
        confidence = min(1.0, max(0.0, score))
        return is_encrypted, confidence
