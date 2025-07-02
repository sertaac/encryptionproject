# EncryptionProject/password_detector_package/entropy.py #

import os
import math
from typing import Tuple
from collections import Counter

# High-entropy file extensions (likely encrypted) #
ENC_EXT = {'.gpg', '.enc', '.aes', '.crypt', '.pgp'}
# Formats that naturally exhibit high entropy (e.g., compressed files) #
HIGH_ENTROPY_FORMATS = {'.docx', '.xlsx', '.pptx', '.ods', '.odt', '.odp', '.odg', '.odf', '.odm'}


class EntropyAnalyzer:
    """Analyzes file entropy and statistical features to detect encryption."""

    @staticmethod
    def analyze(file_path: str, sample_size: int = 8192) -> Tuple[bool, float]:
        """
        Analyze file entropy and byte distribution to detect encryption.
        
        Args:
            file_path (str): File to analyze.
            sample_size (int): Bytes to sample (default: 8KB).
        
        Returns:
            Tuple[bool, float]: (is_encrypted, confidence_score)
        """
        try:
            with open(file_path, 'rb') as f:
                data = f.read(sample_size)
        except Exception:
            return False, 0.0

        if not data:
            return False, 0.0

        counts = Counter(data)
        # Avoid math.log2(0) by filtering out zero counts if any #
        entropy = -sum((c / len(data)) * math.log2(c / len(data)) for c in counts.values() if c > 0)

        freqs = [counts.get(i, 0) for i in range(256)]
        mean = sum(freqs) / 256
        var = sum((f - mean) ** 2 for f in freqs) / 256
        # Avoid division by zero if var is 0 (e.g. all bytes are same) #
        skew = sum(((f - mean) / (math.sqrt(var) + 1e-8)) ** 3 for f in freqs) / 256

        null_byte_ratio = data.count(0x00) / len(data)
        ascii_ratio = sum(32 <= b <= 126 for b in data) / len(data)
        high_byte_ratio = sum(b > 127 for b in data) / len(data)

        score = 0.0
        if entropy > 7.8:
            score += 0.7
        elif entropy > 7.5:
            score += 0.5
        elif entropy > 7.2:
            score += 0.3

        if abs(skew) < 0.3:
            score += 0.2

        if null_byte_ratio < 0.01:
            score += 0.1

        if ascii_ratio < 0.4:
            score += 0.1

        if high_byte_ratio > 0.3:
            score += 0.1

        ext = os.path.splitext(file_path)[1].lower()
        if ext in HIGH_ENTROPY_FORMATS and entropy > 7.2:
            score -= 0.2

        if ext in ENC_EXT:
            score += 0.2

        is_encrypted = score > 0.7
        confidence = min(1.0, max(0.0, score))
        return is_encrypted, confidence
