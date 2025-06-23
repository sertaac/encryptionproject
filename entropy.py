# password_detector/entropy.py #

import os
import math
from collections import Counter
from typing import Tuple


# High-entropy file extensions (likely encrypted) #
ENC_EXT = {'.gpg', '.enc', '.aes', '.crypt', '.pgp'}
# Formats that naturally exhibit high entropy (e.g., compressed files) #
HIGH_ENTROPY_FORMATS = {'.docx', '.xlsx', '.pptx', '.ods'}


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
        # --- Read File Sample --- #
        try:
            with open(file_path, 'rb') as f:
                data = f.read(sample_size)
        except Exception:
            return False, 0.0

        if not data:
            return False, 0.0

        # --- Entropy Calculation --- #
        counts = Counter(data)
        entropy = -sum((c / len(data)) * math.log2(c / len(data)) for c in counts.values())

        # --- Statistical Features --- #
        freqs = [counts.get(i, 0) for i in range(256)]
        mean = sum(freqs) / 256
        var = sum((f - mean) ** 2 for f in freqs) / 256
        skew = sum(((f - mean) / (math.sqrt(var) + 1e-8)) ** 3 for f in freqs) / 256

        # --- Byte Distribution Analysis --- #
        null_byte_ratio = data.count(0x00) / len(data)
        ascii_ratio = sum(32 <= b <= 126 for b in data) / len(data)
        high_byte_ratio = sum(b > 127 for b in data) / len(data)

        # --- Scoring Logic --- #
        score = 0.0
        if entropy > 7.8:  # Very high entropy → strong encryption signal #
            score += 0.7
        elif entropy > 7.5:
            score += 0.5
        elif entropy > 7.2:
            score += 0.3

        if abs(skew) < 0.3:  # Uniform byte distribution → encryption likely #
            score += 0.2

        if null_byte_ratio < 0.01:  # Few null bytes → encryption likely #
            score += 0.1

        if ascii_ratio < 0.4:  # Low ASCII content → encryption likely #
            score += 0.1

        if high_byte_ratio > 0.3:  # High non-ASCII bytes → encryption likely #
            score += 0.1

        # --- Format-Specific Adjustments --- #
        ext = os.path.splitext(file_path)[1].lower()
        if ext in HIGH_ENTROPY_FORMATS and entropy > 7.2:
            score -= 0.2  # Reduce false positives for known high-entropy formats #

        if ext in ENC_EXT:  # Known encrypted extensions → boost confidence #
            score += 0.2

        # --- Final Decision --- #
        is_encrypted = score > 0.7
        confidence = min(1.0, max(0.0, score))
        return is_encrypted, confidence