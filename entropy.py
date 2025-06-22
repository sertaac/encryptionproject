# password_detector/entropy.py

import os
import math
from collections import Counter
from typing import Tuple


# High-entropy file extensions (likely encrypted)
ENC_EXT = {'.gpg', '.enc', '.aes', '.crypt', '.pgp'}


class EntropyAnalyzer:
    """Analyzes file entropy to detect encryption likelihood."""
    
    @staticmethod
    def analyze(file_path: str, sample_size: int = 8192) -> Tuple[bool, float]:
        """
        Calculate Shannon entropy and statistical features to detect encryption.
        
        Args:
            file_path (str): File to analyze.
            sample_size (int): Bytes to sample (default: 8KB).
        
        Returns:
            Tuple[bool, float]: (is_encrypted, confidence_score)
        """
        # --- Read File Sample ---
        try:
            with open(file_path, 'rb') as f:
                data = f.read(sample_size)
        except Exception:
            return False, 0.0

        if not data:
            return False, 0.0

        # --- Entropy Calculation ---
        counts = Counter(data)
        entropy = -sum((c / len(data)) * math.log2(c / len(data)) for c in counts.values())

        # --- Statistical Features ---
        freqs = [counts.get(i, 0) for i in range(256)]
        mean = sum(freqs) / 256
        var = sum((f - mean) ** 2 for f in freqs) / 256
        skew = sum(((f - mean) / (math.sqrt(var) + 1e-8)) ** 3 for f in freqs) / 256

        # --- Scoring Logic ---
        score = 0.0
        if entropy > 7.5:  # High entropy → likely encrypted
            score += 0.6
        elif entropy > 7.2:
            score += 0.3

        if abs(skew) < 0.3:  # Low skew → uniform byte distribution
            score += 0.2

        # Extension-based boost
        ext = os.path.splitext(file_path)[1].lower()
        if ext in ENC_EXT:
            score += 0.2

        return score > 0.7, min(1.0, max(0.0, score))