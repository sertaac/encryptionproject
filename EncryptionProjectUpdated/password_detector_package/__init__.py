# EncryptionProject/password_detector_package/__init__.py

from .detector import PasswordProtectionDetector
from .sync_detector import SynchronousPasswordProtectionDetector # Yeni import

__all__ = ['PasswordProtectionDetector', 'SynchronousPasswordProtectionDetector']