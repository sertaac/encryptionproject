# password_detector/file_handlers.py

import os
import zipfile
import sqlite3

# --- Optional Dependency Checks ---
# These try/except blocks check for optional dependencies and set availability flags
# This allows graceful fallback when specific libraries aren't installed

try:
    import msoffcrypto
    MSOFFCRYPTO_AVAILABLE = True
except ImportError:
    MSOFFCRYPTO_AVAILABLE = False

try:
    from PyPDF2 import PdfReader
    from PyPDF2.errors import PdfReadError
    PDF2_AVAILABLE = True
except ImportError:
    PDF2_AVAILABLE = False

try:
    import pikepdf
    from pikepdf import PasswordError, Pdf
    PIKEPDF_AVAILABLE = True
except ImportError:
    PIKEPDF_AVAILABLE = False

try:
    import rarfile
    RARFILE_AVAILABLE = True
except ImportError:
    RARFILE_AVAILABLE = False

try:
    import py7zr
    PY7ZR_AVAILABLE = True
except ImportError:
    PY7ZR_AVAILABLE = False

try:
    import pypff
    PYPFF_AVAILABLE = True
except ImportError:
    PYPFF_AVAILABLE = False

try:
    import olefile
    OLEFILE_AVAILABLE = True
except ImportError:
    OLEFILE_AVAILABLE = False

try:
    from extract_msg import Message
    EXTRACT_MSG_AVAILABLE = True
except ImportError:
    EXTRACT_MSG_AVAILABLE = False


# ========== HANDLER CLASSES ==========

class OfficeOpenXMLHandler:
    """Handler for modern Office file formats (.docx, .xlsx, .pptx)"""
    
    @staticmethod
    def is_encrypted(file_path):
        """
        Check if Office OpenXML file is password protected.
        
        Args:
            file_path (str): Path to the file to check
            
        Returns:
            tuple: (password_protected, encrypted, confidence)
                   where confidence is 1.0 if protected, 0.0 otherwise
        """
        if not MSOFFCRYPTO_AVAILABLE:
            return False, False, 0.0
        try:
            with open(file_path, 'rb') as f:
                office_file = msoffcrypto.OfficeFile(f)
                is_protected = office_file.is_encrypted()
                return is_protected, False, 1.0 if is_protected else 0.0
        except Exception:
            return False, False, 0.0


class OfficeLegacyHandler(OfficeOpenXMLHandler):
    """Handler for legacy Office formats (.doc, .xls, .ppt) - inherits from OpenXML handler"""
    pass


class PDFHandler:
    """Handler for PDF files with multiple detection methods"""
    
    @staticmethod
    def is_encrypted(file_path):
        """
        Check if PDF is encrypted using available PDF libraries.
        
        Tries PyPDF2 first, falls back to pikepdf if available.
        """
        # Try PyPDF2 first if available
        if PDF2_AVAILABLE:
            try:
                with open(file_path, 'rb') as f:
                    reader = PdfReader(f)
                    if reader.is_encrypted:
                        return True, True, 1.0
            except PdfReadError:
                pass  # Continue to next method
            except Exception:
                return False, False, 0.0

        # Fallback to pikepdf if available
        if PIKEPDF_AVAILABLE:
            try:
                with Pdf.open(file_path) as pdf:
                    if pdf.is_encrypted:
                        return True, True, 1.0
            except PasswordError:  # Specific exception for password-protected PDFs
                return True, True, 1.0
            except Exception:
                pass

        return False, False, 0.0


class ZIPHandler:
    """Handler for ZIP archive files"""
    
    @staticmethod
    def is_encrypted(file_path):
        """
        Check if ZIP file contains encrypted entries.
        
        Uses zipfile module to check both the central directory flags
        and attempts to read a file to detect encryption.
        """
        try:
            # Check central directory encryption flags
            with zipfile.ZipFile(file_path) as zf:
                for file_info in zf.infolist():
                    if file_info.flag_bits & 0x1:  # Check encryption bit
                        return True, True, 1.0
                # If no encrypted files found but archive is valid
                return False, False, 1.0
                
        except zipfile.BadZipFile:
            # If standard check fails, try reading first file
            try:
                with zipfile.ZipFile(file_path) as zf:
                    first_file = zf.infolist()[0]
                    with zf.open(first_file) as f:
                        f.read(1)  # Try reading 1 byte
            except RuntimeError as e:
                if 'encrypted' in str(e).lower():
                    return True, True, 1.0
            except Exception:
                pass
        except Exception:
            pass
            
        return False, False, 0.0


class RARHandler:
    """Handler for RAR archive files"""
    
    @staticmethod
    def is_encrypted(file_path):
        """Check if RAR file is password protected using rarfile module"""
        if not RARFILE_AVAILABLE:
            return False, False, 0.0
        try:
            with rarfile.RarFile(file_path) as rf:
                return rf.needs_password(), rf.needs_password(), 1.0
        except Exception:
            return False, False, 0.0


class SevenZipHandler:
    """Handler for 7-Zip archive files"""
    
    @staticmethod
    def is_encrypted(file_path):
        """Check if 7z file is password protected using py7zr module"""
        if not PY7ZR_AVAILABLE:
            return False, False, 0.0
        try:
            with py7zr.SevenZipFile(file_path) as z7:
                return z7.needs_password(), z7.needs_password(), 1.0
        except Exception:
            return False, False, 0.0


class SQLiteHandler:
    """Handler for SQLite database files"""
    
    @staticmethod
    def is_encrypted(file_path):
        """
        Check if SQLite database is encrypted by attempting to read it.
        
        Encrypted databases will raise a 'file is encrypted' or 'not a database' error.
        """
        try:
            # Try to open and query the database
            conn = sqlite3.connect(f'file:{file_path}?mode=ro', uri=True)
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' LIMIT 1;")
            cursor.fetchone()  # Attempt to read
            cursor.close()
            conn.close()
            return False, False, 1.0  # Success means not encrypted
        except sqlite3.DatabaseError as e:
            # Specific errors indicate encryption
            if 'encrypted' in str(e).lower() or 'not a database' in str(e).lower():
                return True, True, 1.0
        except Exception:
            pass
        return False, False, 0.0


class PSTHandler:
    """Handler for Outlook PST files"""
    
    @staticmethod
    def is_encrypted(file_path):
        """Check if PST file is encrypted using pypff module"""
        if not PYPFF_AVAILABLE:
            return False, False, 0.0
        try:
            pst = pypff.file()
            pst.open(file_path)
            pst.close()
            return False, False, 1.0  # Successfully opened means not encrypted
        except pypff.Error as e:
            if 'password' in str(e).lower() or 'encrypted' in str(e).lower():
                return True, True, 1.0
        except Exception:
            pass
        return False, False, 0.0


class MSGHandler:
    """Handler for Outlook MSG files"""
    
    @staticmethod
    def is_encrypted(file_path):
        """
        Check if MSG file is encrypted using either extract_msg or olefile.
        
        Tries extract_msg first, falls back to olefile if available.
        """
        # First try with extract_msg
        if EXTRACT_MSG_AVAILABLE:
            try:
                msg = Message(file_path)
                msg.close()
                return False, False, 1.0
            except Exception as e:
                if 'encrypted' in str(e).lower():
                    return True, True, 1.0

        # Fallback to olefile
        if OLEFILE_AVAILABLE:
            try:
                ole = olefile.OleFileIO(file_path)
                if ole.exists('EncryptedSummary'):
                    ole.close()
                    return True, True, 0.9  # Slightly lower confidence
                ole.close()
            except Exception:
                pass

        return False, False, 0.0