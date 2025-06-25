# password_detector/file_handlers.py #

import os
import zipfile
import sqlite3

# --- Optional Dependency Checks --- #
# Check for availability of third-party libraries with graceful fallbacks #

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


# ========== HANDLER CLASSES ========== #

class OfficeOpenXMLHandler:
    """Handler for modern Office files (.docx, .xlsx, .pptx)"""
    
    def is_encrypted(file_path):
        """
        Check if Office OpenXML file is password protected with more precise detection.
        """
        if not MSOFFCRYPTO_AVAILABLE:
            return False, False, 0.0
            
        try:
            with open(file_path, 'rb') as f:
                office_file = msoffcrypto.OfficeFile(f)
                
                # First check if file is encrypted
                if not office_file.is_encrypted():
                    return False, False, 1.0
                
                # If encrypted, try to determine if it's password protected
                try:
                    # Try to decrypt with empty password
                    office_file.load_key(password='')
                    # If succeeds, it's encrypted but not password protected
                    return False, True, 0.8
                except (msoffcrypto.exceptions.InvalidKeyError, 
                       msoffcrypto.exceptions.DecryptionError):
                    # If fails, it's password protected
                    return True, True, 1.0
                    
        except Exception:
            # Fallback ZIP structure check
            try:
                with zipfile.ZipFile(file_path) as zf:
                    # Check for specific protection indicators
                    if 'EncryptedPackage' in zf.namelist():
                        return True, True, 1.0
                    if 'docProps/core.xml' in zf.namelist():
                        core_data = zf.read('docProps/core.xml').decode('utf-8', errors='ignore')
                        if 'DocumentProtection' in core_data:
                            return True, False, 0.9
            except Exception:
                pass

        return False, False, 0.0


class OfficeLegacyHandler(OfficeOpenXMLHandler):
    """Handler for legacy Office files (.doc, .xls, .ppt)"""
    pass


class PDFHandler:
    """Handler for PDF files"""
    
    def is_encrypted(file_path):
        """
        Check if PDF is password protected using available libraries.
        
        Args:
            file_path (str): Path to PDF file
            
        Returns:
            Tuple[bool, bool, float]: 
                (password_protected, encrypted, confidence)
        """
        # Try PyPDF2 first
        if PDF2_AVAILABLE:
            try:
                with open(file_path, 'rb') as f:
                    reader = PdfReader(f)
                    if reader.is_encrypted:
                        # Try to determine if password is actually required
                        try:
                            if len(reader.pages) > 0:  # If we can access pages
                                return False, True, 0.8  # Encrypted but not password protected
                        except Exception:
                            return True, True, 1.0  # Password protected
            except Exception:
                pass

        # Fallback to pikepdf
        if PIKEPDF_AVAILABLE:
            try:
                with Pdf.open(file_path) as pdf:
                    if pdf.is_encrypted:
                        try:
                            pdf.pages[0]  # Try accessing content
                            return False, True, 0.8
                        except PasswordError:
                            return True, True, 1.0
            except Exception:
                pass

        return False, False, 0.0


class ZIPHandler:
    """Handler for ZIP archives"""
    
    def is_encrypted(file_path):
        """
        Check if ZIP contains encrypted files.
        
        Args:
            file_path (str): Path to ZIP file
            
        Returns:
            Tuple[bool, bool, float]: 
                (password_protected, encrypted, confidence)
        """
        try:
            with zipfile.ZipFile(file_path) as zf:
                # Check each file's encryption flag #
                for file_info in zf.infolist():
                    if file_info.flag_bits & 0x1:  # Encryption flag #
                        return True, True, 1.0
                return False, False, 1.0  # No encryption found #
        except zipfile.BadZipFile:
            # Fallback for corrupted ZIPs #
            try:
                with zipfile.ZipFile(file_path) as zf:
                    first_file = zf.infolist()[0]
                    with zf.open(first_file) as f:
                        f.read(1)  # Try reading first byte #
            except RuntimeError as e:
                if 'encrypted' in str(e).lower():
                    return True, True, 1.0
            except Exception:
                pass
        except Exception:
            pass
            
        return False, False, 0.0


class RARHandler:
    """Handler for RAR archives"""
    
    def is_encrypted(file_path):
        """
        Check if RAR is password protected.
        
        Args:
            file_path (str): Path to RAR file
            
        Returns:
            Tuple[bool, bool, float]: 
                (password_protected, encrypted, confidence)
        """
        if not RARFILE_AVAILABLE:
            return False, False, 0.0
            
        try:
            with rarfile.RarFile(file_path) as rf:
                needs_pass = rf.needs_password()
                return needs_pass, needs_pass, 1.0
        except Exception:
            return False, False, 0.0


class SevenZipHandler:
    """Handler for 7z archives"""
    
    def is_encrypted(file_path):
        """
        Check if 7z archive is password protected.
        
        Args:
            file_path (str): Path to 7z file
            
        Returns:
            Tuple[bool, bool, float]: 
                (password_protected, encrypted, confidence)
        """
        if not PY7ZR_AVAILABLE:
            return False, False, 0.0
            
        try:
            with py7zr.SevenZipFile(file_path) as z7:
                needs_pass = z7.needs_password()
                return needs_pass, needs_pass, 1.0
        except Exception:
            return False, False, 0.0


class SQLiteHandler:
    """Handler for SQLite databases"""
    
    def is_encrypted(file_path):
        """
        Check if SQLite database is encrypted.
        
        Args:
            file_path (str): Path to SQLite file
            
        Returns:
            Tuple[bool, bool, float]: 
                (password_protected, encrypted, confidence)
        """
        try:
            # Try to read database structure #
            conn = sqlite3.connect(f'file:{file_path}?mode=ro', uri=True)
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' LIMIT 1;")
            cursor.fetchone()
            cursor.close()
            conn.close()
            return False, False, 1.0
        except sqlite3.DatabaseError as e:
            if 'encrypted' in str(e).lower() or 'not a database' in str(e).lower():
                return True, True, 1.0
        except Exception:
            pass
            
        return False, False, 0.0


class PSTHandler:
    """Handler for Outlook PST files"""
    
    def is_encrypted(file_path):
        """
        Check if PST file is password protected.
        
        Args:
            file_path (str): Path to PST file
            
        Returns:
            Tuple[bool, bool, float]: 
                (password_protected, encrypted, confidence)
        """
        if not PYPFF_AVAILABLE:
            return False, False, 0.0
            
        try:
            pst = pypff.file()
            pst.open(file_path)
            pst.close()
            return False, False, 1.0
        except pypff.Error as e:
            if 'password' in str(e).lower() or 'encrypted' in str(e).lower():
                return True, True, 1.0
        except Exception:
            pass
            
        return False, False, 0.0


class MSGHandler:
    """Handler for Outlook MSG files"""
    
    def is_encrypted(file_path):
        """
        Check if MSG file is encrypted.
        
        Args:
            file_path (str): Path to MSG file
            
        Returns:
            Tuple[bool, bool, float]: 
                (password_protected, encrypted, confidence)
        """
        if EXTRACT_MSG_AVAILABLE:
            try:
                msg = Message(file_path)
                msg.close()
                return False, False, 1.0
            except Exception as e:
                if 'encrypted' in str(e).lower():
                    return True, True, 1.0

        if OLEFILE_AVAILABLE:
            try:
                ole = olefile.OleFileIO(file_path)
                if ole.exists('EncryptedSummary'):
                    ole.close()
                    return True, True, 0.9
                ole.close()
            except Exception:
                pass

        return False, False, 0.0


class LibreOfficeHandler:
    """Handler for LibreOffice files (.ods, .odt, .odp, .odm)"""
    
    def is_encrypted(file_path):
        """
        Check if LibreOffice file is encrypted by inspecting its ZIP structure.
        
        Args:
            file_path (str): Path to LibreOffice file
            
        Returns:
            Tuple[bool, bool, float]: 
                (password_protected, encrypted, confidence)
        """
        try:
            with zipfile.ZipFile(file_path) as zf:
                # Check manifest for encryption
                if 'META-INF/manifest.xml' in zf.namelist():
                    manifest = zf.read('META-INF/manifest.xml').decode('utf-8', errors='ignore')
                    if 'manifest:encryption-data' in manifest:
                        return True, True, 1.0
                
                # Check content accessibility
                try:
                    if 'content.xml' in zf.namelist():
                        zf.read('content.xml')  # Try to read main content
                    return False, False, 1.0
                except RuntimeError as e:
                    if 'encrypted' in str(e).lower():
                        return True, True, 1.0
        except Exception:
            pass
            
        return False, False, 0.0    