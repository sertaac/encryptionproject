# EncryptionProject/password_detector_package/file_handlers.py #

import os
import zipfile
import sqlite3
import asyncio 

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

# ========== HANDLER CLASSES ========== #

class OfficeOpenXMLHandler:
    """Handler for modern Office files (.docx, .xlsx, .pptx)"""
    
    @staticmethod
    async def is_encrypted(file_path: str):
        def _check_openxml_blocking(path):
            if not MSOFFCRYPTO_AVAILABLE:
                return False, False, 0.0
            try:
                with open(path, 'rb') as f:
                    office_file = msoffcrypto.OfficeFile(f)
                    
                    if not office_file.is_encrypted():
                        return False, False, 1.0
                    
                    try:
                        office_file.load_key(password='')
                        return False, True, 0.8
                    except (msoffcrypto.exceptions.InvalidKeyError, 
                           msoffcrypto.exceptions.DecryptionError):
                        return True, True, 1.0
                        
            except Exception:
                try:
                    with zipfile.ZipFile(path) as zf:
                        if 'EncryptedPackage' in zf.namelist():
                            return True, True, 1.0
                        if 'docProps/core.xml' in zf.namelist():
                            core_data = zf.read('docProps/core.xml').decode('utf-8', errors='ignore')
                            if 'DocumentProtection' in core_data:
                                return True, False, 0.9
                except Exception:
                    pass

            return False, False, 0.0
        
        return await asyncio.to_thread(_check_openxml_blocking, file_path)


class OfficeLegacyHandler:
    """Handler for older Office files (.doc, .xls, .ppt)."""

    @staticmethod
    async def is_encrypted(file_path: str):
        def _check_legacy_blocking(path):
            if not OLEFILE_AVAILABLE:
                return False, False, 0.0
            try:
                with olefile.OleFileIO(path) as ole:
                    if ole.exists('EncryptionInfo') or ole.exists('EncryptedPackage'):
                        return True, True, 1.0
                    if ole.exists('\x01CompObj') and ole.exists('\x05SummaryInformation'):
                        return False, False, 0.5
            except Exception:
                pass
            return False, False, 0.0
        
        return await asyncio.to_thread(_check_legacy_blocking, file_path)


class PDFHandler:
    """Handler for PDF files"""
    
    @staticmethod
    async def is_encrypted(file_path: str):
        def _check_pdf_blocking(path):
            if not (PDF2_AVAILABLE or PIKEPDF_AVAILABLE):
                return False, False, 0.0

            if PDF2_AVAILABLE:
                try:
                    with open(path, 'rb') as f:
                        reader = PdfReader(f)
                        if reader.is_encrypted:
                            try:
                                if len(reader.pages) > 0:
                                    return False, True, 0.8
                            except Exception:
                                return True, True, 1.0
                        return False, False, 1.0
                except PdfReadError as e:
                    if "password required" in str(e).lower():
                        return True, True, 1.0
                    return False, False, 0.0
                except Exception:
                    pass

            if PIKEPDF_AVAILABLE:
                try:
                    with Pdf.open(path) as pdf:
                        if pdf.is_encrypted:
                            try:
                                pdf.pages[0]
                                return False, True, 0.8
                            except PasswordError:
                                return True, True, 1.0
                    return False, False, 1.0
                except Exception:
                    pass

            return False, False, 0.0
        
        return await asyncio.to_thread(_check_pdf_blocking, file_path)


class ZIPHandler:
    """Handler for ZIP archive files."""

    @staticmethod
    async def is_encrypted(file_path: str):
        def _check_zip_blocking(path):
            try:
                with zipfile.ZipFile(path, 'r') as zf:
                    for file_info in zf.infolist():
                        if file_info.flag_bits & 0x1:
                            return True, True, 1.0
                    return False, False, 1.0
            except zipfile.BadZipFile:
                try:
                    with zipfile.ZipFile(path) as zf:
                        first_file = zf.infolist()[0]
                        with zf.open(first_file) as f:
                            f.read(1)
                except RuntimeError as e:
                    if 'encrypted' in str(e).lower():
                        return True, True, 1.0
                except Exception:
                    pass
            except Exception:
                pass
                
            return False, False, 0.0
        
        return await asyncio.to_thread(_check_zip_blocking, file_path)


class RARHandler:
    """Handler for RAR archives"""
    
    @staticmethod
    async def is_encrypted(file_path: str):
        def _check_rar_blocking(path):
            if not RARFILE_AVAILABLE:
                return False, False, 0.0
            try:
                with rarfile.RarFile(path, 'r') as rf:
                    needs_pass = rf.needs_password()
                    return needs_pass, needs_pass, 1.0
            except Exception:
                return False, False, 0.0
        
        return await asyncio.to_thread(_check_rar_blocking, file_path)


class SevenZipHandler:
    """Handler for 7z archives"""
    
    @staticmethod
    async def is_encrypted(file_path: str):
        def _check_7z_blocking(path):
            if not PY7ZR_AVAILABLE:
                return False, False, 0.0
                
            try:
                with py7zr.SevenZipFile(path, mode='r') as z7:
                    needs_pass = z7.needs_password()
                    return needs_pass, needs_pass, 1.0
            except Exception:
                return False, False, 0.0
        
        return await asyncio.to_thread(_check_7z_blocking, file_path)


class SQLiteHandler:
    """Handler for SQLite databases"""
    
    @staticmethod
    async def is_encrypted(file_path: str):
        def _check_sqlite_blocking(path):
            try:
                conn = sqlite3.connect(f'file:{path}?mode=ro', uri=True)
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
        
        return await asyncio.to_thread(_check_sqlite_blocking, file_path)


class PSTHandler:
    """Handler for Outlook PST files"""
    
    @staticmethod
    async def is_encrypted(file_path: str):
        def _check_pst_blocking(path):
            if not PYPFF_AVAILABLE:
                return False, False, 0.0
                
            try:
                pst = pypff.file()
                pst.open(path)
                pst.close()
                return False, False, 1.0
            except pypff.Error as e:
                if 'password' in str(e).lower() or 'encrypted' in str(e).lower():
                    return True, True, 1.0
            except Exception:
                pass
                
            return False, False, 0.0
        
        return await asyncio.to_thread(_check_pst_blocking, file_path)


class MSGHandler:
    """Handler for Outlook MSG files"""
    
    @staticmethod
    async def is_encrypted(file_path: str):
        def _check_msg_blocking(path):

            if OLEFILE_AVAILABLE:
                try:
                    ole = olefile.OleFileIO(path)
                    if ole.exists('EncryptedSummary'):
                        ole.close()
                        return True, True, 0.9
                    ole.close()
                except Exception:
                    pass

            return False, False, 0.0
        
        return await asyncio.to_thread(_check_msg_blocking, file_path)


class LibreOfficeHandler:
    """Handler for LibreOffice files (.ods, .odt, .odp, .odm)"""
    
    @staticmethod
    async def is_encrypted(file_path: str):
        def _check_libreoffice_blocking(path):
            try:
                with zipfile.ZipFile(path) as zf:
                    if 'META-INF/manifest.xml' in zf.namelist():
                        manifest = zf.read('META-INF/manifest.xml').decode('utf-8', errors='ignore')
                        if 'manifest:encryption-data' in manifest:
                            return True, True, 1.0
                    
                    try:
                        if 'content.xml' in zf.namelist():
                            zf.read('content.xml')
                        return False, False, 1.0
                    except RuntimeError as e:
                        if 'encrypted' in str(e).lower():
                            return True, True, 1.0
            except Exception:
                pass
                
            return False, False, 0.0
        
        return await asyncio.to_thread(_check_libreoffice_blocking, file_path)
