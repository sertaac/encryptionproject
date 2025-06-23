# password_detector/file_handlers.py (GÜNCELLENMİŞ)

import os
import zipfile
import sqlite3

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


# HANDLER SINIFLARI

class OfficeOpenXMLHandler:
    @staticmethod
    def is_encrypted(file_path):
        if not MSOFFCRYPTO_AVAILABLE:
            return False, False, 0.0
        try:
            with open(file_path, 'rb') as f:
                office_file = msoffcrypto.OfficeFile(f)
                if office_file.is_encrypted():
                    return True, False, 1.0
        except Exception:
            pass

        # Fallback: ZIP içinde EncryptedPackage varsa içerik şifreli olabilir
        try:
            with zipfile.ZipFile(file_path) as zf:
                if 'EncryptedPackage' in zf.namelist():
                    return True, True, 1.0
        except Exception:
            pass

        return False, False, 0.0

class OfficeLegacyHandler(OfficeOpenXMLHandler):
    pass

class PDFHandler:
    @staticmethod
    def is_encrypted(file_path):
        if PDF2_AVAILABLE:
            try:
                with open(file_path, 'rb') as f:
                    reader = PdfReader(f)
                    if reader.is_encrypted:
                        return True, True, 1.0
            except PdfReadError:
                pass
            except Exception:
                return False, False, 0.0

        if PIKEPDF_AVAILABLE:
            try:
                with Pdf.open(file_path) as pdf:
                    if pdf.is_encrypted:
                        return True, True, 1.0
            except PasswordError:
                return True, True, 1.0
            except Exception:
                pass

        return False, False, 0.0

class ZIPHandler:
    @staticmethod
    def is_encrypted(file_path):
        try:
            with zipfile.ZipFile(file_path) as zf:
                for file_info in zf.infolist():
                    if file_info.flag_bits & 0x1:
                        return True, True, 1.0
                return False, False, 1.0
        except zipfile.BadZipFile:
            try:
                with zipfile.ZipFile(file_path) as zf:
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

class RARHandler:
    @staticmethod
    def is_encrypted(file_path):
        if not RARFILE_AVAILABLE:
            return False, False, 0.0
        try:
            with rarfile.RarFile(file_path) as rf:
                return rf.needs_password(), rf.needs_password(), 1.0
        except Exception:
            return False, False, 0.0

class SevenZipHandler:
    @staticmethod
    def is_encrypted(file_path):
        if not PY7ZR_AVAILABLE:
            return False, False, 0.0
        try:
            with py7zr.SevenZipFile(file_path) as z7:
                return z7.needs_password(), z7.needs_password(), 1.0
        except Exception:
            return False, False, 0.0

class SQLiteHandler:
    @staticmethod
    def is_encrypted(file_path):
        try:
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
    @staticmethod
    def is_encrypted(file_path):
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
    @staticmethod
    def is_encrypted(file_path):
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
    @staticmethod
    def is_encrypted(file_path):
        try:
            with zipfile.ZipFile(file_path) as zf:
                if 'settings.xml' in zf.namelist():
                    settings_data = zf.read('settings.xml').decode('utf-8', errors='ignore')
                    if 'config:config-item config:name="ProtectionKey"' in settings_data:
                        return True, True, 1.0
        except Exception:
            pass
        return False, False, 0.0
