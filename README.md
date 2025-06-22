# Password Protection & Encryption Detector 🔒

A powerful Python tool to detect password-protected and encrypted files across a variety of formats using format-specific handlers and entropy-based analysis.
- %100 Accuracy on 215 Test Cases for Password Protection.
- %70 Accuracy on 760 Test Cases for Encryption Detection.

---

## 🚀 Features

- **Multi-format support**: Office (modern & legacy), PDF, ZIP/RAR/7z, SQLite, PST/MSG.
- **Entropy analysis**: Detects potential encryption based on file randomness.
- **Recursive scanning**: Batch process entire directories.
- **Confidence scoring**: Each result includes a score from `0.0` (low) to `1.0` (high certainty).

---

## 📦 Installation

1. **Clone the repository**:

   ```bash
   git clone https://github.com/yourusername/password-detector.git
   cd password-detector
   ```

2. **Install dependencies**:

   ```bash
   pip install -r requirements.txt
   ```

3. *(Optional)*: For full handler support, install optional libraries:

   ```bash
   pip install msoffcrypto-tool pikepdf rarfile py7zr
   ```

---

## 🛠️ Usage

### Single file scan:

```bash
python main.py /path/to/file.pdf
```

### Directory scan (recursive):

```bash
python main.py /path/to/folder --batch
```

### Output Example:

```
/path/to/document.docx: PASSWORD PROTECTED (Encrypted: True, Conf: 0.95)
/path/to/data.zip: NOT PASSWORD PROTECTED (Encrypted: False, Conf: 0.10)
```

---

## 🔍 How It Works

- **File Type Detection**: Uses file extensions and Magika (machine learning-based) for fallback recognition.
- **Handler-Based Inspection**: Employs format-specific tools (e.g., `msoffcrypto-tool`, `pikepdf`).
- **Entropy Analysis**: Flags files with high randomness as potentially encrypted.

---

## 📂 Supported Formats

| Format    | Handlers                          |
| --------- | --------------------------------- |
| Office    | `.docx`, `.doc` via `msoffcrypto` |
| PDF       | `PyPDF2`, `pikepdf`               |
| Archives  | ZIP, RAR, 7z                      |
| Databases | SQLite                            |
| Email     | PST, MSG                          |

---

## ⚠️ Limitations

- **False positives/negatives**: Entropy isn't foolproof.
- **Handler availability**: Some formats require optional libraries (e.g., `rarfile` for RAR).

---

## 📄 License

This project is licensed under the **MIT License**. See the [LICENSE](LICENSE) file for details.

---

## 🔑 Key Notes

1. **Update URLs**: Replace `yourusername` with your actual GitHub username in links.
2. **Include **``: Ensure all required and optional dependencies are documented.
3. **Optional Libraries Matter**: Tools like `pikepdf` and `rarfile` greatly improve accuracy.

---

Contributions and feedback are welcome! ⭐