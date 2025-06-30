# Password Protection & Encryption Detector

A high-performance Python tool for detecting password protection and encryption in various file formats, designed with asynchronous I/O operations for efficient scanning.

![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

## Features

- **Multi-format support**: Detects password protection in 10+ file formats
- **Hybrid detection**: Combines format-specific checks with entropy analysis
- **High performance**: Uses asynchronous I/O and multi-threading
- **Confidence scoring**: Provides confidence levels (0.0-1.0) for detection results
- **Batch processing**: Recursively scans directories with parallel processing
- **Unicode support**: Handles file paths with special characters
- **Optional sync mode**: Can run in synchronous mode if needed

## Supported File Formats

| Format            | Detection Method                          |
|-------------------|-------------------------------------------|
| Office OpenXML    | msoffcrypto + ZIP structure analysis      |
| Office Legacy     | olefile + OLE stream analysis             |
| PDF               | PyPDF2/pikepdf libraries                  |
| ZIP/RAR/7z        | Native Python libraries                   |
| SQLite            | Database header analysis                  |
| PST/MSG           | pypff/extract_msg libraries               |
| LibreOffice       | Manifest.xml + content analysis           |
| Other files       | Entropy-based detection fallback          |

## Installation

### From Source
1. Clone the repository:
```bash
git clone https://github.com/sertaac/encryptionproject.git
cd encryptionproject
```

2. Install with pip:
```bash
pip install .
```

### Optional Dependencies
For full format support, install optional dependencies:
```bash
pip install msoffcrypto-tool PyPDF2 pikepdf rarfile py7zr pypff olefile extract-msg
```

## Usage

### Command Line Interface

Scan a single file:
```bash
run-detector path/to/file.pdf
```

Scan a directory recursively:
```bash
run-detector path/to/directory --batch
```

Run in synchronous mode:
```bash
run-detector path/to/file --sync
```

### Python API
```python
from password_detector_package import PasswordProtectionDetector
from concurrent.futures import ThreadPoolExecutor
import asyncio

async def analyze_file(file_path):
    with ThreadPoolExecutor() as executor:
        detector = PasswordProtectionDetector(executor)
        result = await detector.analyze_file(file_path)
        print(result)
        
asyncio.run(analyze_file("test.docx"))
```

## Output Format

The tool outputs results in the following format:
```
[file_path]: [STATUS] (Encrypted: [True/False], Confidence: [0.00-1.00], Time: [duration]s)
```

Example:
```
/document.docx: NOT PASSWORD PROTECTED (Encrypted: False, Confidence: 1.00, Time: 0.0456s)
/secret.xlsx: PASSWORD PROTECTED (Encrypted: True, Confidence: 0.95, Time: 0.1287s)
```

## Performance Considerations

- By default uses asynchronous I/O with thread pool (2x CPU cores + 4 threads)
- For large directories (>10,000 files), batch mode is recommended
- Entropy analysis is performed as a fallback for low-confidence cases

## Project Structure

```
encryptionproject/
├── EncryptionProject/                   # Current production version
│ ├── password_detector_package/
│ │ ├── init.py                          # Package exports
│ │ ├── detector.py                      # Main detector class with async support
│ │ ├── entropy.py                       # Entropy analysis implementation
│ │ ├── file_handlers.py                 # Format-specific handlers (10+ formats)
│ │ ├── magika_detector.py               # File type detection using Google's Magika
│ │ └── type_utils.py                    # Type detection utilities
│ ├── scripts/
│ │ └── run_detector.py                  # CLI entry point with both sync/async modes
│ └── setup.py                           # Package configuration and dependencies
│ │ ├── password_detector_package/       # Core detection logic package
│ │ ├── scripts/                         # CLI implementation
│ │ └── setup.py                         # Package configuration
├── documents/                           # Project documentation and research
├── olderfiles/                          # Legacy versions
│ ├── v1Final/                           # Initial synchronous version
│ └── v2withAsync/                       # First async implementation
```

## Limitations

- Cannot crack passwords - only detects protection
- Some encrypted files may be missed if they don't exhibit high entropy
- Certain proprietary formats may require additional libraries

## Contributing

Contributions are welcome! Please open an issue or pull request for:
- New file format handlers
- Improved detection algorithms
- Performance optimizations

## License

MIT License - See LICENSE file for details.


---
This README includes:
1. Clear badges for Python version and license
2. Comprehensive feature list
3. Installation instructions for both PyPI and source
4. Usage examples for both CLI and Python API
5. Output format explanation
6. Performance considerations
7. Project structure overview
8. Limitations and contribution guidelines
9. License information
