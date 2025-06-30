# Password Protection & Encryption Detector Async Version

## Overview

A powerful Python tool to detect password-protected and encrypted files across a variety of formats using format-specific handlers and entropy-based analysis.

%100 Accuracy on 180 Test Cases for Password Protection.
%92.78 Accuracy on 180 Test Cases for Encryption Detection.

## Key Features

- **Multi-format support**: Detects password protection in 10+ file formats
- **Hybrid detection**: Combines format-specific checks with entropy analysis
- **High performance**: Uses asynchronous I/O and multi-threading for fast scanning
- **Confidence scoring**: Provides confidence levels for detection results
- **Batch processing**: Can scan entire directories recursively

## Supported File Formats

| Format            | Detection Method                          |
|-------------------|-------------------------------------------|
| Office OpenXML    | msoffcrypto library + ZIP structure       |
| Office Legacy     | olefile library + OLE stream analysis     |
| PDF               | PyPDF2/pikepdf libraries                  |
| ZIP/RAR/7z        | Native Python libraries                   |
| SQLite            | Database header analysis                  |
| PST/MSG           | pypff/extract_msg libraries               |
| LibreOffice       | Manifest.xml + content analysis           |
| Other files       | Entropy-based detection fallback          |

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/password-detector.git
   cd password-detector
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

   Optional dependencies (for enhanced detection):
   ```bash
   pip install msoffcrypto-tool PyPDF2 pikepdf rarfile py7zr pypff extract_msg olefile
   ```

3. Install Magika (for file type detection):
   ```bash
   pip install magika
   ```

## Usage

### Basic Usage

Scan a single file:
```bash
python main.py /path/to/file.pdf
```

Scan a directory (recursively):
```bash
python main.py /path/to/directory --batch
```

### Output Format

The tool outputs results in the following format:
```
[file_path]: [STATUS] (Encrypted: [True/False], Confidence: [0.00-1.00], Time: [duration]s)
```

Example:
```
/document.docx: NOT PASSWORD PROTECTED (Encrypted: False, Confidence: 1.00, Time: 0.0456s)
/secret.xlsx: PASSWORD PROTECTED (Encrypted: True, Confidence: 0.95, Time: 0.1287s)
```

## Configuration

The tool automatically scales to use available system resources. For manual configuration:

- Thread count is determined by CPU cores (default: 2x cores + 4)
- Sample size for entropy analysis: 8KB (configurable in `entropy.py`)

## Limitations

- Cannot crack passwords - only detects protection
- Some encrypted files may be missed if they don't exhibit high entropy
- Certain proprietary formats may require additional libraries

## Contributing

Contributions are welcome! Please open an issue or pull request for:
- New file format handlers
- Improved detection algorithms
- Performance optimizations
