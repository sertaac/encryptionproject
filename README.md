-----

# Password Protection & Encryption Detector

A high-performance Python tool for detecting password protection and encryption in various file formats. It is designed with asynchronous I/O to scan files with maximum efficiency, and also provides a synchronous mode for simple, sequential processing.

[](https://www.python.org/downloads/)
[](https://opensource.org/licenses/MIT)
[](https://www.google.com/search?q=https://badge.fury.io/py/password-protection-detector)

This project is licensed under the MIT License. It uses several third-party libraries, each of which retains its own license. Please see the `setup.py` file for a full list of dependencies.

## Features

  - **Multi-Format Support**: Detects password protection in modern and legacy file formats including Office, PDF, various archives, and more.
  - **Hybrid Detection**: Combines fast, format-specific metadata checks with a fallback to statistical entropy analysis for unknown file types.
  - **High-Performance Async Mode**: The default mode uses asynchronous I/O and a thread pool to scan large numbers of files concurrently, ideal for batch processing.
  - **True Synchronous Mode**: Provides a synchronous wrapper that processes files sequentially, one-by-one. Useful for simpler scripts or as a performance baseline.
  - **Confidence Scoring**: Provides a confidence score (0.0 to 1.0) for each detection result.
  - **CLI and API Access**: Can be used as a flexible command-line tool or imported directly into your Python projects.

## Supported File Formats

| Format Group | Detection Method |
| --- | --- |
| Office OpenXML (.docx, .xlsx, .pptx) | `msoffcrypto` + ZIP structure analysis |
| Office Legacy (.doc, .xls, .ppt) | `olefile` stream analysis |
| PDF | `PyPDF2` / `pikepdf` encryption flag checks |
| Archives (.zip, .rar, .7z) | Native library checks for encryption flags |
| SQLite (.sqlite, .db) | Attempting a connection to check for encryption errors |
| Outlook Data (.pst, .msg) | `pypff` and `olefile` for encryption metadata |
| LibreOffice (.odt, .ods, etc.) | `manifest.xml` encryption data analysis |
| Other File Types | Fallback to file entropy and byte distribution analysis |

## Installation

The tool is available on PyPI and can be installed with pip:

```bash
pip install password-protection-detector
```

To install from the source, clone the repository and install locally:

```bash
git clone https://github.com/sertaac/encryptionproject.git
cd encryptionproject
pip install .
```

The required dependencies like `magika`, `msoffcrypto-tool`, `PyPDF2`, `pikepdf`, `rarfile`, `py7zr`, `pypff`, and `olefile` will be installed automatically.

## Usage

### Command-Line Interface

The CLI is made available through the `run-detector` script.

**Scan a single file:**

```bash
run-detector "path/to/my document.pdf"
```

**Scan an entire directory recursively (fast, asynchronous mode):**

```bash
run-detector "path/to/directory" --batch
```

**Run in synchronous mode (slower, one-by-one processing):**

```bash
run-detector "path/to/directory" --batch --sync
```

### Python API

The package provides two main classes: `PasswordProtectionDetector` for asynchronous operations and `SynchronousPasswordProtectionDetector` for blocking, sequential operations.

**Asynchronous Usage (Recommended for performance):**

```python
import asyncio
from concurrent.futures import ThreadPoolExecutor
from password_detector_package import PasswordProtectionDetector

async def main():
    # A single ThreadPoolExecutor can be shared across many calls
    with ThreadPoolExecutor() as executor:
        detector = PasswordProtectionDetector(executor)
        
        # Analyze a directory concurrently
        results = await detector.scan_directory("path/to/directory")
        for result in results:
            if result and result.get('password_protected'):
                print(f"Protected file found: {result['file']}")

asyncio.run(main())
```

**Synchronous Usage (Simpler for basic scripts):**

```python
from concurrent.futures import ThreadPoolExecutor
from password_detector_package import SynchronousPasswordProtectionDetector

# A single ThreadPoolExecutor can be shared across many calls
with ThreadPoolExecutor() as executor:
    detector = SynchronousPasswordProtectionDetector(executor)

    # analyze_file() blocks until the result is ready
    result = detector.analyze_file("path/to/file.docx")
    print(result)

    # scan_directory() processes files one by one
    all_results = detector.scan_directory("path/to/directory")
    print(f"Scanned {len(all_results)} files sequentially.")
```

## Performance Considerations

  - **Asynchronous (Default)**: This mode is significantly faster for directories with many files. It uses `asyncio.gather` to launch analysis tasks for all files at once, with I/O-heavy operations running in parallel on a thread pool. Your bottleneck becomes system resources, not the script's ability to process files sequentially.
  - **Synchronous (`--sync`)**: This mode is intentionally sequential and therefore much slower for large directories. It is useful when you need a simple, blocking function call or wish to integrate into a non-async codebase without managing an event loop.
  - **Thread Pool**: The application uses a `ThreadPoolExecutor` with a default of `max(32, cpu_cores * 2 + 4)` workers to prevent I/O from blocking execution.

## Project Structure

```
encryptionproject/
├── password_detector_package/    # The core installable package
│   ├── __init__.py               # Exposes the main detector classes
│   ├── detector.py               # Main async detector and logic
│   ├── sync_detector.py          # The synchronous wrapper class
│   ├── file_handlers.py          # Format-specific detection logic
│   ├── entropy.py                # Entropy analysis fallback
│   ├── magika_detector.py        # File type detection with Google's Magika
│   └── type_utils.py             # Utility for mapping file types
├── scripts/
│   └── run_detector.py           # The command-line interface entry point
├── setup.py                      # Packaging and dependency configuration
└── README.md

encryptionproject/
├── EncryptionProject/                   # Current production version
│ ├── password_detector_package/         # The core installable package
│ │ ├── init.py                          # Package exports
│ │ ├── detector.py                      # Main detector class with async support
│ │ ├── sync_detector.py                 # The synchronous wrapper class
│ │ ├── entropy.py                       # Entropy analysis implementation
│ │ ├── file_handlers.py                 # Format-specific handlers (10+ formats)
│ │ ├── magika_detector.py               # File type detection using Google's Magika
│ │ └── type_utils.py                    # Type detection utilities
│ ├── scripts/
│ │ └── run_detector.py                  # CLI entry point with both sync/async modes
│ └── setup.py                           # Package configuration and dependencies
│ │ ├── password_detector_package/       # Core detection logic package
│ │ ├── scripts/                         # CLI implementation
│ │ └── setup.py                         # Package configuration
├── documents/                           # Project documentation 
├── olderfiles/                          # Legacy versions
│ ├── v1Final/                           # Initial synchronous version
│ └── v2withAsync/                       # First async implementation
│ └── olddocuments/                      # Older documentations
├── README.md
└── LICENSE
```

## Limitations

  - The tool **detects** password protection; it does not crack or remove passwords.
  - Detection confidence may be lower for heavily compressed (but not encrypted) file formats that naturally have high entropy. The tool attempts to adjust for known formats.
  - Proprietary or rare encrypted formats may not be recognized and will only be flagged if they exhibit high entropy.

## Contributing

Contributions are welcome\! Please open an issue or submit a pull request for:

  - Handlers for new file formats.
  - Improvements to detection algorithms and confidence scoring.
  - Performance optimizations.

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.
