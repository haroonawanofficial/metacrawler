# 🚀 MetaCrawler: Universal Sensitive Data Extraction Platform

A comprehensive Python tool for extracting secrets, metadata, and sensitive data from **ALL file types**. Designed for security researchers, penetration testers, and developers to identify exposed sensitive information.

![Python](https://img.shields.io/badge/Python-3.7+-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)

## 🌟 Features

### 🔍 **Universal File Support**
- **📄 Documents**: PDF, DOC, DOCX, XLS, XLSX, PPT, PPTX
- **🖼️ Images**: JPG, PNG, GIF, BMP, TIFF, WEBP (with EXIF/metadata extraction)
- **📁 Archives**: ZIP, TAR, GZ, 7Z, RAR (recursive extraction)
- **🔐 Certificates**: PEM, KEY, CRT, CER
- **💻 Code**: JavaScript, PHP, HTML, CSS, JSON, XML
- **📊 Data**: CSV, TXT, LOG, SQL, Config files
- **🌐 Web**: All web-accessible file types

### 🛡️ **Comprehensive Pattern Detection**
- **API Keys**: Google, AWS, Stripe, GitHub, Slack, Twilio, SendGrid
- **Authentication**: JWT, OAuth, Bearer tokens, Session tokens
- **Cryptographic Material**: Private keys, SSH keys, PGP keys, Certificates
- **Database Connections**: MongoDB, PostgreSQL, MySQL, Redis, SQLite
- **PII**: Email addresses, Credit cards, SSN, Phone numbers, IP addresses
- **Web3/Blockchain**: Ethereum addresses, Bitcoin addresses, Private keys
- **Financial**: Bank accounts, SWIFT codes, IBAN
- **Medical**: Medical records, Health insurance
- **Government**: Passport numbers, Driver licenses

### 🌐 **Advanced Web Crawling**
- Intelligent website crawling with robots.txt respect
- Automatic file discovery from HTML content
- Configurable depth and limits
- Async concurrent processing

## 📦 Installation

### Full Installation (Recommended)
```bash
pip install aiohttp beautifulsoup4 PyPDF2 Pillow exifread olefile python-magic
```

## 🚀 Quick Start

### Analyze a Single File
```bash
python metacrawler.py -f document.pdf
```

### Crawl a Website
```bash
python metacrawler.py -u https://example.com --crawl
```

### Analyze Multiple Files
```bash
python metacrawler.py -f file1.pdf -f file2.docx -f image.jpg
```

### Analyze Local Directory
```bash
python mega_sentinel.py -d ./documents
```

### Advanced Usage
```bash
# Crawl with depth limit and save results
python mega_sentinel.py -u https://example.com --crawl --crawl-depth 3 -o results.json

# Analyze from target list file
python mega_sentinel.py -l targets.txt --max-files 50
```

## 📋 Usage Examples

### Basic File Analysis
```bash
python mega_sentinel.py -f sensitive_document.pdf
```

### Comprehensive Website Audit
```bash
python mega_sentinel.py -u https://target-site.com --crawl --crawl-depth 2 -o website_audit.json
```

### Batch Directory Processing
```bash
python mega_sentinel.py -d ./project_files --max-files 200 -o project_scan.json
```

### Multiple Target Types
```bash
python mega_sentinel.py -u https://api.example.com -f config.json -d ./src --crawl
```

## 🔧 Advanced Options

| Option | Description | Default |
|--------|-------------|---------|
| `-u, --url` | Target URL to analyze | - |
| `-f, --file` | Local file to analyze | - |
| `-d, --directory` | Directory to analyze recursively | - |
| `-l, --list` | File containing list of targets | - |
| `-o, --output` | Output file for results (JSON) | - |
| `--crawl` | Enable website crawling | False |
| `--crawl-depth` | Maximum crawl depth | 2 |
| `--max-files` | Maximum files to analyze | 100 |

## 📊 Output Format

Results are provided in detailed JSON format with the following structure:

```json
{
  "filename": "document.pdf",
  "file_type": "pdf",
  "file_size": 102400,
  "md5_hash": "...",
  "sha256_hash": "...",
  "sensitive_patterns": [
    {
      "pattern_type": "aws_access_key",
      "matched_text": "AKIA*****KEY",
      "risk_score": 0.9,
      "position": [120, 140]
    }
  ],
  "extracted_data": {
    "pdf_data": {
      "metadata": {"author": "John Doe", "title": "Secret Document"},
      "text_content": "...",
      "page_count": 5
    }
  },
  "analysis_timestamp": "2024-01-15T10:30:00"
}
```

## 🛡️ Security Features

### Risk Scoring
- **High Risk (0.7-1.0)**: Private keys, API secrets, credentials
- **Medium Risk (0.4-0.7)**: Configuration data, tokens
- **Low Risk (0.0-0.4)**: Public information, test data

### False Positive Reduction
- Intelligent pattern validation
- Common test data filtering
- Context-aware detection

### Safe Data Handling
- Sensitive data masking in output
- Secure memory handling
- No data persistence without explicit consent

## 🔍 Detection Capabilities

### File Type Detection
- Magic byte signatures
- File extension mapping
- Content-based classification
- Fallback binary/text detection

### Pattern Recognition
- 50+ sensitive data patterns
- Regular expression-based matching
- Multi-format support (Base64, Hex, etc.)
- Contextual validation

### Metadata Extraction
- PDF metadata and text content
- Image EXIF and GPS data
- Office document properties
- Archive contents listing

## 🌐 Web Crawling Features

### Intelligent Discovery
- HTML parsing for file links
- Script and resource detection
- Sitemap and directory enumeration
- Recursive link following

### Respectful Crawling
- robots.txt compliance
- Configurable delay between requests
- Domain restriction options
- Rate limiting

### Async Performance
- Concurrent file processing
- Non-blocking network operations
- Configurable connection limits
- Efficient memory usage

## 🐛 Troubleshooting

### Common Issues

**Missing Dependencies**
```bash
# Install all optional dependencies
pip install PyPDF2 Pillow exifread olefile python-magic
```

**SSL Certificate Errors**
- Tool automatically handles SSL verification bypass for testing
- Use in controlled environments only

**Memory Issues with Large Files**
- Use `--max-files` to limit processing
- Tool includes safeguards for large archive processing

### Performance Tips
- Use `--max-files` for large directories
- Adjust `--crawl-depth` based on target size
- Process files in batches for memory efficiency


### Adding New Patterns
Edit the `ComprehensivePatternEngine` class to add new detection patterns:

```python
"new_pattern": r"your_regex_pattern_here"
```

### Supporting New File Types
Extend the `UniversalFileParser` with new parsing methods:

```python
async def _parse_new_format(self, content: bytes) -> Dict[str, Any]:
    # Your parsing logic here
    return extracted_data
```

## 📄 License

This project is licensed under the MIT License.

## ⚠️ Disclaimer

This tool is designed for:
- Security research and penetration testing
- Educational purposes
- Authorized security assessments


---

<div align="center">

**Meta Crawler **

</div>
```
