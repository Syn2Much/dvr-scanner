# 🎯 DVR Scanner & Fingerprinter

[![Python](https://img.shields.io/badge/python-3.7+-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Threads](https://img.shields.io/badge/threads-configurable-orange.svg)](README.md)
[![Version](https://img.shields.io/badge/version-1.1-brightgreen.svg)](README.md)

A high-performance, multi-threaded Python tool for scanning, fingerprinting, and logging DVR devices from IP address lists. Perfect for security researchers, network administrators, and penetration testers.

## ✨ Features

- **Multi-threaded Scanning**: Lightning-fast parallel scanning with configurable thread counts
- **Smart DVR Detection**: Advanced pattern matching for 12+ DVR brands including Hikvision, Dahua, Axis, and more
- **Real-time Logging**: Immediate notification when DVR devices are found with detection evidence
- **Multi-Encoding Support**: Handles Chinese, Japanese, Korean, and various text encodings
- **Multiple Output Formats**: JSON results and clean IP lists
- **Command-line Interface**: Easy-to-use CLI with sensible defaults
- **Verbose Mode**: Detailed output showing detection signatures and evidence
- **Progress Tracking**: Real-time scan progress with completion statistics
- **SSL Bypass**: Automatically handles self-signed certificates common in DVRs

## 🚀 Quick Start

### Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/Syn2Much/DVR-Fingerprinter.git
   cd DVR-Fingerprinter
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

   Or install manually:
   ```bash
   pip install requests
   ```

3. **Create your IP list**:
   ```bash
   echo "192.168.1.100" > ips.txt
   echo "192.168.1.101" >> ips.txt
   # Add more IPs, one per line
   ```

### Basic Usage

```bash
# Scan with default settings (10 threads)
python dvr_scanner.py

# Scan with 50 threads
python dvr_scanner.py -t 50

# Verbose mode with 20 threads
python dvr_scanner.py -t 20 -v

# Use custom input file
python dvr_scanner.py -i my_targets.txt -t 30

# Show help
python dvr_scanner.py --help
```

## 📖 Usage Examples

### Example 1: Basic Scan
```bash
python dvr_scanner.py
```
Scans IPs from `ips.txt` using 10 threads.

### Example 2: High-Speed Scan
```bash
python dvr_scanner.py -t 100 -v
```
Scans with 100 threads and shows detailed output for each found DVR.

### Example 3: Custom IP List
```bash
python dvr_scanner.py -i targets.txt -t 25
```
Scans IPs from `targets.txt` using 25 threads.

## 🎯 DVR Brands Detected

The scanner can identify 12+ DVR brands including:

| Brand | Key Signatures |
|-------|----------------|
| **Hikvision** | `hikvision`, `ds-`, `iVMS`, `ISAPI`, `/SDK/` |
| **Dahua** | `dahua`, `dhip`, `configManager.cgi`, `login.cgi` |
| **Uniview** | `uniview`, `NVR`, `ivms-4200`, `easy7` |
| **Axis** | `axis`, `vapix`, `axis-cgi/` |
| **Bosch** | `bosch`, `divar`, `videojet` |
| **Samsung/Hanwha** | `hanwha`, `wisenet`, `smartvss`, `snr-` |
| **Honeywell** | `honeywell`, `maxpro`, `pro-watch` |
| **Pelco** | `pelco`, `spectra`, `videoXpert` |
| **Vivotek** | `vivotek`, `vivoview`, `cc9`, `fd9` |
| **Sony** | `sony security`, `snc-`, `srx-` |
| **Panasonic** | `panasonic`, `wj-`, `bl-`, `wv-` |
| **Generic DVR/NVR** | Any device with DVR/NVR keywords or Chinese characters |

**Chinese DVR Support**: Detects devices with Chinese keywords (监控, 安防, 录像机, 摄像机)

## 📊 Output Files

The scanner creates two output files:

### 1. `dvr_scan_results.json`
Complete scan results with full details:
- IP addresses and ports
- HTTP status codes and headers
- Page content samples
- Detected DVR types
- Detection signatures and evidence
- Content length and timestamps
- Server information and page titles

### 2. `dvr_ips.txt`
Clean list of IP addresses with detected DVRs (one per line)

### Sample JSON Output
```json
{
  "ip": "192.168.1.100",
  "status_code": 200,
  "dvr_type": ["Hikvision"],
  "detection_method": "Pattern match",
  "detection_signatures": [
    {
      "brand": "Hikvision",
      "pattern": "hikvision",
      "matched_text": "server: hikvision web server 2.0"
    }
  ],
  "page_title": "Hikvision Web Login",
  "server_info": "Hikvision Web Server",
  "scan_timestamp": "2024-01-15T14:30:45.123456",
  "url": "http://192.168.1.100:80"
}
```

## ⚙️ Configuration

### Command-line Arguments

| Argument | Short | Description | Default |
|----------|-------|-------------|---------|
| `--input` | `-i` | Input file with IP addresses | `ips.txt` |
| `--threads` | `-t` | Number of threads to use | `10` |
| `--verbose` | `-v` | Enable verbose output showing full DVR details | `False` |
| `--version` | | Show version information | `DVR Scanner v1.1` |
| `--help` | `-h` | Show help message | |

### Thread Recommendations

| Scenario | Recommended Threads |
|----------|---------------------|
| Small networks (< 100 IPs) | 10-20 |
| Medium networks (100-1000 IPs) | 20-50 |
| Large networks (> 1000 IPs) | 50-100 |
| Low-bandwidth connections | 5-10 |
| Aggressive scanning | 100-200 |

## 🔧 Technical Details

### Detection Methodology

The scanner uses a multi-layered detection approach:

1. **Encoding Detection**: Automatically detects and handles various text encodings
2. **Pattern Matching**: Regular expressions for 12+ DVR brands
3. **Keyword Analysis**: Minimum 2 DVR-related keywords triggers detection
4. **Header Analysis**: Server headers and authentication realms
5. **Chinese Language Support**: Detection for Chinese DVR interfaces

### Filtering Logic

The scanner includes IPs if ANY of these conditions are met:

1. **Exact DVR Match**: Detected as specific DVR brand
2. **Keyword Density**: ≥2 DVR keywords in response
3. **Server Header**: DVR-related terms in Server header
4. **Authentication**: DVR keywords in WWW-Authenticate header
5. **Common Patterns**: Known DVR login pages or URLs

### Supported Encodings

- UTF-8
- GB2312 (Chinese)
- GBK (Chinese)
- Big5 (Traditional Chinese)
- Shift_JIS (Japanese)
- EUC-KR (Korean)
- Latin-1 / ISO-8859-1
- CP1252

## 🛡️ Security Considerations

### Ethical Use Only
This tool is designed for:
- Security research and testing
- Network inventory and auditing
- Penetration testing with proper authorization
- Educational purposes

**⚠️ IMPORTANT**: Only scan networks you own or have explicit permission to test. Unauthorized scanning may be illegal.

### Best Practices
1. **Get Permission**: Always obtain written authorization before scanning
2. **Limit Threads**: Avoid overwhelming target networks (default: 10 threads)
3. **Respect Rate Limits**: Some DVRs may have request rate limits
4. **Use Responsibly**: This tool is for security improvement, not exploitation

## 🐛 Troubleshooting

### Common Issues

**"Input file not found"**
```bash
# Create the default input file
echo "192.168.1.100" > ips.txt
```

**"Too many open files" (Linux/Mac)**
```bash
# Reduce thread count
python dvr_scanner.py -t 20
# OR increase system limits
ulimit -n 2048
```

**"Connection timeout"**
- Reduce thread count
- Increase timeout in code (currently 3 seconds)
- Check network connectivity

**"No DVRs found"**
- Verify IPs are reachable on port 80
- Check if DVRs use non-standard ports
- Try verbose mode to see all responses

### Debugging Tips

1. **Use verbose mode** to see all HTTP responses:
   ```bash
   python dvr_scanner.py -v
   ```

2. **Test single IP** to verify detection:
   ```bash
   echo "192.168.1.100" > test.txt
   python dvr_scanner.py -i test.txt -v
   ```

3. **Check JSON output** for detailed response analysis:
   ```bash
   cat dvr_scan_results.json | python -m json.tool
   ```

## 🤝 Contributing

Contributions are welcome! Here's how you can help:

1. **Report Issues**: Found a bug? Open an issue with details
2. **Add DVR Signatures**: Know a DVR brand not detected? Submit a PR
3. **Improve Performance**: Optimize scanning or detection algorithms
4. **Enhance Features**: Add new output formats or scanning options

### Development Setup
```bash
# Fork and clone the repository
git clone https://github.com/yourusername/dvr-scanner.git
cd dvr-scanner

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install development dependencies
pip install -r requirements-dev.txt

# Run tests (if available)
python -m pytest tests/
```

### Adding New DVR Signatures
To add a new DVR brand, update the `detect_dvr_type_with_signatures` method with:
```python
'NewBrand': [
    r'newbrand',
    r'new\-brand',
    r'/cgi-bin/newbrand',
    # Add more patterns
]
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This tool is provided for educational and authorized security testing purposes only. The authors are not responsible for any misuse or damage caused by this program. Always ensure you have proper authorization before scanning any network or system.


**Made with ❤️ for the security community**

*Remember: With great power comes great responsibility. Use this tool ethically and legally.*

---

## 🚀 Quick Commands Reference

```bash
# Show help
python dvr_scanner.py --help

# Show version
python dvr_scanner.py --version

# Quick scan
python dvr_scanner.py

# Full power scan
python dvr_scanner.py -t 100 -v -i targets.txt

# Check results
cat dvr_ips.txt
cat dvr_scan_results.json | jq .  # if jq is installed
```

## 📞 Support

For issues, questions, or suggestions:

---

**Happy Scanning! 🎯**
