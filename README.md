# DVR Scanner & Fingerprinter

![Banner](https://img.shields.io/badge/DVR-Finder-blue)
![Python](https://img.shields.io/badge/Python-3.7%2B-green)
![License](https://img.shields.io/badge/License-MIT-orange)
![Threading](https://img.shields.io/badge/Multi--Threaded-Yes-brightgreen)

A high-performance, multi-threaded DVR/NVR device scanner that fingerprints surveillance systems from a list of IP addresses. Detects and identifies various DVR brands with real-time filtering and auto-saving capabilities.

<img width="1703" height="1171" alt="Screenshot 2026-01-18 101903" src="https://github.com/user-attachments/assets/a6519164-2311-4629-96b1-0848f6e0debb" />


## 🔧 How It Works

### Scanning Process
1. **IP Loading**: Reads IP addresses from input file
2. **Parallel Scanning**: Uses thread pool to scan multiple IPs simultaneously
3. **HTTP Requests**: Sends HTTP GET requests to port 80
4. **Mid-Scan Filtering**: Immediately checks if response indicates a DVR
5. **Signature Matching**: Compares response against known DVR patterns
6. **Incremental Saving**: Saves results as DVRs are discovered
7. **Statistics**: Tracks progress and provides real-time updates

### Detection Methods
1. **Pattern Matching**: Regex patterns for specific DVR brands
2. **Keyword Analysis**: Searches for DVR-related terms
3. **Header Inspection**: Examines Server and WWW-Authenticate headers
4. **Chinese Language Support**: Detects Chinese security keywords
5. **Content Analysis**: Page titles and meta information

## ⚡ Performance Tips

- **Thread Count**: Start with 10-20 threads, increase based on network capacity
- **Save Interval**: Lower values provide more frequent saves but more disk I/O
- **Verbose Mode**: Use only when debugging as it increases output
- **Input File Size**: The scanner handles large files efficiently

## 🛡️ Safety Features

- **Graceful Shutdown**: Ctrl+C saves all results before exiting
- **Timeout Handling**: Prevents hanging on unresponsive hosts
- **Error Recovery**: Continues scanning even if individual IPs fail
- **Encoding Fallbacks**: Multiple encoding attempts for international devices
- **Resource Management**: Proper thread pool shutdown
## 🚀 Installation

### Prerequisites
- Python 3.7 or higher
- pip package manager

### Install Dependencies
```bash
pip install requests urllib3
```

Or clone and install:
```bash
git clone https://github.com/Syn2Much/dvr-finder.git
cd dvr-finder
pip install -r requirements.txt
```

### Requirements File
Create `requirements.txt`:
```txt
requests>=2.28.0
urllib3>=1.26.0
```

## 📖 Usage

### Basic Usage
```bash
python dvr_finder.py
```

### Command Line Arguments
```bash
python dvr_finder.py [OPTIONS]
```

| Option | Description | Default |
|--------|-------------|---------|
| `-i, --input` | Input file with IPs (one per line) | `ips.txt` |
| `-t, --threads` | Number of threads to use | `10` |
| `-v, --verbose` | Enable verbose output | `False` |
| `--save-interval` | Save every N DVRs found | `10` |
| `-o, --output` | Output JSON filename | `dvr_scan_results.json` |
| `--version` | Show version | - |

### Examples

**Scan with default settings:**
```bash
python dvr_finder.py
```

**Scan with 20 threads:**
```bash
python dvr_finder.py -t 20
```

**Scan with verbose output and custom input:**
```bash
python dvr_finder.py -i my_ips.txt -t 30 -v
```

**Save results every 5 DVRs found:**
```bash
python dvr_finder.py --save-interval 5
```

**Use custom output filename:**
```bash
python dvr_finder.py -o results.json
```
## 📋 Supported DVR Brands

| Brand | Detection Patterns |
|-------|-------------------|
| **Hikvision** | `hikvision`, `ds-*`, `nvr*`, `iVMS`, `ISAPI` |
| **Dahua** | `dahua`, `dhip`, `configManager.cgi`, `login.cgi` |
| **Uniview** | `uniview`, `uniarch`, `NVR*`, `ivms-4200` |
| **Axis** | `axis`, `axis communications`, `vapix` |
| **Bosch** | `bosch`, `divar`, `dynacord` |
| **Samsung/Hanwha** | `hanwha`, `wisenet`, `smartvss` |
| **Honeywell** | `honeywell`, `equinox`, `maxpro` |
| **Pelco** | `pelco`, `spectra`, `sarix` |
| **Vivotek** | `vivotek`, `vivoview`, `cc9` |
| **Sony** | `sony security`, `snc-*` |
| **Panasonic** | `panasonic`, `wj-*`, `bl-*` |
| **Generic DVR/NVR** | `dvr login`, `nvr login`, `cctv`, `监控`, `安防` |

## 📁 Input Format

Create a file named `ips.txt` (or custom name) with one IP address per line:

```txt
192.168.1.1
192.168.1.2
192.168.1.3
10.0.0.1
10.0.0.2
...
```

## 📊 Output Files

The scanner creates two output files:

### 1. JSON Results (`dvr_scan_results.json`)
Contains detailed information for each detected DVR:
```json
[
  {
    "ip": "192.168.1.100",
    "status_code": 200,
    "headers": {...},
    "important_headers": {...},
    "page_content": "...",
    "content_length": 1523,
    "dvr_type": ["Hikvision", "Generic DVR/NVR"],
    "detection_method": "Pattern match",
    "detection_signatures": [...],
    "scan_timestamp": "2024-01-15T10:30:45.123456",
    "url": "http://192.168.1.100:80",
    "server_info": "Apache/2.4.41",
    "page_title": "Hikvision Web Login"
  }
]
```

### 2. IP List (`dvr_ips.txt`)
Plain text file with one IP address per line:
```txt
192.168.1.100
192.168.1.101
10.0.0.50
...
```

## 📝 Sample Output

```
    ╔═══════════════════════════════════════════════════════════════════════════════╗
    ║    ____________   ______________  ___________.__            . ___              ║
    ║    \______ \   \ /   /\______   \ \_   _____/|__| ____    __| _/___________   ║
    ║    |    |  \   Y   /  |       _/  |    __)  |  |/    \  / __ |/ __ \_  __ \   ║
    ║    |    `   \     /   |    |   \  |     \   |  |   |  \/ /_/ \  ___/|  | \/   ║
    ║    /_______  /\___/    |____|_  /  \___  /   |__|___|  /\____ |\___  >__|     ║
    ║            \/                 \/       \/            \/      \/    \/         ║
    ║                         DVR Scanner & Fingerprinter                           ║
    ║                         v2.0 - dev@sinners.cty                                ║
    ╚═══════════════════════════════════════════════════════════════════════════════╝    

                     🔍 Scanning for DVR Devices

                     💡 Press Ctrl+C to save and exit gracefully

════════════════════════════════════════════════════════════════════════
Starting DVR Scanner
════════════════════════════════════════════════════════════════════════
Input file: ips.txt
Threads: 10
Verbose: False
Auto-save interval: Every 10 DVRs found
Scan started:  2024-01-15 10:30:45
════════════════════════════════════════════════════════════════════════

Loaded 1000 IP addresses from ips.txt
Starting scan with 10 threads...

✓ [1/1000] 192.168.1.1 - Status: 200 (not DVR)
✗ [2/1000] 192.168.1.2 - Connection refused
🎯 [3/1000] DVR FOUND: 192.168.1.100 | Status: 200 | Type: Hikvision, Generic DVR/NVR
...
💾 Auto-saved 10 DVR results
...
🎯 [25/1000] DVR FOUND: 10.0.0.50 | Status: 401 | Type: Dahua
```

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

### Adding New DVR Signatures
To add support for a new DVR brand, add patterns to the `dvr_signatures` dictionary in the `detect_dvr_type_with_signatures` method.

## ⚠️ Disclaimer

**FOR EDUCATIONAL AND AUTHORIZED TESTING PURPOSES ONLY**

This tool is intended for:
- Security researchers testing their own networks
- Network administrators auditing their infrastructure
- Educational purposes in controlled environments

**YOU MUST HAVE EXPLICIT PERMISSION** to scan any network or device. Unauthorized scanning may be illegal in your jurisdiction.

The authors are not responsible for any misuse or damage caused by this tool.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🐛 Troubleshooting

### Common Issues

**"Input file not found" error:**
- Ensure the input file exists in the same directory
- Check file permissions
- Specify full path: `-i /path/to/ips.txt`

**Slow scanning:**
- Reduce thread count with `-t 5`
- Check network connectivity
- Some networks may throttle multiple connections

**No DVRs detected:**
- Verify IPs are reachable on port 80
- Check if devices require different ports
- Try increasing timeout in code (currently 5 seconds)

**Encoding errors:**
- The scanner automatically tries multiple encodings
- Check if input file uses unusual encoding

## 📞 Support

For issues, feature requests, or questions:
1. Check the troubleshooting section above
2. Open an issue on GitHub
3. Ensure you include:
   - Python version
   - Command used
   - Error messages
   - Sample input (if possible)

---

**Happy Scanning!** 🎯

*Remember: Always scan responsibly and with proper authorization.*
