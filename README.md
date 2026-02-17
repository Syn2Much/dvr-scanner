# DVR Scanner & Fingerprinter

Fast, multi-threaded scanner that fingerprints DVR/NVR web interfaces and security IoT devices with brand-specific detection.

![Python](https://img.shields.io/badge/Python-3.7%2B-green)
![License](https://img.shields.io/badge/License-MIT-orange)

---
<img width="891" height="619" alt="image" src="https://github.com/user-attachments/assets/7668b20b-d8cc-4aaf-82a1-1e223ecea7f5" />

## How It Works

1. Reads target IPs from input file.
2. Sends HTTP requests with browser-like headers.
3. Skips 400/404 responses.
4. Applies brand-specific signature matching against headers, body content, and page titles.
5. Saves results incrementally, with full save on exit or interrupt.

## Features

- **Brand-Specific Detection** — Strict signatures for Hikvision, Dahua, Uniview, Axis, Hanwha, XMEye, Amcrest, Reolink, MikroTik, Ubiquiti, Synology, and more.
- **Evidence-Rich Output** — Detection method, matched signatures, headers, page titles, and server info per result.
- **Concurrent Scanning** — Configurable thread pool for high-throughput scanning.
- **Auto-Save** — Periodic saves and graceful Ctrl+C handling to prevent data loss.
- **Low False Positives** — Title-based fallback limited to explicit DVR/NVR/camera phrases; generic login heuristics excluded.

## Quick Start

### Prerequisites

- Python 3.7+
- `pip install requests urllib3`

### Usage
```bash
python scanner.py -i ips.txt -t 20 --save-interval 5 -o results.json
```

| Flag | Description | Default |
|------|-------------|---------|
| `-i, --input` | Path to IP list (one per line) | `ips.txt` |
| `-t, --threads` | Max worker threads | `10` |
| `-v, --verbose` | Enable verbose logging | Off |
| `--save-interval` | Auto-save every N detections | `10` |
| `-o, --output` | JSON output path | `dvr_scan_results.json` |

### Output Files

- **JSON** — Full metadata per detection (IP, status, headers, DVR type, detection method, signatures, timestamp).
- **TXT** — Plain list of detected DVR IPs, saved alongside as `<output>_ips.txt`.


## Disclaimer

Only scan hosts and networks you are authorized to test. Unauthorized scanning may violate applicable laws or terms of service.

## Author

**Syn2Much**

- Email: [dev@sinnners.city](mailto:dev@sinnners.city)
- X: [@synacket](https://x.com/synacket)

