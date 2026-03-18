# DVR Scanner & Fingerprinter

A fast, multi-threaded CLI tool for discovering and identifying DVR/NVR web interfaces and security camera devices on a network. It fingerprints devices by brand using signature matching against HTTP responses.

![Python](https://img.shields.io/badge/Python-3.7%2B-green)
![License](https://img.shields.io/badge/License-MIT-orange)

---

<img width="891" height="619" alt="image" src="https://github.com/user-attachments/assets/7668b20b-d8cc-4aaf-82a1-1e223ecea7f5" />

---

## Getting Started

### Install

```bash
pip install requests urllib3
```

### Prepare Your Target List

Create a plain text file with one IP per line (port optional):

```
192.168.1.100
10.0.0.50:8080
172.16.0.1
```

### Run a Scan

Basic scan with defaults:

```bash
python scanner.py -i targets.txt
```

Faster scan with 20 threads, saving every 5 detections:

```bash
python scanner.py -i targets.txt -t 20 --save-interval 5 -o results.json
```

See what's happening under the hood:

```bash
python scanner.py -i targets.txt -t 15 -v
```

## CLI Options

| Flag | Description | Default |
|------|-------------|---------|
| `-i, --input` | Path to your IP list file | `ips.txt` |
| `-t, --threads` | Number of concurrent worker threads | `10` |
| `-v, --verbose` | Print detailed logs during scanning | Off |
| `--save-interval` | Auto-save results every N detections | `10` |
| `-o, --output` | Path for JSON output file | `dvr_scan_results.json` |

## Output

The scanner produces two files:

**`results.json`** — Detailed JSON with full metadata per detected device:
- IP and HTTP status code
- Detected brand/model (e.g. Hikvision, Dahua, Axis)
- Detection method and matched signatures
- Response headers and page title
- Timestamp of detection

**`results_ips.txt`** — A clean list of IPs where DVR/NVR devices were found, one per line. Useful for piping into other tools.

## How It Works

1. Reads IPs from your input file
2. Sends HTTP requests with realistic browser headers to avoid simple blocking
3. Discards 400/404 responses immediately
4. Matches responses against brand-specific signatures in headers, HTML body, and page titles
5. Auto-saves results periodically and on Ctrl+C so you never lose progress mid-scan

## Supported Brands

Hikvision, Dahua, Uniview, Axis, Hanwha, XMEye, Amcrest, Reolink, MikroTik, Ubiquiti, Synology, and more.

Detection uses strict signature matching to keep false positives low — generic "login page" heuristics are intentionally excluded.

## Disclaimer

Only scan hosts and networks you are authorized to test. Unauthorized scanning may violate applicable laws or terms of service.

## Author

**Syn2Much**

- Email: [hell@sinnners.city](mailto:hell@sinnners.city)
- X: [@synacket](https://x.com/synacket)
