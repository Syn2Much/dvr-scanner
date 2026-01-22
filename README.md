
# DVR Scanner & Fingerprinter (Brand Specific)

Fast, multi-threaded scanner that fingerprints surveillance web interfaces (DVR/NVR) and security-related IoT devices. 

![Banner](https://img.shields.io/badge/DVR-Finder-blue)
![Python](https://img.shields.io/badge/Python-3.7%2B-green)
![License](https://img.shields.io/badge/License-MIT-orange)


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
Starting DVR Scanner on ips.txt with 10 threads...
════════════════════════════════════════════════════════════════════════

✓ [1/1000] 192.168.1.1 - Status: 200 (not DVR)
✗ [2/1000] 192.168.1.2 - Connection refused
🎯 [3/1000] DVR FOUND: 192.168.1.100 | Status: 200 | Type: Hikvision
🎯 [4/1000] DVR FOUND: 10.0.0.55 | Status: 200 | Type: Generic Login (Context: Login page with 'stream')
...
💾 Auto-saved 10 DVR results
...
```

## Features
- 🚀 **Concurrent scanning** using `ThreadPoolExecutor` with configurable thread count.
- 🛡️ **Graceful shutdown** on SIGINT/SIGTERM (Ctrl+C): saves progress, stops workers cleanly.
- 🎯 **Brand-specific detection** via strict signatures (Hikvision, Dahua, Uniview, Axis, Hanwha/Wisenet, Avigilon, Mobotix, XMEye, TVT, Amcrest, Foscam, Reolink, DrayTek, MikroTik, Ubiquiti, Synology, etc.).
- 🏷️ **Evidence-rich results**: detection method, signatures matched, headers, titles, server info.
- 🧠 **Robust content decoding**: tries multiple encodings with safe fallback.
- 📝 **Auto-saving** JSON + IP list every N detections; empty files created if none found.
- 🚫 **Noise reduction**: skips processing 400/404 responses; tracks HTTP error count.
- 📊 **Scan summary**: totals for scanned, skipped errors, failures, DVRs found.
- ⚙️ **Configurable** input file, threads, verbosity flag, save interval, output paths.
- 🔒 **SSL warnings suppressed** for cleaner output (HTTP-only scanning on port 80).

## Getting Started

### Prerequisites
- Python 3.8+
- `requests`, `urllib3`

### Installation
```bash
pip install requests urllib3
```

### Prepare targets
Create an `ips.txt` file (default) with one IP per line:
```
192.0.2.10
198.51.100.23
203.0.113.42
```

### Usage
```bash
python scanner.py \
  --input ips.txt \
  --threads 10 \
  --save-interval 10 \
  --output dvr_scan_results.json
```

Flags:
- `-i, --input` — path to IP list file (default: `ips.txt`)
- `-t, --threads` — max worker threads (default: `10`)
- `-v, --verbose` — verbose logging (flag)
- `--save-interval` — auto-save every N DVR detections (default: `10`)
- `-o, --output` — JSON output path (default: `dvr_scan_results.json`)
  - The IP list is also saved as `<output>_ips.txt`.

### What it does
1. Reads IPs from the input file.
2. Sends HTTP GET to `http://<ip>:80` with common browser headers.
3. Skips 400/404 responses (counts them separately).
4. Decodes content robustly; extracts key headers.
5. Applies strict brand signatures (headers + body + `<title>` fallback for DVR terms).
6. Saves detections (JSON + IP list), with auto-save every N hits.
7. On Ctrl+C, saves progress and exits cleanly.

### Outputs
- **JSON** (default: `dvr_scan_results.json`): rich per-hit metadata  
  - `ip`, `status_code`, `important_headers`, `page_title`, `page_content` (truncated), `dvr_type`, `detection_method`, `detection_signatures`, `scan_timestamp`, `url`, optional `server_info`
- **TXT** (default: `dvr_scan_results_ips.txt`): list of detected DVR IPs



### Detection logic (strict)
- Brand patterns for major DVR/NVR/IoT vendors (headers + body).
- Title-based fallback only for explicit DVR/NVR/camera phrases (e.g., “network video recorder”, “embedded net dvr”).
- Generic password/login heuristics are intentionally removed to reduce false positives.

### Graceful shutdown
- SIGINT/SIGTERM triggers immediate safe-save of current detections and cancels pending futures.

### Operational tips
- Start with a modest thread count to avoid overloading networks.
- Ensure you’re authorized to scan the target IP ranges.
- Increase `--save-interval` for fewer writes; decrease for safer incremental checkpoints.

### Safety & legal
Only scan hosts and networks you are authorized to test. Unauthorized scanning may violate law or terms of service.

### Quick example
```bash
python scanner.py -i ips.txt -t 20 --save-interval 5 -o results.json
```

## Project structure (suggested)
```
scanner.py        # contains FingerPrinter and CLI
ips.txt           # input IP list (one per line)
dvr_scan_results.json      # JSON detections (output)
dvr_scan_results_ips.txt   # IPs only (output)
```
