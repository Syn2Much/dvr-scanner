# DVR Scanner & Fingerprinter

Fast, multi-threaded DVR/NVR scanner that fingerprints common surveillance web interfaces from a list of IPs, with real-time filtering and incremental saving.

![Banner](https://img.shields.io/badge/DVR-Finder-blue)
![Python](https://img.shields.io/badge/Python-3.7%2B-green)
![License](https://img.shields.io/badge/License-MIT-orange)
![Threading](https://img.shields.io/badge/Multi--Threaded-Yes-brightgreen)

## Features
- **Multi-threaded scanning** (thread pool)
- **DVR detection & fingerprinting** (patterns, keywords, headers, titles/meta; includes Chinese keywords)
- **Auto-save** results while scanning + **Ctrl+C** graceful save/exit
- **Resilient** timeouts, error handling, encoding fallbacks

## Installation
```bash
git clone https://github.com/Syn2Much/dvr-finder.git
cd dvr-finder
pip install -r requirements.txt
```

Or:
```bash
pip install requests urllib3
```

**Requirements:** Python 3.7+

## Usage
```bash
python dvr_finder.py -i ips.txt -t 10 -o dvr_scan_results.json
```

Common options:
- `-i, --input` IP list (default: `ips.txt`)
- `-t, --threads` threads (default: `10`)
- `--save-interval` save every N DVRs found (default: `10`)
- `-o, --output` output JSON (default: `dvr_scan_results.json`)
- `-v, --verbose` verbose output

Examples:
```bash
python dvr_finder.py
python dvr_finder.py -t 20
python dvr_finder.py -i my_ips.txt -t 30 -v
python dvr_finder.py --save-interval 5
python dvr_finder.py -o results.json
```

## Input / Output
**Input:** one IP per line.
```txt
192.168.1.1
192.168.1.2
10.0.0.1
```

**Outputs:**
- `dvr_scan_results.json` — full fingerprint details per hit
- `dvr_ips.txt` — plain list of DVR IPs found

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


## Example Output
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

## Adding signatures
Add new patterns to the `dvr_signatures` dictionary inside `detect_dvr_type_with_signatures()`.

## Disclaimer
**Educational and authorized testing only.** You must have explicit permission to scan networks/devices. The authors are not responsible for misuse or damage.
