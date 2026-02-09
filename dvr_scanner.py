from pathlib import Path
import json
from datetime import datetime
import re
import concurrent.futures
import threading
import argparse
import sys
import signal
from typing import List, Dict, Any, Tuple, Optional
import requests
from requests.adapters import HTTPAdapter
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Pre-compiled title regex — used in hot path, compile once
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


class FingerPrinter:
    # DVR brand signatures — compiled once at class level
    _DVR_SIGNATURES: Dict[str, re.Pattern] = {}

    @classmethod
    def _compile_signatures(cls) -> None:
        """Pre-compile all brand regex patterns into a single alternated pattern per brand."""
        if cls._DVR_SIGNATURES:
            return  # already compiled
        raw = {
            "Hikvision": [
                r"hikvision",
                r"hik\-?vision",
                r"doc/page/login\.asp",
                r"ivms",
                r"webcomponent",
            ],
            "Dahua": [
                r"dahua",
                r"dahuasecurity",
                r"login\.cgi",
                r"guilogin\.cgi",
                r"web\.cgi",
                r"dss-web",
            ],
            "Uniview": [r"uniview", r"uniarch", r"/LAPI/V1\.0", r"program/login"],
            "Axis": [r"axis communications", r"axis network camera"],
            "Samsung/Hanwha": [r"hanwha", r"wisenet", r"samsung techwin"],
            "Avigilon": [r"avigilon"],
            "Mobotix": [r"mobotix"],
            "XMEye": [r"xmeye", r"cloud\.net"],
            "TVT": [r"tvt", r"nvms"],
            "Amcrest": [r"amcrest"],
            "Foscam": [r"foscam"],
            "Reolink": [r"reolink"],
            "Synology": [r"synology", r"diskstation", r"surveillance station"],
        }
        for brand, patterns in raw.items():
            combined = "|".join(f"(?:{p})" for p in patterns)
            cls._DVR_SIGNATURES[brand] = re.compile(combined, re.IGNORECASE)

    # Title keywords for fallback detection — lowered and pre-built
    _TITLE_KEYWORDS = (
        "network video recorder",
        "digital video recorder",
        "web viewer",
        "network camera",
        "surveillance system",
        "ip camera",
        "ipcam",
        "net surveillance",
        "embedded net dvr",
    )

    def __init__(
        self,
        file: Path = Path("ips.txt"),
        max_threads: int = 10,
        verbose: bool = False,
        save_interval: int = 10,
        output_json: Path = Path("dvr_scan_results.json"),
        output_txt: Path = Path("dvr_ips.txt"),
    ):
        self.file = file
        self.max_threads = max_threads
        self.verbose = verbose
        self.save_interval = save_interval
        self.output_json = output_json
        self.output_txt = output_txt

        self.results_lock = threading.Lock()
        self.scanned_count = 0
        self.total_ips = 0
        self.dvr_count = 0
        self.failed_count = 0
        self.http_error_count = 0

        self.dvr_results: List[Dict[str, Any]] = []
        self.last_save_count = 0

        self.shutdown_requested = False
        self.executor = None

        # Compile brand regex once
        self._compile_signatures()

        # Reusable HTTP session with connection pooling
        self._session = requests.Session()
        adapter = HTTPAdapter(
            pool_connections=max_threads,
            pool_maxsize=max_threads,
            max_retries=0,
        )
        self._session.mount("http://", adapter)
        self._session.headers.update(
            {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9",
                "Connection": "close",
            }
        )

        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

    def _signal_handler(self, signum, frame):
        print(f"\n\n⚠️  Interrupt received!  Saving results and shutting down...")
        self.shutdown_requested = True
        self._save_results_safe()
        if self.executor:
            self.executor.shutdown(wait=False, cancel_futures=True)
        print(f"✅ Results saved.  Exiting gracefully.")
        sys.exit(0)

    def _save_results_safe(self):
        with self.results_lock:
            if self.dvr_results:
                self._write_outputs(self.dvr_results)
                print(f"💾 Saved {len(self.dvr_results)} DVR results")
            else:
                self.output_json.write_text("[]", encoding="utf-8")
                self.output_txt.write_text("", encoding="utf-8")
                print("💾 No DVRs found yet, created empty output files")

    def _write_outputs(self, data: List[Dict[str, Any]]) -> None:
        """Single method that writes both JSON and TXT outputs."""
        try:
            self.output_json.write_text(
                json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8"
            )
            self.output_txt.write_text(
                "\n".join(r["ip"] for r in data) + "\n", encoding="utf-8"
            )
        except Exception as e:
            print(f"⚠️  Warning: Failed to save results: {e}")

    def print_banner(self):
        banner = r"""
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
"""
        print(banner)
        print(" " * 20 + "🔍 Scanning for DVR Devices\n")
        print(" " * 15 + "💡 Press Ctrl+C to save and exit gracefully\n")

    def save_data(self, data: List[Dict[str, Any]]) -> None:
        self._write_outputs(data)
        print(f"DVR results saved to {self.output_json}")
        print(f"DVR IPs saved to {self.output_txt}")

    @staticmethod
    def safe_decode_content(response_content: bytes) -> str:
        # Fast path — vast majority of web content is UTF-8
        try:
            return response_content.decode("utf-8")
        except UnicodeDecodeError:
            pass
        for enc in ("gb2312", "gbk", "big5", "latin-1", "shift_jis", "euc-kr"):
            try:
                return response_content.decode(enc)
            except (UnicodeDecodeError, LookupError):
                continue
        return response_content.decode("utf-8", errors="replace")

    def _check_if_dvr(self, result: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if result.get("status_code") is None:
            return None

        status_code = result["status_code"]
        headers = result.get("headers", {})
        page_content = result.get("content", "")
        content_str = (
            page_content if isinstance(page_content, str) else str(page_content)
        )

        # Extract title once — reused for both detection and output
        title_match = _TITLE_RE.search(content_str)
        title_text = title_match.group(1).strip() if title_match else ""

        # 1. Brand signature detection (pre-compiled regex)
        dvr_types, detection_evidence = self._detect_dvr_brands(headers, content_str)
        detection_method = "Brand Pattern match" if dvr_types else "Unknown"

        # 2. Fallback: title keyword check
        if not dvr_types:
            title_lower = title_text.lower()
            for kw in self._TITLE_KEYWORDS:
                if kw in title_lower:
                    dvr_types = ["Suspected DVR (Title Match)"]
                    detection_method = f"Title contains specific term: {kw}"
                    detection_evidence.append(
                        {
                            "brand": "Generic Title",
                            "pattern": kw,
                            "matched_text": title_text,
                        }
                    )
                    break

        if not dvr_types:
            return None

        filtered_result = {
            "ip": result["ip"],
            "status_code": status_code,
            "headers": headers,
            "important_headers": self._extract_headers(headers),
            "page_content": content_str[:2000],
            "content_length": result.get("content_length", 0),
            "dvr_type": dvr_types,
            "detection_method": detection_method,
            "detection_signatures": detection_evidence,
            "scan_timestamp": datetime.now().isoformat(),
            "url": f"http://{result['ip']}:80",
        }

        server = headers.get("Server")
        if server:
            filtered_result["server_info"] = server
        if title_text:
            filtered_result["page_title"] = title_text[:200]

        return filtered_result

    def scan_single_ip(self, ip: str) -> Optional[Dict[str, Any]]:
        if self.shutdown_requested:
            return None
        ip = ip.strip()
        if not ip:
            return None

        raw_result: Optional[Dict[str, Any]] = None
        try:
            response = self._session.get(
                f"http://{ip}:80",
                timeout=5,
                verify=False,
                allow_redirects=True,
            )

            if response.status_code in (400, 404):
                with self.results_lock:
                    self.scanned_count += 1
                    self.http_error_count += 1
                print(
                    f"⚫ [{self.scanned_count}/{self.total_ips}] {ip} - HTTP {response.status_code} (skipped)"
                )
                return None

            raw_result = {
                "ip": ip,
                "port": 80,
                "status_code": response.status_code,
                "reason": response.reason,
                "headers": dict(response.headers),
                "content": self.safe_decode_content(response.content),
                "content_length": len(response.content),
                "url": response.url,
                "encoding_detected": response.encoding or "unknown",
            }
        except Exception as e:
            raw_result = {
                "ip": ip,
                "port": 80,
                "status_code": None,
                "error": str(e)[:50],
            }

        # DVR check happens outside the lock — CPU work shouldn't block others
        dvr_result = None
        if raw_result and raw_result.get("status_code") is not None:
            dvr_result = self._check_if_dvr(raw_result)

        # Minimise time under lock: build log line first, print after release
        need_save = False
        with self.results_lock:
            self.scanned_count += 1
            count = self.scanned_count
            if raw_result.get("status_code") is None:
                self.failed_count += 1
            elif dvr_result:
                self.dvr_results.append(dvr_result)
                self.dvr_count += 1
                need_save = (
                    self.dvr_count - self.last_save_count
                ) >= self.save_interval
                if need_save:
                    self._write_outputs(self.dvr_results)
                    self.last_save_count = self.dvr_count

        # Print outside the lock to reduce contention
        if raw_result.get("status_code") is None:
            print(
                f"✗ [{count}/{self.total_ips}] {ip} - {raw_result.get('error', 'Error')}"
            )
        elif dvr_result:
            types = ", ".join(dvr_result["dvr_type"])
            print(
                f"🎯 [{count}/{self.total_ips}] DVR FOUND: {ip} | Status: {raw_result['status_code']} | Type: {types}"
            )
            if need_save:
                print(f"💾 Auto-saved {len(self.dvr_results)} DVR results")
        else:
            print(
                f"✓ [{count}/{self.total_ips}] {ip} - Status: {raw_result['status_code']} (not DVR)"
            )

        return raw_result

    def scan_main(self, max_threads=None):
        threads_to_use = max_threads if max_threads is not None else self.max_threads
        self.print_banner()
        print(f"Starting DVR Scanner on {self.file} with {threads_to_use} threads...")

        try:
            content = self.file.read_text(encoding="utf-8")
        except:
            content = self.file.read_bytes().decode("utf-8", errors="ignore")

        ips = [ip.strip() for ip in content.strip().split("\n") if ip.strip()]
        self.total_ips = len(ips)

        try:
            with concurrent.futures.ThreadPoolExecutor(
                max_workers=threads_to_use
            ) as executor:
                self.executor = executor
                future_to_ip = {
                    executor.submit(self.scan_single_ip, ip): ip for ip in ips
                }
                for future in concurrent.futures.as_completed(future_to_ip):
                    if self.shutdown_requested:
                        break
                    try:
                        future.result(timeout=30)
                    except:
                        pass
        except KeyboardInterrupt:
            self._signal_handler(None, None)
        finally:
            self.executor = None

        self._print_summary(threads_to_use)
        return self.dvr_results

    def _print_summary(self, threads_used):
        print(f"\n{'='*60}")
        print(f"SCAN SUMMARY")
        print(f"{'='*60}")
        print(f"Total IPs: {self.total_ips}")
        print(f"Scanned: {self.scanned_count}")
        print(f"HTTP 400/404 skipped: {self.http_error_count}")
        print(f"Connection failed: {self.failed_count}")
        print(f"DVRs found: {self.dvr_count}")
        print(f"{'='*60}")

        if self.dvr_results:
            self.save_data(self.dvr_results)

    _IMPORTANT_HEADERS = ("Server", "X-Powered-By", "WWW-Authenticate")

    @staticmethod
    def _extract_headers(headers: Dict[str, str]) -> Dict[str, str]:
        return {k: headers[k] for k in FingerPrinter._IMPORTANT_HEADERS if k in headers}

    def _detect_dvr_brands(
        self, headers: Dict[str, str], content: str
    ) -> Tuple[List[str], List[Dict[str, str]]]:
        """Match pre-compiled brand regex against content and headers."""
        combined_text = f"{content}\n{headers}"
        detected: List[str] = []
        evidence: List[Dict[str, str]] = []

        for brand, pattern in self._DVR_SIGNATURES.items():
            m = pattern.search(combined_text)
            if m:
                detected.append(brand)
                evidence.append(
                    {
                        "brand": brand,
                        "pattern": pattern.pattern,
                        "matched_text": m.group(),
                    }
                )

        return detected, evidence


def main():
    parser = argparse.ArgumentParser(description="DVR Scanner (Brand Specific)")
    parser.add_argument("-i", "--input", default="ips.txt", help="Input file")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Threads")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose")
    parser.add_argument("--save-interval", type=int, default=10, help="Save interval")
    parser.add_argument(
        "-o", "--output", default="dvr_scan_results.json", help="Output file"
    )
    args = parser.parse_args()

    input_file = Path(args.input)
    if not input_file.exists():
        print(f"Error: {args.input} not found.")
        sys.exit(1)

    scanner = FingerPrinter(
        file=input_file,
        max_threads=args.threads,
        verbose=args.verbose,
        save_interval=args.save_interval,
        output_json=Path(args.output),
        output_txt=Path(args.output.replace(".json", "_ips.txt")),
    )
    scanner.scan_main()


if __name__ == "__main__":
    main()
