from pathlib import Path
import json as js
from datetime import datetime
import re
import concurrent.futures
import threading
import argparse
import sys
import signal
from typing import List, Dict, Any
import requests
import urllib3

# Suppress SSL warnings globally
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class FingerPrinter:    
    def __init__(self, file=Path('ips.txt'), max_threads=10, verbose=False, 
                 save_interval=10, output_json=Path('dvr_scan_results.json'),
                 output_txt=Path('dvr_ips.txt')):
        '''
        The main class to fingerprint and log http results for DVR devices
        '''
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
        
        self.dvr_results: List[Dict[str, Any]] = []
        self.last_save_count = 0
        
        self.shutdown_requested = False
        self.executor = None
        
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
                self._save_data_internal(self.dvr_results)
                print(f"💾 Saved {len(self.dvr_results)} DVR results")
            else:
                with open(self.output_json, 'w', encoding='utf-8') as f:
                    f.write('[]')
                with open(self.output_txt, 'w', encoding='utf-8') as f:
                    f.write('')
                print(f"💾 No DVRs found yet, created empty output files")
    
    def _save_data_internal(self, data):
        try:
            encoder = js.JSONEncoder(indent=2, ensure_ascii=False)
            json_data = encoder.encode(data)
            with open(self.output_json, 'w', encoding='utf-8') as f:
                f.write(json_data)
            
            ips = [result['ip'] for result in data]
            with open(self.output_txt, 'w', encoding='utf-8') as f:
                for ip in ips:
                    f.write(f"{ip}\n")
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

    def save_data(self, data, output_file=None):
        if output_file is None:
            output_file = self.output_json
        encoder = js.JSONEncoder(indent=2, ensure_ascii=False)
        json_data = encoder.encode(data)
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(json_data)
        print(f"DVR results saved to {output_file}")
        self.save_ips_txt(data)

    def save_ips_txt(self, data, output_file=None):
        if output_file is None:
            output_file = self.output_txt
        ips = [result['ip'] for result in data]
        with open(output_file, 'w', encoding='utf-8') as f:
            for ip in ips:
                f.write(f"{ip}\n")
        print(f"DVR IPs saved to {output_file}")

    def safe_decode_content(self, response_content: bytes) -> str:
        encodings_to_try = ['utf-8', 'gb2312', 'gbk', 'big5', 'latin-1', 'iso-8859-1', 'cp1252', 'shift_jis', 'euc-kr']
        for encoding in encodings_to_try:
            try: 
                return response_content.decode(encoding)
            except (UnicodeDecodeError, LookupError):
                continue
        try:
            return response_content.decode('utf-8', errors='replace')
        except:
            return "[BINARY CONTENT - COULD NOT DECODE]"

    def _check_if_dvr(self, result: Dict[str, Any]) -> Dict[str, Any]:
        if result.get('status_code') is None:
            return None
        
        status_code = result.get('status_code')
        headers = result.get('headers', {})
        important_headers = self.extract_headers(headers)
        page_content = result.get('content', '')
        
        # Detect DVR type with signatures
        dvr_types, detection_signatures = self.detect_dvr_type_with_signatures(headers, page_content)
        
        detection_method = "Unknown"
        detection_evidence = []
        
        # 1. Explicitly detected DVR type
        if dvr_types: 
            detection_method = "Pattern match"
            detection_evidence = detection_signatures
            
        # 2. STRICTER Fallback: Only check Title or Login form indicators if no specific brand found
        if not dvr_types:
            content_lower = page_content.lower() if isinstance(page_content, str) else str(page_content).lower()
            
            # Check for <title> specifically
            title_match = re.search(r'<title[^>]*>(.*?)</title>', content_lower)
            title_text = title_match.group(1) if title_match else ""
            
            # Must be in TITLE to count as generic DVR
            title_keywords = ['dvr', 'nvr', 'web viewer', 'network video', 'hikvision', 'dahua', 'ip camera', 'surveillance']
            for kw in title_keywords:
                if kw in title_text:
                    dvr_types = ['Suspected DVR (Title Match)']
                    detection_method = f"Title contains: {kw}"
                    detection_evidence.append({'brand': 'Generic Title', 'pattern': kw, 'matched_text': title_text})
                    break

            # Check for specific login form inputs combined with DVR terms
            if not dvr_types:
                if 'password' in content_lower and ('login' in content_lower or 'user' in content_lower):
                    # Only if it also looks like a DVR
                    suspicious_terms = ['onvif', 'rtsp', 'stream', 'channel', 'preview', 'playback']
                    for term in suspicious_terms:
                        if term in content_lower:
                            dvr_types = ['Suspected DVR (Login Page)']
                            detection_method = f"Login page with DVR term: {term}"
                            detection_evidence.append({'brand': 'Generic Login', 'pattern': f'login + {term}', 'matched_text': 'found login form'})
                            break
        
        # Not a DVR
        if not dvr_types:
            return None
        
        filtered_result = {
            'ip': result['ip'],
            'status_code': status_code,
            'headers': headers,
            'important_headers': important_headers,
            'page_content': page_content[:2000] if isinstance(page_content, str) else str(page_content)[:2000],
            'content_length': result.get('content_length', 0),
            'dvr_type': dvr_types,
            'detection_method': detection_method,
            'detection_signatures': detection_evidence,
            'scan_timestamp': datetime.now().isoformat(),
            'url': f"http://{result['ip']}:80"
        }
        
        server = headers.get('Server')
        if server:
            filtered_result['server_info'] = server
        
        if isinstance(page_content, str):
            title_match = re.search(r'<title[^>]*>(.*?)</title>', page_content, re.IGNORECASE)
            if title_match: 
                filtered_result['page_title'] = title_match.group(1).strip()[:200]
        
        return filtered_result

    def scan_single_ip(self, ip: str) -> Dict[str, Any]:
        if self.shutdown_requested: return None
        ip = ip.strip()
        if not ip: return None
        
        raw_result = None
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9',
                'Connection': 'close'
            }
            
            response = requests.get(
                f'http://{ip}:80', 
                timeout=5, 
                headers=headers, 
                verify=False,
                allow_redirects=True
            )
            
            decoded_content = self.safe_decode_content(response.content)
            
            raw_result = {
                'ip': ip, 'port': 80,
                'status_code': response.status_code,
                'reason': response.reason,
                'headers': dict(response.headers),
                'content': decoded_content,
                'content_length': len(response.content),
                'url': response.url,
                'encoding_detected': response.encoding or 'unknown'
            }
        except Exception as e:
            raw_result = {'ip': ip, 'port': 80, 'status_code': None, 'error': str(e)[:50]}
        
        dvr_result = None
        if raw_result and raw_result.get('status_code') is not None:
            dvr_result = self._check_if_dvr(raw_result)
        
        with self.results_lock:
            self.scanned_count += 1
            if raw_result.get('status_code') is None:
                self.failed_count += 1
                print(f"✗ [{self.scanned_count}/{self.total_ips}] {ip} - {raw_result.get('error', 'Error')}")
            else:
                status = raw_result['status_code']
                if dvr_result: 
                    self.dvr_results.append(dvr_result)
                    self.dvr_count += 1
                    types = ', '.join(dvr_result['dvr_type'])
                    print(f"🎯 [{self.scanned_count}/{self.total_ips}] DVR FOUND: {ip} | Status: {status} | Type: {types}")
                    if self.dvr_count - self.last_save_count >= self.save_interval:
                        self._save_data_internal(self.dvr_results)
                        self.last_save_count = self.dvr_count
                        print(f"💾 Auto-saved {len(self.dvr_results)} DVR results")
                else:
                    print(f"✓ [{self.scanned_count}/{self.total_ips}] {ip} - Status: {status} (not DVR)")
        
        return raw_result

    def scan_main(self, max_threads=None):
        threads_to_use = max_threads if max_threads is not None else self.max_threads
        self.print_banner()
        print(f"Starting DVR Scanner on {self.file} with {threads_to_use} threads...")

        try:
            content = self.file.read_text(encoding='utf-8')
        except:
            content = self.file.read_bytes().decode('utf-8', errors='ignore')
        
        ips = [ip.strip() for ip in content.strip().split('\n') if ip.strip()]
        self.total_ips = len(ips)
        
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=threads_to_use) as executor:
                self.executor = executor
                future_to_ip = {executor.submit(self.scan_single_ip, ip): ip for ip in ips}
                for future in concurrent.futures.as_completed(future_to_ip):
                    if self.shutdown_requested: break
                    try: future.result(timeout=30)
                    except: pass
        except KeyboardInterrupt:
            self._signal_handler(None, None)
        finally:
            self.executor = None
        
        self._print_summary(threads_to_use)
        return self.dvr_results

    def _print_summary(self, threads_used):
        print(f"\nScan Complete. Found {self.dvr_count} DVRs out of {self.scanned_count} scanned IPs.")
        if self.dvr_results:
            self.save_data(self.dvr_results)

    def extract_headers(self, headers):
        important_keys = ['Server', 'X-Powered-By', 'WWW-Authenticate']
        return {key: headers[key] for key in important_keys if key in headers}

    def detect_dvr_type_with_signatures(self, headers, content):
        '''
        STRICTER detection: Only matches explicit brand signatures or login page indicators.
        Removed generic words like 'camera', 'security' that match unrelated websites.
        '''
        dvr_signatures = {
            'Hikvision': [r'hikvision', r'hik\-?vision', r'doc/page/login\.asp', r'ivms', r'webcomponent'],
            'Dahua': [r'dahua', r'dahuasecurity', r'login\.cgi', r'guilogin\.cgi', r'web\.cgi', r'dss-web'],
            'Uniview': [r'uniview', r'uniarch', r'/LAPI/V1.0', r'program/login'],
            'Axis': [r'axis communications', r'axis network camera'],
            'Samsung/Hanwha': [r'hanwha', r'wisenet', r'samsung techwin'],
            'Avigilon': [r'avigilon'],
            'Mobotix': [r'mobotix'],
            'XMEye': [r'xmeye', r'cloud\.net'],
            'Generic Login': [
                r'login\.asp', r'login\.php', r'index\.asp', r'index\.html'
            ]
        }
        
        detected_dvrs = []
        detection_signatures = []
        
        try:
            headers_text = str(headers).lower()
            content_text = content.lower() if isinstance(content, str) else str(content).lower()
        except:
            return [], []

        # 1. Check for Brands in Title/Content/Headers
        for dvr_brand, patterns in dvr_signatures.items():
            for pattern in patterns:
                # Check match
                if re.search(pattern, content_text, re.IGNORECASE) or re.search(pattern, headers_text, re.IGNORECASE):
                    # ADDITIONAL FILTER: If it's a "Generic" signature, ensure it actually looks like a login page
                    if dvr_brand == 'Generic Login':
                        if 'user' not in content_text and 'password' not in content_text:
                            continue # Skip if it's just a file named login.php without login fields

                    if dvr_brand not in detected_dvrs:
                        detected_dvrs.append(dvr_brand)
                    detection_signatures.append({
                        'brand': dvr_brand,
                        'pattern': pattern,
                        'matched_text': 'pattern matched'
                    })
        
        return detected_dvrs, detection_signatures

def main():
    parser = argparse.ArgumentParser(description='DVR Scanner (Strict Mode)')
    parser.add_argument('-i', '--input', default='ips.txt', help='Input file')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Threads')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose')
    parser.add_argument('--save-interval', type=int, default=10, help='Save interval')
    parser.add_argument('-o', '--output', default='dvr_scan_results.json', help='Output file')
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
        output_txt=Path(args.output.replace('.json', '_ips.txt'))
    )
    scanner.scan_main()

if __name__ == "__main__":
    main()
