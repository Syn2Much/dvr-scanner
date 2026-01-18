import requests
from pathlib import Path
import json as js
from datetime import datetime
import re
import concurrent.futures
import threading
import argparse
import sys
from typing import List, Dict, Any

class FingerPrinter:   
    def __init__(self, file=Path('ips.txt'), max_threads=10, verbose=False):
        '''
        The main class to fingerprint and log http results for DVR devices
        '''
        self.file = file
        self.max_threads = max_threads
        self.verbose = verbose
        self.results_lock = threading.Lock()
        self.scanned_count = 0
        self.total_ips = 0
        self.dvr_count = 0
        
    def print_banner(self):
        '''Print program banner'''
        banner = r"""
    ╔═══════════════════════════════════════════════════════════════════════════════╗
    ║    ____________   ______________  ___________.__            .___              ║
    ║    \______ \   \ /   /\______   \ \_   _____/|__| ____    __| _/___________   ║
    ║    |    |  \   Y   /  |       _/  |    __)  |  |/    \  / __ |/ __ \_  __ \   ║
    ║    |    `   \     /   |    |   \  |     \   |  |   |  \/ /_/ \  ___/|  | \/   ║
    ║    /_______  /\___/    |____|_  /  \___  /   |__|___|  /\____ |\___  >__|     ║
    ║            \/                 \/       \/            \/      \/    \/         ║
    ║                         DVR Scanner & Fingerprinter                           ║
    ║                         v1.1 - Professional Edition                           ║
    ╚═══════════════════════════════════════════════════════════════════════════════╝    
"""
        print(banner)
        print(" " * 20 + "🔍 Scanning for DVR Devices\n")
        a
    def read_data(self):
        print(self.file.read_text(encoding='utf-8', errors='ignore'))
        
    def enc_data(self):
        code = js.JSONEncoder()
        try:
            content = self.file.read_text(encoding='utf-8')
        except UnicodeDecodeError:
            content = self.file.read_text(encoding='latin-1', errors='ignore')
        jsonData = code.encode(content)
        print(jsonData)
        return jsonData

    def save_data(self, data, output_file=Path('dvr_scan_results.json')):
        '''
        Saves only DVR scan results to a JSON file
        '''
        encoder = js.JSONEncoder(indent=2, ensure_ascii=False)
        json_data = encoder.encode(data)
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(json_data)
        print(f"DVR results saved to {output_file}")
        
        # Also save IPs to a text file
        self.save_ips_txt(data)

    def save_ips_txt(self, data, output_file=Path('dvr_ips.txt')):
        '''
        Save only the IP addresses of detected DVRs to a text file
        '''
        ips = [result['ip'] for result in data]
        with open(output_file, 'w', encoding='utf-8') as f:
            for ip in ips:
                f.write(f"{ip}\n")
        print(f"DVR IPs saved to {output_file}")

    def safe_decode_content(self, response_content: bytes) -> str:
        '''
        Safely decode response content trying multiple encodings
        '''
        # Common encodings for DVR devices (especially Chinese ones)
        encodings_to_try = [
            'utf-8',
            'gb2312',
            'gbk',
            'big5',      # Traditional Chinese
            'latin-1',
            'iso-8859-1',
            'cp1252',
            'shift_jis', # Japanese
            'euc-kr'     # Korean
        ]
        
        for encoding in encodings_to_try:
            try:
                return response_content.decode(encoding)
            except (UnicodeDecodeError, LookupError):
                continue
        
        # If all else fails, use replace strategy
        try:
            return response_content.decode('utf-8', errors='replace')
        except:
            # Last resort: represent as hex or skip
            return "[BINARY CONTENT - COULD NOT DECODE]"

    def scan_single_ip(self, ip: str) -> Dict[str, Any]:
        '''
        Scan a single IP address and return the result
        '''
        ip = ip.strip()
        if not ip:
            return None
            
        try:
            # Send GET request to each IP on port 80 with custom headers
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'close'
            }
            
            response = requests.get(f'http://{ip}:80', timeout=3, headers=headers, verify=False)
            
            # Safely decode the content
            decoded_content = self.safe_decode_content(response.content)
            
            # Collect full HTTP response data
            raw_result = {
                'ip': ip,
                'port': 80,
                'status_code': response.status_code,
                'reason': response.reason,
                'headers': dict(response.headers),
                'content': decoded_content,
                'content_length': len(response.content),
                'url': response.url,
                'encoding_detected': response.encoding or 'unknown'
            }
            
            # Thread-safe progress update
            with self.results_lock:
                self.scanned_count += 1
                print(f"✓ Scanned {ip}:80 - Status: {response.status_code} "
                      f"({self.scanned_count}/{self.total_ips})")
            
            return raw_result
            
        except requests.exceptions.SSLError:
            # Try HTTP if HTTPS fails
            try:
                headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                    'Accept-Language': 'en-US,en;q=0.5',
                    'Accept-Encoding': 'gzip, deflate',
                    'Connection': 'close'
                }
                response = requests.get(f'http://{ip}:80', timeout=3, headers=headers, verify=False)
                decoded_content = self.safe_decode_content(response.content)
                
                raw_result = {
                    'ip': ip,
                    'port': 80,
                    'status_code': response.status_code,
                    'reason': response.reason,
                    'headers': dict(response.headers),
                    'content': decoded_content,
                    'content_length': len(response.content),
                    'url': response.url,
                    'encoding_detected': response.encoding or 'unknown'
                }
                
                with self.results_lock:
                    self.scanned_count += 1
                    print(f"✓ Scanned {ip}:80 (SSL bypass) - Status: {response.status_code} "
                          f"({self.scanned_count}/{self.total_ips})")
                
                return raw_result
                
            except Exception as e:
                raw_result = {
                    'ip': ip,
                    'port': 80,
                    'status_code': None,
                    'error': str(e),
                }
                
                with self.results_lock:
                    self.scanned_count += 1
                    print(f"✗ Failed to scan {ip}:80 - Error: SSL/TLS issue")
                
                return raw_result
                
        except requests.exceptions.RequestException as e:
            raw_result = {
                'ip': ip,
                'port': 80,
                'status_code': None,
                'error': str(e),
            }
            
            # Thread-safe progress update
            with self.results_lock:
                self.scanned_count += 1
                print(f"✗ Failed to scan {ip}:80 - Error: {str(e)[:50]}... "
                      f"({self.scanned_count}/{self.total_ips})")
            
            return raw_result
        except Exception as e:
            raw_result = {
                'ip': ip,
                'port': 80,
                'status_code': None,
                'error': f"Unexpected error: {str(e)}",
            }
            
            with self.results_lock:
                self.scanned_count += 1
                print(f"✗ Failed to scan {ip}:80 - Unexpected error")
            
            return raw_result

    def scan_main(self, max_threads=None):
        '''
        Scans each IP address on port 80 and collects HTTP response data,
        filtering specifically for DVR devices
        
        Args:
            max_threads: Override the default thread count
        '''
        # Use provided thread count or default
        threads_to_use = max_threads if max_threads is not None else self.max_threads
        
        # Print banner
        self.print_banner()
        
        print(f"{'='*60}")
        print(f"Starting DVR Scanner")
        print(f"{'='*60}")
        print(f"Input file: {self.file}")
        print(f"Threads: {threads_to_use}")
        print(f"Verbose: {self.verbose}")
        print(f"Scan started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'='*60}\n")
        
        # Read IPs with encoding handling
        try:
            content = self.file.read_text(encoding='utf-8')
        except UnicodeDecodeError:
            # Try other common encodings if UTF-8 fails
            for encoding in ['latin-1', 'iso-8859-1', 'cp1252', 'gb2312', 'gbk']:
                try:
                    content = self.file.read_text(encoding=encoding)
                    print(f"Note: Input file read with {encoding} encoding")
                    break
                except:
                    continue
            else:
                # Last resort: read as binary and decode with errors='replace'
                content = self.file.read_bytes().decode('utf-8', errors='replace')
        
        ips = [ip.strip() for ip in content.strip().split('\n') if ip.strip()]
        self.total_ips = len(ips)
        self.scanned_count = 0
        self.dvr_count = 0
        self.failed_count = 0
        
        print(f"Loaded {self.total_ips} IP addresses from {self.file}")
        print(f"Starting scan with {threads_to_use} threads...\n")
        
        raw_results = []
        
        # Use ThreadPoolExecutor for parallel scanning
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads_to_use) as executor:
            # Submit all scanning tasks
            future_to_ip = {executor.submit(self.scan_single_ip, ip): ip for ip in ips}
            
            # Collect results as they complete
            for future in concurrent.futures.as_completed(future_to_ip):
                result = future.result()
                if result:
                    raw_results.append(result)
                    # Count failed scans (where status_code is None)
                    if result.get('status_code') is None:
                        self.failed_count += 1
        
        print(f"\n{'='*60}")
        print(f"Scan complete! Scanned {len(raw_results)} IP addresses.")
        
        # Filter for DVR devices only
        filtered_results = self.filter_dvr_results(raw_results)
        
        # Count successful scans (non-failed and with status code)
        successful_scans = len([r for r in raw_results if r.get('status_code') is not None])
        
        # Save only DVR results to JSON file and TXT file with IPs
        if filtered_results:
            self.save_data(filtered_results, Path('dvr_scan_results.json'))
            
            print(f"\n{'='*60}")
            print(f"SCAN COMPLETED")
            print(f"{'='*60}")
            print(f"Input File: {self.file}")
            print(f"Threads Used: {threads_to_use}")
            print(f"Scan Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"{'='*60}")
            
            # Statistics Section
            print(f"\n📊 SCAN STATISTICS")
            print(f"{'-'*60}")
            print(f"Total IPs in input file: {self.total_ips}")
            print(f"Successfully scanned: {successful_scans}")
            print(f"Failed to connect: {self.failed_count}")
            print(f"DVR devices detected: {self.dvr_count}")
            if successful_scans > 0:
                print(f"Non-DVR devices: {successful_scans - self.dvr_count}")
                print(f"Detection rate: {(self.dvr_count / successful_scans * 100):.1f}% of responsive hosts")
            else:
                print(f"Non-DVR devices: 0")
                print(f"Detection rate: 0.0% (no responsive hosts)")
            print(f"{'-'*60}")
            
            # File Output Section
            print(f"\n💾 OUTPUT FILES")
            print(f"{'-'*60}")
            json_file = Path('dvr_scan_results.json')
            txt_file = Path('dvr_ips.txt')
            print(f"JSON Results: {json_file.absolute()}")
            print(f"  - Contains: {len(filtered_results)} DVR entries")
            print(f"  - File size: {json_file.stat().st_size if json_file.exists() else 0:,} bytes")
            print(f"IP List: {txt_file.absolute()}")
            print(f"  - Contains: {self.dvr_count} IP addresses")
            print(f"  - File size: {txt_file.stat().st_size if txt_file.exists() else 0:,} bytes")
            print(f"{'-'*60}")
            
            # DVR Summary Section
            print(f"\n🎯 DVR DEVICES FOUND")
            print(f"{'-'*60}")
            if len(filtered_results) <= 20:  # Show all if 20 or fewer
                for i, dvr in enumerate(filtered_results, 1):
                    ip = dvr['ip']
                    status = dvr['status_code']
                    types = ', '.join(dvr['dvr_type'])
                    detection_method = dvr.get('detection_method', 'Unknown')
                    print(f"{i:3}. {ip:15} | Status: {status:3} | Type: {types:30} | Method: {detection_method}")
            else:  # Show summary for large lists
                print(f"Found {len(filtered_results)} DVR devices (showing first 10):")
                print(f"{'-'*60}")
                for i, dvr in enumerate(filtered_results[:10], 1):
                    ip = dvr['ip']
                    status = dvr['status_code']
                    types = ', '.join(dvr['dvr_type'])
                    detection_method = dvr.get('detection_method', 'Unknown')
                    print(f"{i:3}. {ip:15} | Status: {status:3} | Type: {types:30} | Method: {detection_method}")
                print(f"... and {len(filtered_results) - 10} more devices")
            
            print(f"{'-'*60}")
            
            # Brand Distribution (if verbose)
            if self.verbose and filtered_results:
                print(f"\n🏷️  BRAND DISTRIBUTION")
                print(f"{'-'*60}")
                brand_counts = {}
                for dvr in filtered_results:
                    for brand in dvr['dvr_type']:
                        brand_counts[brand] = brand_counts.get(brand, 0) + 1
                
                for brand, count in sorted(brand_counts.items(), key=lambda x: x[1], reverse=True):
                    percentage = (count / len(filtered_results)) * 100
                    print(f"{brand:30}: {count:3} ({percentage:.1f}%)")
                print(f"{'-'*60}")
                
            print(f"\n✅ Scan completed successfully!")
            
        else:
            print(f"\n{'='*60}")
            print(f"SCAN COMPLETED")
            print(f"{'='*60}")
            print(f"Input File: {self.file}")
            print(f"Threads Used: {threads_to_use}")
            print(f"Scan Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"{'='*60}")
            
            # Statistics Section
            print(f"\n📊 SCAN STATISTICS")
            print(f"{'-'*60}")
            print(f"Total IPs in input file: {self.total_ips}")
            print(f"Successfully scanned: {successful_scans}")
            print(f"Failed to connect: {self.failed_count}")
            print(f"DVR devices detected: 0")
            print(f"Non-DVR devices: {successful_scans}")
            print(f"{'-'*60}")
            
            # File Output Section
            print(f"\n💾 OUTPUT FILES")
            print(f"{'-'*60}")
            json_file = Path('dvr_scan_results.json')
            txt_file = Path('dvr_ips.txt')
            print(f"JSON Results: {json_file.absolute()}")
            print(f"  - Status: Empty file created (no DVRs found)")
            print(f"  - File size: {json_file.stat().st_size if json_file.exists() else 0:,} bytes")
            print(f"IP List: {txt_file.absolute()}")
            print(f"  - Status: Empty file created (no DVRs found)")
            print(f"  - File size: {txt_file.stat().st_size if txt_file.exists() else 0:,} bytes")
            print(f"{'-'*60}")
            
            print(f"\n⚠️  No DVR devices detected in the scanned IP addresses.")
            print(f"✅ Scan completed successfully!")
            
            # Create empty files if no DVRs found
            with open('dvr_scan_results.json', 'w', encoding='utf-8') as f:
                f.write('[]')
            with open('dvr_ips.txt', 'w', encoding='utf-8') as f:
                f.write('')
        
        # Return results as JSON (but don't print them)
        encoder = js.JSONEncoder(indent=2, ensure_ascii=False)
        json_results = encoder.encode(filtered_results)
            
        return json_results

    def extract_headers(self, headers):
        '''
        Extract important HTTP headers for fingerprinting
        '''
        important_keys = [
            'Server',
            'X-Powered-By',
            'X-AspNet-Version',
            'X-Runtime',
            'Content-Type',
            'Set-Cookie',
            'WWW-Authenticate',
            'X-Frame-Options',
            'X-Content-Type-Options',
            'Strict-Transport-Security',
            'Access-Control-Allow-Origin',
            'Cache-Control'
        ]
        
        extracted = {}
        for key in important_keys:
            if key in headers:  
                extracted[key] = headers[key]
        
        return extracted

    def detect_dvr_type_with_signatures(self, headers, content):
        '''
        Detect DVR device type from headers and page content
        Returns: (detected_brands, detection_signatures)
        '''
        dvr_signatures = {
            'Hikvision': [
                r'hikvision',
                r'hik\-?vision',
                r'ds\-?\d{1,}',
                r'nvr\d{3,}',
                r'dvr\d{3,}',
                r'sadp',
                r'plug\-?play',
                r'iVMS',
                r'weboperator',
                r'ISAPI',
                r'/SDK/',
                r'rtsp://.*\.dav'
            ],
            'Dahua': [
                r'dahua',
                r'dahuasecurity',
                r'hcvr',
                r'hdvr',
                r'dhip',
                r'dss_lite',
                r'configManager\.cgi',
                r'login\.cgi',
                r'videotest\.cgi'
            ],
            'Uniview': [
                r'uniview',
                r'uniarch',
                r'NVR\d{3,}',
                r'ivms\-?4200',
                r'easy7',
                r'easyview'
            ],
            'Axis': [
                r'axis',
                r'axis communications',
                r'vapix',
                r'axis\-cgi/'
            ],
            'Bosch': [
                r'bosch',
                r'bosch security',
                r'divar',
                r'dynacord',
                r'videojet'
            ],
            'Samsung/Hanwha': [
                r'hanwha',
                r'wisenet',
                r'smartvss',
                r'snr\-',
                r'xvr\-'
            ],
            'Honeywell': [
                r'honeywell',
                r'equinox',
                r'maxpro',
                r'pro\-watch',
                r'hren',
                r'digital sentry'
            ],
            'Pelco': [
                r'pelco',
                r'pelco security',
                r'spectra',
                r'sarix',
                r'videoXpert'
            ],
            'Vivotek': [
                r'vivotek',
                r'vivoview',
                r'cc9',
                r'fd9'
            ],
            'Sony': [
                r'sony security',
                r'snc\-',
                r'srx\-'
            ],
            'Panasonic': [
                r'panasonic',
                r'wj\-',
                r'bl\-',
                r'wv\-'
            ],
            'Generic DVR/NVR': [
                r'dvr.*login',
                r'nvr.*login',
                r'ip camera',
                r'webcam',
                r'surveillance',
                r'cctv',
                r'/viewer\.html?',
                r'/live\.html?',
                r'/main\.html?',
                r'/login\.asp',
                r'/login\.php',
                r'/login\.html',
                r'/webadmin\.',
                r'web\s?interface',
                r'video\s?server',
                r'onvif',
                r'rtsp://',
                r'rtmp://',
                r'监控',
                r'安防',
                r'录像机',
                r'摄像机'
            ]
        }
        
        detected_dvrs = []
        detection_signatures = []
        
        # Combine text for searching (handle encoding issues)
        try:
            headers_text = str(headers).lower()
            content_text = content.lower() if isinstance(content, str) else str(content).lower()
            combined_text = f"{headers_text} {content_text}"
        except:
            # If encoding fails, use string representation
            combined_text = f"{headers} {content}"
        
        for dvr_brand, patterns in dvr_signatures.items():
            for pattern in patterns:
                try:
                    if re.search(pattern, combined_text, re.IGNORECASE):
                        if dvr_brand not in detected_dvrs:
                            detected_dvrs.append(dvr_brand)
                        # Store the actual matched pattern
                        match = re.search(pattern, combined_text, re.IGNORECASE)
                        if match:
                            matched_text = match.group(0)[:100]  # First 100 chars
                            detection_signatures.append({
                                'brand': dvr_brand,
                                'pattern': pattern,
                                'matched_text': matched_text
                            })
                except Exception as e:
                    # Skip problematic patterns
                    continue
        
        # Additional keyword check for Chinese DVRs
        chinese_keywords = ['监控', '安防', '录像', '摄像']
        if isinstance(content, str):
            for keyword in chinese_keywords:
                if keyword in content:
                    if 'Generic DVR/NVR' not in detected_dvrs:
                        detected_dvrs.append('Generic DVR/NVR')
                    detection_signatures.append({
                        'brand': 'Generic DVR/NVR',
                        'pattern': f'Chinese keyword: {keyword}',
                        'matched_text': keyword
                    })
                    break
        
        return detected_dvrs, detection_signatures

    def filter_dvr_results(self, raw_results):
        '''
        Filter raw scan results to only include DVR devices
        '''
        filtered = []
        
        for result in raw_results: 
            # Skip failed requests
            if result.get('status_code') is None:
                continue
            
            # Accept all status codes including errors
            status_code = result.get('status_code')
            
            # Extract important headers
            headers = result.get('headers', {})
            important_headers = self.extract_headers(headers)
            
            # Get page content (already decoded)
            page_content = result.get('content', '')
            
            # Detect DVR type with signatures
            dvr_types, detection_signatures = self.detect_dvr_type_with_signatures(headers, page_content)
            
            # Determine detection method and collect evidence
            detection_method = "Unknown"
            detection_evidence = []
            
            # 1. Explicitly detected DVR type
            if dvr_types:
                detection_method = "Pattern match"
                detection_evidence = detection_signatures
            
            # 2. Check for DVR keywords in ANY part of response
            elif not dvr_types:
                all_text = f"{headers} {page_content}".lower()
                dvr_keywords = ['dvr', 'nvr', 'camera', '监控', '安防', 'surveillance', 
                               'security', 'ipcam', 'onvif', 'rtsp', 'cctv']
                
                found_keywords = []
                for keyword in dvr_keywords:
                    if keyword in all_text:
                        found_keywords.append(keyword)
                        # Find where it was found
                        idx = all_text.find(keyword)
                        context_start = max(0, idx - 20)
                        context_end = min(len(all_text), idx + len(keyword) + 20)
                        context = all_text[context_start:context_end].strip()
                        detection_evidence.append({
                            'brand': 'Keyword detection',
                            'pattern': f'Keyword: {keyword}',
                            'matched_text': context
                        })
                
                # If at least 2 DVR keywords found, include it
                if len(found_keywords) >= 2:
                    dvr_types = ['Suspected DVR/NVR']
                    detection_method = f"Keyword match ({len(found_keywords)} keywords: {', '.join(found_keywords[:5])})"
            
            # 3. Check for specific headers that indicate DVRs
            elif not dvr_types:
                server_header = headers.get('Server', '').lower()
                dvr_server_indicators = ['dvr', 'nvr', 'camera', 'security']
                for indicator in dvr_server_indicators:
                    if indicator in server_header:
                        dvr_types = ['Suspected DVR/NVR (Server header)']
                        detection_method = f"Server header contains: {indicator}"
                        detection_evidence.append({
                            'brand': 'Server header analysis',
                            'pattern': f'Server contains: {indicator}',
                            'matched_text': server_header[:200]
                        })
                        break
            
            # 4. Check for common DVR authentication headers
            elif not dvr_types:
                if 'WWW-Authenticate' in headers:
                    auth_header = headers.get('WWW-Authenticate', '').lower()
                    auth_indicators = ['camera', 'dvr', 'nvr', 'ip']
                    for indicator in auth_indicators:
                        if indicator in auth_header:
                            dvr_types = ['Suspected DVR/NVR (Auth header)']
                            detection_method = f"Auth header contains: {indicator}"
                            detection_evidence.append({
                                'brand': 'Authentication header',
                                'pattern': f'WWW-Authenticate contains: {indicator}',
                                'matched_text': auth_header[:200]
                            })
                            break
            
            if dvr_types:
                # Create the filtered result with detection details
                filtered_result = {
                    'ip': result['ip'],
                    'status_code': status_code,
                    'headers': headers,
                    'important_headers': important_headers,
                    'page_content': page_content[:2000] if isinstance(page_content, str) else str(page_content)[:2000],
                    'content_length': result['content_length'],
                    'dvr_type': dvr_types,
                    'detection_method': detection_method,
                    'detection_signatures': detection_evidence,
                    'scan_timestamp': datetime.now().isoformat(),
                    'url': f"http://{result['ip']}:80"
                }
                
                # Add server info if available
                server = headers.get('Server')
                if server:
                    filtered_result['server_info'] = server
                
                # Extract page title if available
                if isinstance(page_content, str):
                    title_match = re.search(r'<title[^>]*>(.*?)</title>', page_content, re.IGNORECASE)
                    if title_match:
                        filtered_result['page_title'] = title_match.group(1).strip()[:200]
                
                filtered.append(filtered_result)
                
                # Thread-safe DVR found logging
                with self.results_lock:
                    self.dvr_count += 1
                    ip = result['ip']
                    status = status_code
                    types = ', '.join(dvr_types)
                    
                    if self.verbose:
                        print(f"\n{'!'*60}")
                        print(f"DVR FOUND: {ip}")
                        print(f"{'-'*60}")
                        print(f"Status Code: {status}")
                        print(f"DVR Type(s): {types}")
                        print(f"Detection Method: {detection_method}")
                        print(f"Content Length: {result['content_length']:,} bytes")
                        
                        # Show detection evidence
                        if detection_evidence:
                            print(f"\nDetection Evidence:")
                            for i, evidence in enumerate(detection_evidence[:3], 1):
                                print(f"  {i}. {evidence.get('brand', 'Unknown')}:")
                                print(f"     Pattern: {evidence.get('pattern', 'N/A')}")
                                print(f"     Matched: {evidence.get('matched_text', 'N/A')[:80]}...")
                        
                        # Show server header if present
                        server = headers.get('Server', 'Not found')
                        if server != 'Not found':
                            print(f"Server: {server}")
                            
                        # Show title if in content
                        if isinstance(page_content, str):
                            title_match = re.search(r'<title[^>]*>(.*?)</title>', page_content, re.IGNORECASE)
                            if title_match:
                                print(f"Title: {title_match.group(1)[:100]}")
                        print(f"{'!'*60}\n")
                    else:
                        print(f"🎯 DVR FOUND: {ip} | Status: {status} | Type: {types} | Method: {detection_method}")
        
        return filtered


def main():
    # Set up command line arguments
    parser = argparse.ArgumentParser(
        description='DVR Scanner - Fingerprint and log DVR devices from IP list',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  %(prog)s                    # Use default settings (10 threads)
  %(prog)s -t 20              # Use 20 threads
  %(prog)s -t 50 -v           # Use 50 threads with verbose output
  %(prog)s -i custom.txt -t 30  # Scan custom IP list with 30 threads
        '''
    )
    
    parser.add_argument('-i', '--input', default='ips.txt',
                       help='Input file with IP addresses (one per line)')
    parser.add_argument('-t', '--threads', type=int, default=10,
                       help='Number of threads to use (default: 10)')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Enable verbose output showing full DVR details')
    parser.add_argument('--version', action='version', version='DVR Scanner v1.1')
    
    # Parse arguments
    args = parser.parse_args()
    
    # Check if input file exists
    input_file = Path(args.input)
    if not input_file.exists():
        print(f"Error: Input file '{args.input}' not found!")
        print(f"Please create '{args.input}' with IP addresses (one per line)")
        sys.exit(1)
    
    # Check thread count is reasonable
    if args.threads < 1:
        print("Error: Thread count must be at least 1")
        sys.exit(1)
    if args.threads > 200:
        print(f"Warning: {args.threads} threads is very high!")
        response = input("Continue anyway? (y/n): ")
        if response.lower() != 'y':
            print("Scan cancelled")
            sys.exit(0)
    
    # Suppress SSL warnings for DVRs with self-signed certs
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    try:
        # Create and run the scanner
        scanner = FingerPrinter(
            file=input_file,
            max_threads=args.threads,
            verbose=args.verbose
        )
        
        # Run the scan
        results = scanner.scan_main()
        
    except KeyboardInterrupt:
        print(f"\n\n⚠️  Scan interrupted by user!")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Error during scan: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
