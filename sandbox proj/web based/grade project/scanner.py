#!/usr/bin/env python3
"""
NETWORK SECURITY SCANNER - CLI VERSION (FIXED FOR WINDOWS)
Scans 192.168.9.0/24 for vulnerabilities and generates reports
NO FAKE DATA - REAL SCANNING ONLY
"""

import subprocess
import socket
import threading
import nmap
import json
import os
from datetime import datetime
from queue import Queue, Empty
import platform

# ============================================================================
# CONFIGURATION
# ============================================================================

NETWORK_SUBNET = "192.168.9.0/24"
PORTS_TO_SCAN = "21,22,23,25,53,80,110,143,443,445,3306,3389,5900,8080,8443"
RESULTS_DIR = "scan_results"

# ============================================================================
# 1. HOST DISCOVERY MODULE (FIXED FOR WINDOWS)
# ============================================================================

class HostDiscovery:
    """Discovers live hosts using ICMP ping"""
    
    def __init__(self, subnet):
        self.subnet = subnet
        self.live_hosts = []
        self.lock = threading.Lock()
    
    def discover(self):
        """Discover all live hosts"""
        print(f"\n🔍 [STEP 1] Discovering hosts on {self.subnet}...")
        print("   (This may take 2-3 minutes)\n")
        
        # Extract IP range
        base = '.'.join(self.subnet.split('/')[0].split('.')[0:3])
        ips = [f"{base}.{i}" for i in range(1, 255)]
        
        # Create worker threads
        queue = Queue()
        threads = []
        
        for _ in range(30):
            t = threading.Thread(target=self._worker, args=(queue,), daemon=True)
            threads.append(t)
            t.start()
        
        # Add IPs to queue
        for ip in ips:
            queue.put(ip)
        
        # Wait for completion
        queue.join()
        
        # Sort results
        self.live_hosts.sort(key=lambda x: int(x.split('.')[-1]))
        
        print(f"\n✅ Discovery complete! Found {len(self.live_hosts)} live hosts\n")
        return self.live_hosts
    
    def _worker(self, queue):
        """Worker thread for pinging"""
        while True:
            try:
                ip = queue.get(timeout=1)
                if self._ping(ip):
                    with self.lock:
                        self.live_hosts.append(ip)
                    print(f"  ✓ {ip}")
                queue.task_done()
            except Empty:
                break
            except:
                break
    
    def _ping(self, ip):
        """Ping a single host - FIXED FOR WINDOWS"""
        try:
            # Windows ping command (fixed)
            result = subprocess.run(
                ['ping', '-n', '1', '-w', '500', ip],
                capture_output=True,
                timeout=2
            )
            return result.returncode == 0
        except:
            return False

# ============================================================================
# 2. PORT SCANNING MODULE
# ============================================================================

class PortScanner:
    """Scans ports using Nmap"""
    
    def __init__(self):
        try:
            self.nm = nmap.PortScanner()
            print("\n✅ Nmap initialized successfully")
        except Exception as e:
            print(f"\n❌ ERROR: Nmap not found or error!")
            print(f"   Error: {str(e)}")
            print(f"   Please install Nmap from https://nmap.org\n")
            exit(1)
    
    def scan_hosts(self, hosts, ports):
        """Scan all discovered hosts"""
        print(f"\n🔍 [STEP 2] Scanning {len(hosts)} hosts for open ports...")
        print(f"   Ports: {ports}\n")
        
        results = []
        
        for idx, host in enumerate(hosts, 1):
            print(f"  [{idx}/{len(hosts)}] Scanning {host}...")
            result = self._scan_host(host, ports)
            results.append(result)
            
            if result['open_ports']:
                print(f"      ✓ Found {len(result['open_ports'])} open ports")
            else:
                print(f"      ○ No open ports found")
        
        print(f"\n✅ Port scanning complete!\n")
        return results
    
    def _scan_host(self, ip, ports):
        """Scan single host"""
        result = {
            'ip': ip,
            'hostname': self._resolve_hostname(ip),
            'status': 'unknown',
            'open_ports': [],
            'services': []
        }
        
        try:
            self.nm.scan(ip, ports, arguments='-sV')
            
            if ip in self.nm.all_hosts():
                result['status'] = 'up'
                
                for proto in self.nm[ip].all_protocols():
                    for port in self.nm[ip][proto].keys():
                        port_info = self.nm[ip][proto][port]
                        
                        if port_info['state'] == 'open':
                            result['open_ports'].append(port)
                            result['services'].append({
                                'port': port,
                                'protocol': proto,
                                'service': port_info.get('name', 'unknown'),
                                'product': port_info.get('product', ''),
                                'version': port_info.get('version', '')
                            })
            else:
                result['status'] = 'down'
        
        except Exception as e:
            result['status'] = 'error'
            result['error'] = str(e)
        
        return result
    
    def _resolve_hostname(self, ip):
        """Resolve hostname"""
        try:
            return socket.gethostbyaddr(ip)[0]
        except:
            return ip

# ============================================================================
# 3. VULNERABILITY DETECTION MODULE
# ============================================================================

class VulnerabilityDetector:
    """Detects vulnerabilities based on scan results"""
    
    @staticmethod
    def analyze(scan_results):
        """Analyze scan results for vulnerabilities"""
        print("\n🔍 [STEP 3] Analyzing vulnerabilities...\n")
        
        vulnerabilities = []
        
        for host in scan_results:
            if host['status'] != 'up' or not host['open_ports']:
                continue
            
            # Check for Telnet
            if 23 in host['open_ports']:
                vulnerabilities.append({
                    'severity': 'CRITICAL',
                    'host': host['ip'],
                    'port': 23,
                    'service': 'Telnet',
                    'title': 'Telnet Service Detected',
                    'description': 'Telnet transmits credentials in plaintext. This is a CRITICAL security risk.',
                    'cvss': 9.8,
                    'solution': 'Disable Telnet and use SSH instead',
                    'commands': [
                        'systemctl stop telnetd',
                        'systemctl disable telnetd',
                        'apt-get remove telnetd'
                    ]
                })
                print(f"  🔴 CRITICAL: Telnet found on {host['ip']}")
            
            # Check for FTP
            if 21 in host['open_ports']:
                vulnerabilities.append({
                    'severity': 'HIGH',
                    'host': host['ip'],
                    'port': 21,
                    'service': 'FTP',
                    'title': 'FTP Service Detected',
                    'description': 'FTP transmits credentials in plaintext.',
                    'cvss': 7.5,
                    'solution': 'Replace FTP with SFTP or SCP',
                    'commands': [
                        'systemctl stop vsftpd',
                        'systemctl disable vsftpd'
                    ]
                })
                print(f"  🟠 HIGH: FTP found on {host['ip']}")
            
            # Check for SMB
            if 445 in host['open_ports']:
                vulnerabilities.append({
                    'severity': 'HIGH',
                    'host': host['ip'],
                    'port': 445,
                    'service': 'SMB',
                    'title': 'SMB/Windows File Sharing Exposed',
                    'description': 'Windows file sharing is exposed to the network.',
                    'cvss': 7.0,
                    'solution': 'Restrict SMB access or use firewall rules',
                    'commands': [
                        'netsh advfirewall firewall add rule name="Block SMB" dir=in action=block protocol=TCP localport=445'
                    ]
                })
                print(f"  🟠 HIGH: SMB exposed on {host['ip']}")
            
            # Check for unencrypted HTTP
            if 80 in host['open_ports'] and 443 not in host['open_ports']:
                vulnerabilities.append({
                    'severity': 'MEDIUM',
                    'host': host['ip'],
                    'port': 80,
                    'service': 'HTTP',
                    'title': 'Unencrypted HTTP Service',
                    'description': 'Web traffic is not encrypted with HTTPS.',
                    'cvss': 5.3,
                    'solution': 'Enable HTTPS with SSL/TLS certificate',
                    'commands': [
                        'certbot certonly --standalone',
                        'Configure web server for HTTPS'
                    ]
                })
                print(f"  🟡 MEDIUM: Unencrypted HTTP on {host['ip']}")
            
            # Check for MySQL remote access
            if 3306 in host['open_ports']:
                vulnerabilities.append({
                    'severity': 'MEDIUM',
                    'host': host['ip'],
                    'port': 3306,
                    'service': 'MySQL',
                    'title': 'MySQL Remote Access Enabled',
                    'description': 'MySQL database is accessible from the network.',
                    'cvss': 5.0,
                    'solution': 'Bind MySQL to localhost only',
                    'commands': [
                        'Edit /etc/mysql/mysql.conf.d/mysqld.cnf',
                        'Set: bind-address = 127.0.0.1',
                        'systemctl restart mysql'
                    ]
                })
                print(f"  🟡 MEDIUM: MySQL remote access on {host['ip']}")
        
        print(f"\n✅ Analysis complete! Found {len(vulnerabilities)} vulnerabilities\n")
        return vulnerabilities

# ============================================================================
# 4. REPORT GENERATION MODULE
# ============================================================================

class ReportGenerator:
    """Generates HTML reports"""
    
    def __init__(self, output_dir):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
    
    def generate_report(self, scan_data, vulnerabilities):
        """Generate HTML report"""
        print("\n📄 [STEP 4] Generating HTML report...\n")
        
        timestamp = datetime.now()
        filename = f"scan_report_{timestamp.strftime('%Y%m%d_%H%M%S')}.html"
        filepath = os.path.join(self.output_dir, filename)
        
        html = self._build_html(scan_data, vulnerabilities, timestamp)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html)
        
        abs_path = os.path.abspath(filepath)
        print(f"  ✅ Report saved: {abs_path}\n")
        
        return abs_path
    
    def _build_html(self, scan_data, vulnerabilities, timestamp):
        """Build HTML content"""
        
        # Build hosts table
        hosts_rows = ""
        for host in scan_data:
            if host['status'] == 'up':
                ports_str = ', '.join(map(str, host['open_ports'])) if host['open_ports'] else 'None'
                hosts_rows += f"""
                <tr>
                    <td>{host['ip']}</td>
                    <td>{host['hostname']}</td>
                    <td>{len(host['open_ports'])}</td>
                    <td>{ports_str}</td>
                </tr>
                """
        
        # Build vulnerability cards
        vuln_cards = ""
        for vuln in vulnerabilities:
            severity_color = {
                'CRITICAL': '#dc3545',
                'HIGH': '#fd7e14',
                'MEDIUM': '#ffc107',
                'LOW': '#28a745'
            }.get(vuln['severity'], '#6c757d')
            
            commands_html = '<br>'.join(f'<code>{cmd}</code>' for cmd in vuln['commands'])
            
            vuln_cards += f"""
            <div class="vuln-card" style="border-left: 4px solid {severity_color}">
                <div class="vuln-header">
                    <span class="badge" style="background: {severity_color}">{vuln['severity']}</span>
                    <h3>{vuln['title']}</h3>
                </div>
                <p><strong>Host:</strong> {vuln['host']}</p>
                <p><strong>Port:</strong> {vuln['port']} ({vuln['service']})</p>
                <p><strong>CVSS Score:</strong> {vuln['cvss']}/10</p>
                <p><strong>Description:</strong> {vuln['description']}</p>
                <p><strong>Solution:</strong> {vuln['solution']}</p>
                <div class="commands">
                    <strong>Fix Commands:</strong><br>
                    {commands_html}
                </div>
            </div>
            """
        
        # Calculate summary stats
        total_hosts = len([h for h in scan_data if h['status'] == 'up'])
        total_ports = sum(len(h['open_ports']) for h in scan_data)
        critical = sum(1 for v in vulnerabilities if v['severity'] == 'CRITICAL')
        high = sum(1 for v in vulnerabilities if v['severity'] == 'HIGH')
        medium = sum(1 for v in vulnerabilities if v['severity'] == 'MEDIUM')
        low = sum(1 for v in vulnerabilities if v['severity'] == 'LOW')
        
        # Security score
        max_score = 100
        deductions = (critical * 30) + (high * 15) + (medium * 5) + (low * 2)
        security_score = max(0, max_score - deductions)
        
        # HTML template
        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Network Security Scan Report - {timestamp.strftime('%Y-%m-%d %H:%M:%S')}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f5f5f5; padding: 20px; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; border-radius: 10px; box-shadow: 0 0 20px rgba(0,0,0,0.1); overflow: hidden; }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 40px; text-align: center; }}
        .header h1 {{ font-size: 2.5em; margin-bottom: 10px; }}
        .content {{ padding: 40px; }}
        .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 30px 0; }}
        .stat-card {{ background: #f8f9fa; padding: 20px; border-radius: 10px; text-align: center; border-left: 4px solid #667eea; }}
        .stat-value {{ font-size: 3em; font-weight: bold; color: #667eea; }}
        .stat-label {{ color: #6c757d; margin-top: 10px; }}
        .security-score {{ text-align: center; margin: 40px 0; }}
        .score-value {{ font-size: 5em; font-weight: bold; color: {('#28a745' if security_score >= 70 else '#ffc107' if security_score >= 40 else '#dc3545')}; }}
        table {{ width: 100%; border-collapse: collapse; margin: 30px 0; }}
        th {{ background: #667eea; color: white; padding: 15px; text-align: left; }}
        td {{ padding: 12px 15px; border-bottom: 1px solid #dee2e6; }}
        tr:hover {{ background: #f8f9fa; }}
        .vuln-card {{ background: #fff; border-radius: 10px; padding: 20px; margin: 20px 0; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }}
        .vuln-header {{ display: flex; align-items: center; gap: 15px; margin-bottom: 15px; }}
        .badge {{ padding: 5px 15px; border-radius: 20px; color: white; font-weight: bold; font-size: 0.9em; }}
        .commands {{ background: #f8f9fa; padding: 15px; border-radius: 5px; margin-top: 15px; }}
        code {{ background: #e9ecef; padding: 2px 6px; border-radius: 3px; font-family: 'Courier New', monospace; }}
        h2 {{ color: #667eea; margin: 40px 0 20px 0; padding-bottom: 10px; border-bottom: 2px solid #667eea; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Network Security Scan Report</h1>
            <p>Network: {NETWORK_SUBNET}</p>
            <p>Scan Date: {timestamp.strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
        
        <div class="content">
            <div class="security-score">
                <h2>Security Score</h2>
                <div class="score-value">{security_score}/100</div>
                <p style="color: #6c757d; margin-top: 10px;">
                    {'✅ Good security posture' if security_score >= 70 else '⚠️ Moderate security concerns' if security_score >= 40 else '🔴 Critical security issues'}
                </p>
            </div>
            
            <h2>📊 Executive Summary</h2>
            <div class="summary">
                <div class="stat-card">
                    <div class="stat-value">{total_hosts}</div>
                    <div class="stat-label">Hosts Discovered</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{total_ports}</div>
                    <div class="stat-label">Open Ports</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{len(vulnerabilities)}</div>
                    <div class="stat-label">Vulnerabilities</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value" style="color: #dc3545;">{critical}</div>
                    <div class="stat-label">Critical Issues</div>
                </div>
            </div>
            
            <h2>🖥️ Discovered Hosts</h2>
            <table>
                <thead>
                    <tr>
                        <th>IP Address</th>
                        <th>Hostname</th>
                        <th>Open Ports</th>
                        <th>Ports List</th>
                    </tr>
                </thead>
                <tbody>
                    {hosts_rows if hosts_rows else '<tr><td colspan="4">No hosts with open ports found</td></tr>'}
                </tbody>
            </table>
            
            <h2>⚠️ Vulnerabilities Found ({len(vulnerabilities)})</h2>
            {vuln_cards if vuln_cards else '<p>✅ No vulnerabilities detected!</p>'}
            
            <h2>📈 Severity Breakdown</h2>
            <div class="summary">
                <div class="stat-card" style="border-left-color: #dc3545;">
                    <div class="stat-value" style="color: #dc3545;">{critical}</div>
                    <div class="stat-label">Critical</div>
                </div>
                <div class="stat-card" style="border-left-color: #fd7e14;">
                    <div class="stat-value" style="color: #fd7e14;">{high}</div>
                    <div class="stat-label">High</div>
                </div>
                <div class="stat-card" style="border-left-color: #ffc107;">
                    <div class="stat-value" style="color: #ffc107;">{medium}</div>
                    <div class="stat-label">Medium</div>
                </div>
                <div class="stat-card" style="border-left-color: #28a745;">
                    <div class="stat-value" style="color: #28a745;">{low}</div>
                    <div class="stat-label">Low</div>
                </div>
            </div>
        </div>
    </div>
</body>
</html>
        """
        
        return html

# ============================================================================
# 5. MAIN SCANNER CLASS
# ============================================================================

class NetworkSecurityScanner:
    """Main scanner orchestrator"""
    
    def __init__(self):
        self.subnet = NETWORK_SUBNET
        self.ports = PORTS_TO_SCAN
        self.results_dir = RESULTS_DIR
    
    def run(self):
        """Run complete scan"""
        print("\n" + "="*70)
        print("🛡️  NETWORK SECURITY SCANNER - CLI VERSION")
        print("="*70)
        print(f"\nNetwork: {self.subnet}")
        print(f"Ports: {self.ports}")
        print(f"Results: {self.results_dir}/")
        print("\n" + "="*70)
        
        try:
            # Step 1: Discover hosts
            discovery = HostDiscovery(self.subnet)
            live_hosts = discovery.discover()
            
            if not live_hosts:
                print("\n⚠️  No live hosts found! Exiting.\n")
                return
            
            # Step 2: Scan ports
            scanner = PortScanner()
            scan_results = scanner.scan_hosts(live_hosts, self.ports)
            
            # Step 3: Analyze vulnerabilities
            detector = VulnerabilityDetector()
            vulnerabilities = detector.analyze(scan_results)
            
            # Step 4: Generate report
            report_gen = ReportGenerator(self.results_dir)
            report_path = report_gen.generate_report(scan_results, vulnerabilities)
            
            # Summary
            print("="*70)
            print("✅ SCAN COMPLETE!")
            print("="*70)
            print(f"\n📊 Summary:")
            print(f"   • Hosts found: {len(live_hosts)}")
            print(f"   • Vulnerabilities: {len(vulnerabilities)}")
            print(f"   • Report: {report_path}")
            print(f"\n💡 Open the HTML report in your browser to view detailed results.")
            print("\n" + "="*70 + "\n")
            
        except KeyboardInterrupt:
            print("\n\n⚠️  Scan interrupted by user.\n")
        except Exception as e:
            print(f"\n\n❌ ERROR: {str(e)}\n")
            import traceback
            traceback.print_exc()

# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

if __name__ == "__main__":
    scanner = NetworkSecurityScanner()
    scanner.run()