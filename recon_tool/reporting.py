"""
Reporting Module
================
Generates comprehensive reports in HTML and TXT format with all gathered information.

Supports multiple report formats and includes timestamps, IP resolution details,
and organized presentation of all reconnaissance data.

Usage:
    from reporting import ReportGenerator
    
    generator = ReportGenerator(
        domain="example.com",
        results={...}
    )
    generator.generate_html_report()
    generator.generate_text_report()
"""

import os
import json
import logging
from typing import Dict, Any, Optional
from datetime import datetime
from html import escape

logger = logging.getLogger(__name__)


class ReportGenerator:
    """
    Report generator for creating comprehensive reconnaissance reports.
    
    Supports HTML and TXT output formats with detailed formatting,
    styling, and organization of reconnaissance data.
    
    Attributes:
        domain (str): Target domain
        results (dict): Comprehensive reconnaissance results
        timestamp (datetime): Report generation timestamp
    """
    
    def __init__(self, domain: str, results: Optional[Dict[str, Any]] = None,
                 output_dir: str = 'reports'):
        """
        Initialize report generator.
        
        Args:
            domain: Target domain for the report
            results: Dictionary containing reconnaissance results
            output_dir: Directory to store generated reports
        """
        self.domain = domain
        self.results = results or {}
        self.output_dir = output_dir
        self.timestamp = datetime.now()
        
        # Create output directory if it doesn't exist
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
        
        logger.debug(f"ReportGenerator initialized for domain: {domain}")
    
    def add_results(self, module_name: str, module_results: Dict[str, Any]):
        """
        Add reconnaissance module results to the report.
        
        Args:
            module_name: Name of the reconnaissance module
            module_results: Results from the module
        """
        self.results[module_name] = module_results
        logger.debug(f"Added results from {module_name}")
    
    def _generate_html_header(self) -> str:
        """
        Generate HTML document header.
        
        Returns:
            HTML header string
        """
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reconnaissance Report - {escape(self.domain)}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background-color: #f5f5f5;
            padding: 20px;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            padding: 40px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        
        header {{
            border-bottom: 3px solid #2c3e50;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }}
        
        h1 {{
            color: #2c3e50;
            font-size: 2.5em;
            margin-bottom: 10px;
        }}
        
        .report-meta {{
            color: #666;
            font-size: 0.95em;
        }}
        
        .report-meta p {{
            margin: 5px 0;
        }}
        
        h2 {{
            color: #34495e;
            border-left: 4px solid #3498db;
            padding-left: 15px;
            margin-top: 40px;
            margin-bottom: 20px;
            font-size: 1.8em;
        }}
        
        h3 {{
            color: #34495e;
            margin-top: 25px;
            margin-bottom: 15px;
            font-size: 1.3em;
        }}
        
        .section {{
            margin-bottom: 30px;
            padding-bottom: 20px;
            border-bottom: 1px solid #ecf0f1;
        }}
        
        .section:last-child {{
            border-bottom: none;
        }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
        }}
        
        th {{
            background-color: #3498db;
            color: white;
            padding: 12px;
            text-align: left;
            font-weight: 600;
        }}
        
        td {{
            padding: 10px 12px;
            border-bottom: 1px solid #ecf0f1;
        }}
        
        tr:hover {{
            background-color: #f9f9f9;
        }}
        
        .data-list {{
            list-style: none;
            padding: 0;
        }}
        
        .data-list li {{
            padding: 10px 0;
            border-bottom: 1px solid #ecf0f1;
        }}
        
        .data-list li:before {{
            content: "▹ ";
            color: #3498db;
            font-weight: bold;
            margin-right: 8px;
        }}
        
        .highlight {{
            background-color: #ecf0f1;
            padding: 15px;
            border-left: 4px solid #3498db;
            margin: 15px 0;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
            overflow-x: auto;
        }}
        
        .tag {{
            display: inline-block;
            background-color: #3498db;
            color: white;
            padding: 4px 10px;
            border-radius: 4px;
            font-size: 0.85em;
            margin: 3px;
        }}
        
        .tag.warning {{
            background-color: #e74c3c;
        }}
        
        .tag.success {{
            background-color: #27ae60;
        }}
        
        .empty-section {{
            color: #999;
            font-style: italic;
            padding: 15px;
            background-color: #f9f9f9;
            border-left: 4px solid #999;
        }}
        
        footer {{
            margin-top: 50px;
            padding-top: 20px;
            border-top: 1px solid #ecf0f1;
            text-align: center;
            color: #666;
            font-size: 0.9em;
        }}
        
        .security-score {{
            display: inline-block;
            font-size: 2em;
            font-weight: bold;
            padding: 10px 20px;
            border-radius: 4px;
            margin: 10px 0;
        }}
        
        .score-high {{
            background-color: #27ae60;
            color: white;
        }}
        
        .score-medium {{
            background-color: #f39c12;
            color: white;
        }}
        
        .score-low {{
            background-color: #e74c3c;
            color: white;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Reconnaissance Report</h1>
            <div class="report-meta">
                <p><strong>Target Domain:</strong> {escape(self.domain)}</p>
                <p><strong>Report Generated:</strong> {self.timestamp.strftime('%Y-%m-%d %H:%M:%S')}</p>
                <p><strong>Report Type:</strong> Comprehensive Reconnaissance Assessment</p>
            </div>
        </header>
"""
    
    def _generate_html_footer(self) -> str:
        """
        Generate HTML document footer.
        
        Returns:
            HTML footer string
        """
        return """
        <footer>
            <p>ReconMaster - Modular Reconnaissance Tool v1.0.0</p>
            <p><em>This report is intended for authorized security testing only.</em></p>
            <p>Generated on {}</p>
        </footer>
    </div>
</body>
</html>
""".format(self.timestamp.strftime('%Y-%m-%d %H:%M:%S'))
    
    def _generate_whois_html(self) -> str:
        """Generate WHOIS section in HTML."""
        if 'whois' not in self.results:
            return ""
        
        whois_data = self.results['whois']
        if not whois_data.get('success'):
            return f"""
        <section class="section">
            <h2>WHOIS Information</h2>
            <div class="empty-section">WHOIS lookup failed: {escape(str(whois_data.get('error', 'Unknown error')))}</div>
        </section>
"""
        
        data = whois_data.get('data', {})
        html = """
        <section class="section">
            <h2>WHOIS Information</h2>
            <table>
                <tr>
                    <th>Field</th>
                    <th>Value</th>
                </tr>
"""
        
        fields = [
            ('Registrar', data.get('registrar')),
            ('Creation Date', data.get('creation_date')),
            ('Expiration Date', data.get('expiration_date')),
            ('Updated Date', data.get('updated_date')),
            ('Status', ', '.join(data.get('status', []))),
        ]
        
        for label, value in fields:
            if value:
                html += f"                <tr><td>{label}</td><td>{escape(str(value))}</td></tr>\n"
        
        if data.get('name_servers'):
            ns_list = ', '.join(data['name_servers'])
            html += f"                <tr><td>Name Servers</td><td>{escape(ns_list)}</td></tr>\n"
        
        html += """            </table>
        </section>
"""
        return html
    
    def _generate_dns_html(self) -> str:
        """Generate DNS section in HTML."""
        if 'dns' not in self.results:
            return ""
        
        dns_data = self.results['dns']
        if not dns_data.get('success'):
            return f"""
        <section class="section">
            <h2>DNS Enumeration</h2>
            <div class="empty-section">DNS enumeration failed: {escape(str(dns_data.get('error', 'Unknown error')))}</div>
        </section>
"""
        
        html = """
        <section class="section">
            <h2>DNS Enumeration</h2>
"""
        
        if dns_data.get('ip_addresses'):
            html += f"""            <h3>IP Addresses</h3>
            <div class="highlight">{escape(', '.join(dns_data['ip_addresses']))}</div>
"""
        
        for rtype, records in dns_data.get('records', {}).items():
            if records:
                html += f"""            <h3>{rtype} Records</h3>
            <ul class="data-list">
"""
                for record in records:
                    html += f"                <li>{escape(str(record))}</li>\n"
                html += "            </ul>\n"
        
        html += """        </section>
"""
        return html
    
    def _generate_subdomains_html(self) -> str:
        """Generate subdomains section in HTML."""
        if 'subdomains' not in self.results:
            return ""
        
        sub_data = self.results['subdomains']
        if not sub_data.get('success'):
            return f"""
        <section class="section">
            <h2>Subdomain Enumeration</h2>
            <div class="empty-section">Subdomain enumeration failed: {escape(str(sub_data.get('error', 'Unknown error')))}</div>
        </section>
"""
        
        html = f"""
        <section class="section">
            <h2>Subdomain Enumeration</h2>
            <p>Total subdomains found: <span class="tag">{len(sub_data.get('subdomains', []))}</span></p>
            <h3>Discovered Subdomains</h3>
            <ul class="data-list">
"""
        
        for subdomain in sub_data.get('subdomains', [])[:100]:
            ips = sub_data.get('resolved', {}).get(subdomain, [])
            ip_str = f" → {', '.join(ips)}" if ips else ""
            html += f"                <li>{escape(subdomain)}{escape(ip_str)}</li>\n"
        
        if len(sub_data.get('subdomains', [])) > 100:
            html += f"                <li><em>... and {len(sub_data['subdomains']) - 100} more</em></li>\n"
        
        html += """            </ul>
        </section>
"""
        return html
    
    def _generate_ports_html(self) -> str:
        """Generate port scan section in HTML."""
        if 'ports' not in self.results:
            return ""
        
        port_data = self.results['ports']
        if not port_data.get('success'):
            return f"""
        <section class="section">
            <h2>Port Scanning</h2>
            <div class="empty-section">Port scan failed: {escape(str(port_data.get('error', 'Unknown error')))}</div>
        </section>
"""
        
        html = f"""
        <section class="section">
            <h2>Port Scanning</h2>
            <p>
                <strong>Target IP:</strong> {escape(port_data.get('target_ip', 'N/A'))}<br>
                <strong>Scan Type:</strong> {escape(port_data.get('scan_type', 'N/A'))}<br>
                <strong>Ports Scanned:</strong> {port_data.get('total_scanned', 0)}<br>
                <strong>Open Ports:</strong> <span class="tag">{len(port_data.get('open_ports', []))}</span>
            </p>
"""
        
        if port_data.get('open_ports'):
            html += """            <table>
                <tr>
                    <th>Port</th>
                    <th>State</th>
                    <th>Service</th>
                </tr>
"""
            for port_info in port_data['open_ports']:
                html += f"""                <tr>
                    <td>{port_info['port']}</td>
                    <td><span class="tag success">{port_info['state']}</span></td>
                    <td>{escape(port_info.get('service', 'unknown'))}</td>
                </tr>
"""
            html += """            </table>
"""
        else:
            html += """            <div class="empty-section">No open ports found</div>
"""
        
        html += """        </section>
"""
        return html
    
    def _generate_banners_html(self) -> str:
        """Generate banner grabbing section in HTML."""
        if 'banners' not in self.results:
            return ""
        
        banner_data = self.results['banners']
        if not banner_data.get('success'):
            return f"""
        <section class="section">
            <h2>Banner Grabbing</h2>
            <div class="empty-section">Banner grabbing failed: {escape(str(banner_data.get('error', 'Unknown error')))}</div>
        </section>
"""
        
        html = f"""
        <section class="section">
            <h2>Banner Grabbing</h2>
            <p>Services identified: <span class="tag">{len(banner_data.get('banners', []))}</span></p>
"""
        
        if banner_data.get('banners'):
            for banner_info in banner_data['banners']:
                html += f"""            <h3>Port {banner_info['port']}/{banner_info['protocol']}</h3>
"""
                if banner_info.get('banner'):
                    banner_display = escape(banner_info['banner'][:500])
                    if len(banner_info['banner']) > 500:
                        banner_display += '...'
                    html += f"""            <div class="highlight">{banner_display}</div>
"""
                if banner_info.get('ssl_info'):
                    ssl = banner_info['ssl_info']
                    html += """            <p><strong>SSL Information:</strong></p>
            <ul class="data-list">
"""
                    if ssl.get('subject'):
                        html += f"                <li>Subject: {escape(str(ssl['subject']))}</li>\n"
                    if ssl.get('issuer'):
                        html += f"                <li>Issuer: {escape(str(ssl['issuer']))}</li>\n"
                    if ssl.get('notAfter'):
                        html += f"                <li>Expires: {escape(ssl['notAfter'])}</li>\n"
                    html += """            </ul>
"""
        else:
            html += """            <div class="empty-section">No banners retrieved</div>
"""
        
        html += """        </section>
"""
        return html
    
    def _generate_tech_html(self) -> str:
        """Generate technology detection section in HTML."""
        if 'technologies' not in self.results:
            return ""
        
        tech_data = self.results['technologies']
        if not tech_data.get('success'):
            return f"""
        <section class="section">
            <h2>Technology Detection</h2>
            <div class="empty-section">Technology detection failed: {escape(str(tech_data.get('error', 'Unknown error')))}</div>
        </section>
"""
        
        score = tech_data.get('security_score', 0)
        score_class = 'score-high' if score >= 70 else ('score-medium' if score >= 40 else 'score-low')
        
        html = f"""
        <section class="section">
            <h2>Technology Detection</h2>
            <p><strong>Server:</strong> {escape(tech_data.get('server', 'Not disclosed'))}</p>
            <p><strong>HTTPS:</strong> {('✓ Available' if tech_data.get('https_available') else '✗ Not Available')}</p>
            <div class="security-score {score_class}">Security Score: {score}/100</div>
"""
        
        if tech_data.get('technologies'):
            html += """            <h3>Detected Technologies</h3>
            <p>
"""
            for tech in tech_data['technologies']:
                html += f"                <span class=\"tag\">{escape(tech)}</span>\n"
            html += """            </p>
"""
        
        if tech_data.get('security_headers'):
            html += """            <h3>Security Headers</h3>
            <table>
                <tr>
                    <th>Header</th>
                    <th>Value</th>
                </tr>
"""
            for header, value in tech_data['security_headers'].items():
                value_display = escape(value[:100]) + ('...' if len(value) > 100 else '')
                html += f"""                <tr>
                    <td>{escape(header)}</td>
                    <td><code>{value_display}</code></td>
                </tr>
"""
            html += """            </table>
"""
        
        html += """        </section>
"""
        return html
    
    def generate_html_report(self, filename: Optional[str] = None) -> str:
        """
        Generate comprehensive HTML report.
        
        Args:
            filename: Custom filename (default: domain_timestamp.html)
            
        Returns:
            Path to generated report
        """
        if not filename:
            timestamp = self.timestamp.strftime('%Y%m%d_%H%M%S')
            filename = os.path.join(self.output_dir, f"{self.domain}_report_{timestamp}.html")
        else:
            filename = os.path.join(self.output_dir, filename)
        
        logger.info(f"Generating HTML report: {filename}")
        
        html_content = self._generate_html_header()
        
        # Add sections
        html_content += self._generate_whois_html()
        html_content += self._generate_dns_html()
        html_content += self._generate_subdomains_html()
        html_content += self._generate_ports_html()
        html_content += self._generate_banners_html()
        html_content += self._generate_tech_html()
        
        html_content += self._generate_html_footer()
        
        # Write to file
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        logger.info(f"HTML report saved: {filename}")
        return filename
    
    def generate_text_report(self, filename: Optional[str] = None) -> str:
        """
        Generate comprehensive text report.
        
        Args:
            filename: Custom filename (default: domain_timestamp.txt)
            
        Returns:
            Path to generated report
        """
        if not filename:
            timestamp = self.timestamp.strftime('%Y%m%d_%H%M%S')
            filename = os.path.join(self.output_dir, f"{self.domain}_report_{timestamp}.txt")
        else:
            filename = os.path.join(self.output_dir, filename)
        
        logger.info(f"Generating text report: {filename}")
        
        lines = [
            "=" * 80,
            "RECONNAISSANCE REPORT",
            "=" * 80,
            f"Target Domain: {self.domain}",
            f"Report Generated: {self.timestamp.strftime('%Y-%m-%d %H:%M:%S')}",
            f"Tool: ReconMaster v1.0.0",
            "=" * 80,
            ""
        ]
        
        # WHOIS section
        if 'whois' in self.results:
            whois_data = self.results['whois']
            lines.append("WHOIS INFORMATION")
            lines.append("-" * 80)
            if whois_data.get('success'):
                data = whois_data.get('data', {})
                lines.append(f"Registrar: {data.get('registrar', 'N/A')}")
                lines.append(f"Creation Date: {data.get('creation_date', 'N/A')}")
                lines.append(f"Expiration Date: {data.get('expiration_date', 'N/A')}")
                lines.append(f"Updated Date: {data.get('updated_date', 'N/A')}")
                if data.get('name_servers'):
                    lines.append(f"Name Servers: {', '.join(data['name_servers'])}")
                if data.get('status'):
                    lines.append(f"Status: {', '.join(data['status'])}")
            else:
                lines.append(f"Error: {whois_data.get('error', 'Unknown error')}")
            lines.append("")
        
        # DNS section
        if 'dns' in self.results:
            dns_data = self.results['dns']
            lines.append("DNS ENUMERATION")
            lines.append("-" * 80)
            if dns_data.get('success'):
                if dns_data.get('ip_addresses'):
                    lines.append(f"IP Addresses: {', '.join(dns_data['ip_addresses'])}")
                for rtype, records in dns_data.get('records', {}).items():
                    if records:
                        lines.append(f"\n{rtype} Records:")
                        for record in records:
                            lines.append(f"  {record}")
            else:
                lines.append(f"Error: {dns_data.get('error', 'Unknown error')}")
            lines.append("")
        
        # Subdomains section
        if 'subdomains' in self.results:
            sub_data = self.results['subdomains']
            lines.append("SUBDOMAIN ENUMERATION")
            lines.append("-" * 80)
            if sub_data.get('success'):
                lines.append(f"Total Subdomains Found: {len(sub_data.get('subdomains', []))}")
                lines.append(f"Sources Used: {', '.join(sub_data.get('sources_used', []))}")
                lines.append("\nSubdomains:")
                for subdomain in sub_data.get('subdomains', [])[:50]:
                    ips = sub_data.get('resolved', {}).get(subdomain, [])
                    ip_str = f" → {', '.join(ips)}" if ips else ""
                    lines.append(f"  {subdomain}{ip_str}")
                if len(sub_data.get('subdomains', [])) > 50:
                    lines.append(f"  ... and {len(sub_data['subdomains']) - 50} more")
            else:
                lines.append(f"Error: {sub_data.get('error', 'Unknown error')}")
            lines.append("")
        
        # Port section
        if 'ports' in self.results:
            port_data = self.results['ports']
            lines.append("PORT SCANNING")
            lines.append("-" * 80)
            if port_data.get('success'):
                lines.append(f"Target IP: {port_data.get('target_ip', 'N/A')}")
                lines.append(f"Scan Type: {port_data.get('scan_type', 'N/A')}")
                lines.append(f"Total Ports Scanned: {port_data.get('total_scanned', 0)}")
                lines.append(f"Open Ports: {len(port_data.get('open_ports', []))}")
                if port_data.get('open_ports'):
                    lines.append("\nOpen Ports:")
                    for port_info in port_data['open_ports']:
                        lines.append(f"  {port_info['port']}/tcp  {port_info['state']}  {port_info.get('service', 'unknown')}")
                else:
                    lines.append("No open ports found")
            else:
                lines.append(f"Error: {port_data.get('error', 'Unknown error')}")
            lines.append("")
        
        # Banners section
        if 'banners' in self.results:
            banner_data = self.results['banners']
            lines.append("BANNER GRABBING")
            lines.append("-" * 80)
            if banner_data.get('success'):
                lines.append(f"Services Identified: {len(banner_data.get('banners', []))}")
                for banner_info in banner_data['banners']:
                    lines.append(f"\nPort {banner_info['port']}/{banner_info['protocol']}:")
                    if banner_info.get('banner'):
                        lines.append(f"  {banner_info['banner'][:200]}")
                    if banner_info.get('ssl_info'):
                        ssl = banner_info['ssl_info']
                        if ssl.get('subject'):
                            lines.append(f"  SSL Subject: {ssl['subject']}")
                        if ssl.get('notAfter'):
                            lines.append(f"  SSL Expires: {ssl['notAfter']}")
                if not banner_data.get('banners'):
                    lines.append("No banners retrieved")
            else:
                lines.append(f"Error: {banner_data.get('error', 'Unknown error')}")
            lines.append("")
        
        # Technology section
        if 'technologies' in self.results:
            tech_data = self.results['technologies']
            lines.append("TECHNOLOGY DETECTION")
            lines.append("-" * 80)
            if tech_data.get('success'):
                lines.append(f"Server: {tech_data.get('server', 'Not disclosed')}")
                lines.append(f"HTTPS: {'Available' if tech_data.get('https_available') else 'Not Available'}")
                lines.append(f"Security Score: {tech_data.get('security_score', 0)}/100")
                if tech_data.get('technologies'):
                    lines.append("\nDetected Technologies:")
                    for tech in tech_data['technologies']:
                        lines.append(f"  • {tech}")
                if tech_data.get('security_headers'):
                    lines.append("\nSecurity Headers:")
                    for header, value in tech_data['security_headers'].items():
                        lines.append(f"  {header}: {value[:100]}")
            else:
                lines.append(f"Error: {tech_data.get('error', 'Unknown error')}")
            lines.append("")
        
        # Footer
        lines.extend([
            "=" * 80,
            "END OF REPORT",
            "=" * 80,
            f"Report generated on {self.timestamp.strftime('%Y-%m-%d %H:%M:%S')}",
            "ReconMaster - Modular Reconnaissance Tool v1.0.0",
            "For authorized security testing only."
        ])
        
        # Write to file
        with open(filename, 'w', encoding='utf-8') as f:
            f.write('\n'.join(lines))
        
        logger.info(f"Text report saved: {filename}")
        return filename
    
    def generate_json_report(self, filename: Optional[str] = None) -> str:
        """
        Generate comprehensive JSON report.
        
        Args:
            filename: Custom filename (default: domain_timestamp.json)
            
        Returns:
            Path to generated report
        """
        if not filename:
            timestamp = self.timestamp.strftime('%Y%m%d_%H%M%S')
            filename = os.path.join(self.output_dir, f"{self.domain}_report_{timestamp}.json")
        else:
            filename = os.path.join(self.output_dir, filename)
        
        logger.info(f"Generating JSON report: {filename}")
        
        report = {
            'metadata': {
                'domain': self.domain,
                'timestamp': self.timestamp.isoformat(),
                'tool': 'ReconMaster',
                'version': '1.0.0'
            },
            'results': self.results
        }
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, default=str)
        
        logger.info(f"JSON report saved: {filename}")
        return filename


# CLI functionality when run directly
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Report Generator")
    parser.add_argument("domain", help="Target domain")
    parser.add_argument("-j", "--json-file", help="JSON file with results")
    parser.add_argument("-o", "--output-dir", default="reports", help="Output directory")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    args = parser.parse_args()
    
    # Configure logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=log_level, format='%(asctime)s - %(levelname)s - %(message)s')
    
    # Load results if provided
    results = {}
    if args.json_file:
        with open(args.json_file, 'r') as f:
            results = json.load(f)
    
    # Generate reports
    generator = ReportGenerator(args.domain, results, args.output_dir)
    print(f"HTML Report: {generator.generate_html_report()}")
    print(f"Text Report: {generator.generate_text_report()}")
    print(f"JSON Report: {generator.generate_json_report()}")
