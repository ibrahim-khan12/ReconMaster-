#!/usr/bin/env python3
"""
ReconMaster - Modular Reconnaissance Tool
==========================================

A lightweight, modular CLI-based reconnaissance tool for automating
initial information gathering during penetration testing engagements.

Usage:
    python reconmaster.py example.com
    python reconmaster.py example.com --all
    python reconmaster.py example.com --whois --dns --subdomains
    python reconmaster.py example.com --ports --tech -v
    python reconmaster.py example.com --full-scan --output results.html
"""

import argparse
import sys
import os
import logging
from typing import Dict, Any, Optional

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from recon_tool.modules.passive import WhoisLookup, DNSEnumerator, SubdomainEnumerator
from recon_tool.modules.active import PortScanner, BannerGrabber, TechDetector
from recon_tool.reporting import ReportGenerator
from recon_tool.utils import setup_logging, log_section, log_subsection, log_result


class ReconMaster:
    """Main reconnaissance tool orchestrator."""
    
    def __init__(self, domain: str, verbosity: int = 0):
        """
        Initialize ReconMaster.
        
        Args:
            domain: Target domain
            verbosity: Logging verbosity level
        """
        self.domain = domain.lower().strip()
        self.verbosity = verbosity
        self.logger = setup_logging('ReconMaster', verbosity=verbosity)
        self.results = {}
    
    def run_whois(self) -> bool:
        """Run WHOIS lookup."""
        try:
            log_subsection(self.logger, "WHOIS Lookup")
            whois = WhoisLookup(self.domain)
            result = whois.lookup()
            self.results['whois'] = result
            
            if result['success']:
                self.logger.info(f"✓ WHOIS lookup completed")
                return True
            else:
                self.logger.warning(f"✗ WHOIS lookup failed: {result.get('error')}")
                return False
        except Exception as e:
            self.logger.error(f"WHOIS error: {e}")
            return False
    
    def run_dns(self) -> bool:
        """Run DNS enumeration."""
        try:
            log_subsection(self.logger, "DNS Enumeration")
            dns = DNSEnumerator(self.domain)
            result = dns.enumerate()
            self.results['dns'] = result
            
            if result['success']:
                self.logger.info(f"✓ DNS enumeration completed")
                if result.get('ip_addresses'):
                    self.logger.info(f"  Found {len(result['ip_addresses'])} IP address(es)")
                    self.logger.info(f"  IPs: {', '.join(result['ip_addresses'])}")
                for rtype, records in result.get('records', {}).items():
                    if records:
                        self.logger.info(f"  {rtype}: {len(records)} record(s)")
                return True
            else:
                self.logger.warning(f"✗ DNS enumeration failed: {result.get('error')}")
                return False
        except Exception as e:
            self.logger.error(f"DNS error: {e}")
            return False
    
    def run_subdomains(self) -> bool:
        """Run subdomain enumeration."""
        try:
            log_subsection(self.logger, "Subdomain Enumeration")
            subenum = SubdomainEnumerator(self.domain)
            result = subenum.enumerate(bruteforce=self.verbosity >= 1)
            self.results['subdomains'] = result
            
            if result['success']:
                self.logger.info(f"✓ Subdomain enumeration completed")
                self.logger.info(f"  Found {result.get('total_found', 0)} subdomain(s)")
                # Show first 10 subdomains
                for subdomain in result.get('subdomains', [])[:10]:
                    ips = result.get('resolved', {}).get(subdomain, [])
                    ip_str = f" → {', '.join(ips)}" if ips else ""
                    self.logger.debug(f"  {subdomain}{ip_str}")
                return True
            else:
                self.logger.warning(f"✗ Subdomain enumeration failed: {result.get('error')}")
                return False
        except Exception as e:
            self.logger.error(f"Subdomain enumeration error: {e}")
            return False
    
    def run_ports(self) -> bool:
        """Run port scanning."""
        try:
            log_subsection(self.logger, "Port Scanning")
            scanner = PortScanner(self.domain, timeout=2.0, threads=100)
            result = scanner.scan(scan_type='extended' if self.verbosity > 0 else 'common')
            self.results['ports'] = result
            
            if result['success']:
                self.logger.info(f"✓ Port scan completed")
                self.logger.info(f"  Target IP: {result.get('target_ip')}")
                self.logger.info(f"  Ports scanned: {result.get('total_scanned')}")
                self.logger.info(f"  Open ports: {len(result.get('open_ports', []))}")
                for port_info in result.get('open_ports', []):
                    self.logger.debug(f"    {port_info['port']}/tcp open {port_info.get('service', 'unknown')}")
                return True
            else:
                self.logger.warning(f"✗ Port scan failed: {result.get('error')}")
                return False
        except Exception as e:
            self.logger.error(f"Port scan error: {e}")
            return False
    
    def run_banner_grab(self) -> bool:
        """Run banner grabbing."""
        try:
            log_subsection(self.logger, "Banner Grabbing")
            grabber = BannerGrabber(self.domain, timeout=5.0)
            result = grabber.grab()
            self.results['banners'] = result
            
            if result['success']:
                self.logger.info(f"✓ Banner grabbing completed")
                self.logger.info(f"  Services identified: {len(result.get('banners', []))}")
                for banner_info in result.get('banners', []):
                    self.logger.debug(f"    Port {banner_info['port']}: {banner_info.get('banner', 'No banner')[:100]}")
                return True
            else:
                self.logger.warning(f"✗ Banner grabbing failed: {result.get('error')}")
                return False
        except Exception as e:
            self.logger.error(f"Banner grabbing error: {e}")
            return False
    
    def run_tech_detect(self) -> bool:
        """Run technology detection."""
        try:
            log_subsection(self.logger, "Technology Detection")
            detector = TechDetector(self.domain, timeout=10)
            result = detector.detect()
            self.results['technologies'] = result
            
            if result['success']:
                self.logger.info(f"✓ Technology detection completed")
                self.logger.info(f"  Server: {result.get('server', 'Not disclosed')}")
                self.logger.info(f"  HTTPS: {'Available' if result.get('https_available') else 'Not available'}")
                self.logger.info(f"  Technologies found: {len(result.get('technologies', []))}")
                self.logger.info(f"  Security score: {result.get('security_score', 0)}/100")
                for tech in result.get('technologies', [])[:10]:
                    self.logger.debug(f"    • {tech}")
                return True
            else:
                self.logger.warning(f"✗ Technology detection failed: {result.get('error')}")
                return False
        except Exception as e:
            self.logger.error(f"Technology detection error: {e}")
            return False
    
    def run_full_scan(self) -> bool:
        """Run complete reconnaissance."""
        results = {
            'WHOIS': self.run_whois(),
            'DNS': self.run_dns(),
            'Subdomains': self.run_subdomains(),
            'Ports': self.run_ports(),
            'Banners': self.run_banner_grab(),
            'Technologies': self.run_tech_detect(),
        }
        
        log_section(self.logger, "RECONNAISSANCE SUMMARY")
        successful = sum(1 for v in results.values() if v)
        total = len(results)
        self.logger.info(f"Modules completed: {successful}/{total}")
        
        for module, success in results.items():
            status = "✓" if success else "✗"
            self.logger.info(f"  {status} {module}")
        
        return successful > 0
    
    def generate_reports(self, output_format: str = 'all', output_file: Optional[str] = None) -> list:
        """
        Generate reconnaissance reports.
        
        Args:
            output_format: Report format (html, txt, json, all)
            output_file: Custom output filename (without extension)
            
        Returns:
            List of generated report files
        """
        log_section(self.logger, "GENERATING REPORTS")
        
        generator = ReportGenerator(self.domain, self.results)
        generated_files = []
        
        try:
            if output_format in ['html', 'all']:
                if output_file:
                    filename = f"{output_file}.html"
                else:
                    filename = None
                file = generator.generate_html_report(filename)
                generated_files.append(file)
                self.logger.info(f"✓ HTML report: {file}")
        except Exception as e:
            self.logger.error(f"HTML report error: {e}")
        
        try:
            if output_format in ['txt', 'all']:
                if output_file:
                    filename = f"{output_file}.txt"
                else:
                    filename = None
                file = generator.generate_text_report(filename)
                generated_files.append(file)
                self.logger.info(f"✓ Text report: {file}")
        except Exception as e:
            self.logger.error(f"Text report error: {e}")
        
        try:
            if output_format in ['json', 'all']:
                if output_file:
                    filename = f"{output_file}.json"
                else:
                    filename = None
                file = generator.generate_json_report(filename)
                generated_files.append(file)
                self.logger.info(f"✓ JSON report: {file}")
        except Exception as e:
            self.logger.error(f"JSON report error: {e}")
        
        return generated_files


def main():
    """Main entry point."""
    
    parser = argparse.ArgumentParser(
        prog='ReconMaster',
        description='Modular Reconnaissance Tool for Penetration Testing',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s example.com                    # Run passive recon
  %(prog)s example.com --all              # Run all modules
  %(prog)s example.com --whois --dns      # Run specific modules
  %(prog)s example.com --ports --tech -v  # Run with verbose output
  %(prog)s example.com --full-scan --output report.html  # Generate HTML report
  %(prog)s example.com --active           # Run active recon (ports, banners, tech)
  %(prog)s example.com --passive          # Run passive recon (whois, dns, subdomains)
        """
    )
    
    # Positional argument
    parser.add_argument('domain', help='Target domain or hostname')
    
    # Reconnaissance modules
    parser.add_argument('--whois', action='store_true', help='Run WHOIS lookup')
    parser.add_argument('--dns', action='store_true', help='Run DNS enumeration')
    parser.add_argument('--subdomains', action='store_true', help='Run subdomain enumeration')
    parser.add_argument('--ports', action='store_true', help='Run port scanning')
    parser.add_argument('--banners', action='store_true', help='Run banner grabbing')
    parser.add_argument('--tech', action='store_true', help='Run technology detection')
    
    # Convenience options
    parser.add_argument('--passive', action='store_true', 
                       help='Run all passive recon modules (whois, dns, subdomains)')
    parser.add_argument('--active', action='store_true',
                       help='Run all active recon modules (ports, banners, tech)')
    parser.add_argument('--all', action='store_true',
                       help='Run all reconnaissance modules')
    parser.add_argument('--full-scan', action='store_true',
                       help='Alias for --all')
    
    # Reporting options
    parser.add_argument('-o', '--output', type=str,
                       help='Output report filename (without extension)')
    parser.add_argument('-f', '--format', choices=['html', 'txt', 'json', 'all'],
                       default='all', help='Report format')
    parser.add_argument('--no-report', action='store_true',
                       help='Skip report generation')
    
    # Advanced options
    parser.add_argument('-v', '--verbose', action='count', default=0,
                       help='Increase verbosity (use -vv for more verbose)')
    parser.add_argument('--timeout', type=int, default=10,
                       help='Connection timeout in seconds (default: 10)')
    parser.add_argument('--threads', type=int, default=100,
                       help='Number of scanning threads (default: 100)')
    
    # Parse arguments
    args = parser.parse_args()
    
    # Create tool instance
    tool = ReconMaster(args.domain, verbosity=args.verbose)
    
    # Log startup information
    log_section(tool.logger, f"RECONMASTER - Reconnaissance Tool v1.0.0")
    tool.logger.info(f"Target: {tool.domain}")
    tool.logger.info(f"Verbosity: {args.verbose}")
    
    # Determine which modules to run
    modules_to_run = []
    
    if args.all or args.full_scan:
        modules_to_run = ['whois', 'dns', 'subdomains', 'ports', 'banners', 'tech']
    else:
        if args.passive:
            modules_to_run.extend(['whois', 'dns', 'subdomains'])
        if args.active:
            modules_to_run.extend(['ports', 'banners', 'tech'])
        
        # Individual modules
        if args.whois:
            modules_to_run.append('whois')
        if args.dns:
            modules_to_run.append('dns')
        if args.subdomains:
            modules_to_run.append('subdomains')
        if args.ports:
            modules_to_run.append('ports')
        if args.banners:
            modules_to_run.append('banners')
        if args.tech:
            modules_to_run.append('tech')
    
    # If no modules specified, run passive recon
    if not modules_to_run:
        tool.logger.info("No modules specified, running passive reconnaissance...")
        modules_to_run = ['whois', 'dns', 'subdomains']
    
    # Remove duplicates while preserving order
    modules_to_run = list(dict.fromkeys(modules_to_run))
    
    tool.logger.info(f"Modules to run: {', '.join(modules_to_run)}")
    tool.logger.info("")
    
    # Run selected modules
    success = True
    module_functions = {
        'whois': tool.run_whois,
        'dns': tool.run_dns,
        'subdomains': tool.run_subdomains,
        'ports': tool.run_ports,
        'banners': tool.run_banner_grab,
        'tech': tool.run_tech_detect,
    }
    
    for module in modules_to_run:
        if module in module_functions:
            try:
                module_functions[module]()
            except KeyboardInterrupt:
                tool.logger.warning("\nInterrupted by user")
                success = False
                break
            except Exception as e:
                tool.logger.error(f"Error running {module}: {e}")
    
    # Generate reports
    if success and not args.no_report and tool.results:
        try:
            tool.generate_reports(output_format=args.format, output_file=args.output)
        except Exception as e:
            tool.logger.error(f"Report generation error: {e}")
    
    # Final summary
    tool.logger.info("")
    log_section(tool.logger, "RECONNAISSANCE COMPLETED")
    tool.logger.info(f"Modules executed: {len([m for m in modules_to_run if tool.results.get(m.replace('-', ''))])}")
    tool.logger.info("Thank you for using ReconMaster!")


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n[*] Interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"[!] Fatal error: {e}", file=sys.stderr)
        sys.exit(1)
