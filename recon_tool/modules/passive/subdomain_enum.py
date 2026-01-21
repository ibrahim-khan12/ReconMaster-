"""
Subdomain Enumeration Module
============================
Performs subdomain enumeration using external APIs and certificate transparency logs.

Sources:
- crt.sh (Certificate Transparency)
- AlienVault OTX
- HackerTarget
- ThreatCrowd (legacy)

Usage:
    from modules.passive import SubdomainEnumerator
    
    subenum = SubdomainEnumerator(domain="example.com")
    result = subenum.enumerate()
"""

import socket
import ssl
import json
import logging
import re
from typing import Dict, Any, List, Set, Optional
from datetime import datetime
from urllib.parse import urlencode
import http.client
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger(__name__)


class SubdomainEnumerator:
    """
    Subdomain enumeration module using multiple external sources.
    
    Attributes:
        domain (str): Target domain for subdomain enumeration
        timeout (int): Request timeout in seconds
    """
    
    # Common subdomain wordlist for basic bruteforce
    COMMON_SUBDOMAINS = [
        'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'ns2',
        'webdisk', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'blog', 'dev',
        'www2', 'admin', 'forum', 'news', 'vpn', 'ns3', 'mail2', 'api', 'cdn',
        'test', 'portal', 'shop', 'support', 'secure', 'assets', 'static', 'app',
        'beta', 'stage', 'staging', 'demo', 'search', 'store', 'web', 'm', 'mobile',
        'login', 'auth', 'sso', 'id', 'gateway', 'proxy', 'git', 'gitlab', 'github',
        'jenkins', 'ci', 'build', 'repo', 'docker', 'k8s', 'kubernetes', 'aws',
        'cloud', 'backup', 'db', 'database', 'mysql', 'postgres', 'redis', 'mongo',
        'elastic', 'kibana', 'grafana', 'prometheus', 'monitoring', 'logs', 'status',
        'help', 'docs', 'documentation', 'wiki', 'confluence', 'jira', 'slack',
        'email', 'exchange', 'owa', 'remote', 'rdp', 'ssh', 'sftp', 'files', 'media',
        'images', 'img', 'video', 'streaming', 'download', 'downloads', 'upload',
        'intranet', 'internal', 'corp', 'office', 'hr', 'crm', 'erp', 'finance',
    ]
    
    def __init__(self, domain: str, timeout: int = 10):
        """
        Initialize subdomain enumerator.
        
        Args:
            domain: Target domain for subdomain enumeration
            timeout: Request timeout in seconds
        """
        self.domain = domain.lower().strip()
        self.timeout = timeout
        self.timestamp = datetime.now()
        self.subdomains: Set[str] = set()
        logger.debug(f"SubdomainEnumerator initialized for domain: {self.domain}")
    
    def _make_https_request(self, host: str, path: str, headers: Optional[Dict] = None) -> Optional[str]:
        """
        Make an HTTPS GET request.
        
        Args:
            host: Target host
            path: Request path
            headers: Optional headers
            
        Returns:
            Response body or None on error
        """
        try:
            context = ssl.create_default_context()
            conn = http.client.HTTPSConnection(host, timeout=self.timeout, context=context)
            
            default_headers = {
                'User-Agent': 'ReconMaster/1.0 (Reconnaissance Tool)',
                'Accept': 'application/json, text/plain, */*',
            }
            if headers:
                default_headers.update(headers)
            
            conn.request('GET', path, headers=default_headers)
            response = conn.getresponse()
            
            if response.status == 200:
                return response.read().decode('utf-8', errors='ignore')
            else:
                logger.debug(f"HTTP {response.status} from {host}{path}")
                return None
        
        except Exception as e:
            logger.debug(f"Request error to {host}: {e}")
            return None
        finally:
            try:
                conn.close()
            except:
                pass
    
    def _make_http_request(self, host: str, path: str, headers: Optional[Dict] = None) -> Optional[str]:
        """
        Make an HTTP GET request.
        
        Args:
            host: Target host
            path: Request path
            headers: Optional headers
            
        Returns:
            Response body or None on error
        """
        try:
            conn = http.client.HTTPConnection(host, timeout=self.timeout)
            
            default_headers = {
                'User-Agent': 'ReconMaster/1.0 (Reconnaissance Tool)',
                'Accept': 'application/json, text/plain, */*',
            }
            if headers:
                default_headers.update(headers)
            
            conn.request('GET', path, headers=default_headers)
            response = conn.getresponse()
            
            if response.status == 200:
                return response.read().decode('utf-8', errors='ignore')
            else:
                logger.debug(f"HTTP {response.status} from {host}{path}")
                return None
        
        except Exception as e:
            logger.debug(f"Request error to {host}: {e}")
            return None
        finally:
            try:
                conn.close()
            except:
                pass
    
    def _extract_subdomains(self, text: str) -> Set[str]:
        """
        Extract subdomains from text using regex.
        
        Args:
            text: Text containing potential subdomains
            
        Returns:
            Set of found subdomains
        """
        # Pattern to match subdomains of target domain
        pattern = rf'(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{{0,61}}[a-zA-Z0-9])?\.)*{re.escape(self.domain)}'
        matches = re.findall(pattern, text, re.IGNORECASE)
        
        subdomains = set()
        for match in matches:
            subdomain = match.lower().strip('.')
            if subdomain and subdomain.endswith(self.domain):
                # Remove wildcard entries
                if not subdomain.startswith('*'):
                    subdomains.add(subdomain)
        
        return subdomains
    
    def enumerate_crtsh(self) -> Set[str]:
        """
        Enumerate subdomains using crt.sh (Certificate Transparency logs).
        
        Returns:
            Set of discovered subdomains
        """
        logger.info("Querying crt.sh for subdomains...")
        subdomains = set()
        
        try:
            path = f'/?q=%.{self.domain}&output=json'
            response = self._make_https_request('crt.sh', path)
            
            if response:
                data = json.loads(response)
                for entry in data:
                    name = entry.get('name_value', '')
                    # Handle multiple names separated by newlines
                    for subdomain in name.split('\n'):
                        subdomain = subdomain.strip().lower()
                        if subdomain.endswith(self.domain) and not subdomain.startswith('*'):
                            subdomains.add(subdomain)
                
                logger.info(f"crt.sh: Found {len(subdomains)} subdomains")
        
        except json.JSONDecodeError:
            logger.warning("Failed to parse crt.sh response")
        except Exception as e:
            logger.warning(f"crt.sh enumeration error: {e}")
        
        return subdomains
    
    def enumerate_alienvault(self) -> Set[str]:
        """
        Enumerate subdomains using AlienVault OTX.
        
        Returns:
            Set of discovered subdomains
        """
        logger.info("Querying AlienVault OTX for subdomains...")
        subdomains = set()
        
        try:
            path = f'/api/v1/indicators/domain/{self.domain}/passive_dns'
            response = self._make_https_request('otx.alienvault.com', path)
            
            if response:
                data = json.loads(response)
                for entry in data.get('passive_dns', []):
                    hostname = entry.get('hostname', '').lower()
                    if hostname.endswith(self.domain):
                        subdomains.add(hostname)
                
                logger.info(f"AlienVault: Found {len(subdomains)} subdomains")
        
        except json.JSONDecodeError:
            logger.warning("Failed to parse AlienVault response")
        except Exception as e:
            logger.warning(f"AlienVault enumeration error: {e}")
        
        return subdomains
    
    def enumerate_hackertarget(self) -> Set[str]:
        """
        Enumerate subdomains using HackerTarget API.
        
        Returns:
            Set of discovered subdomains
        """
        logger.info("Querying HackerTarget for subdomains...")
        subdomains = set()
        
        try:
            path = f'/api/hostsearch/?q={self.domain}'
            response = self._make_https_request('api.hackertarget.com', path)
            
            if response and 'error' not in response.lower():
                for line in response.strip().split('\n'):
                    if ',' in line:
                        hostname = line.split(',')[0].strip().lower()
                        if hostname.endswith(self.domain):
                            subdomains.add(hostname)
                
                logger.info(f"HackerTarget: Found {len(subdomains)} subdomains")
        
        except Exception as e:
            logger.warning(f"HackerTarget enumeration error: {e}")
        
        return subdomains
    
    def enumerate_threatcrowd(self) -> Set[str]:
        """
        Enumerate subdomains using ThreatCrowd API.
        
        Returns:
            Set of discovered subdomains
        """
        logger.info("Querying ThreatCrowd for subdomains...")
        subdomains = set()
        
        try:
            path = f'/searchApi/v2/domain/report/?domain={self.domain}'
            response = self._make_https_request('www.threatcrowd.org', path)
            
            if response:
                data = json.loads(response)
                for subdomain in data.get('subdomains', []):
                    subdomain = subdomain.lower()
                    if subdomain.endswith(self.domain):
                        subdomains.add(subdomain)
                
                logger.info(f"ThreatCrowd: Found {len(subdomains)} subdomains")
        
        except json.JSONDecodeError:
            logger.warning("Failed to parse ThreatCrowd response")
        except Exception as e:
            logger.warning(f"ThreatCrowd enumeration error: {e}")
        
        return subdomains
    
    def enumerate_bruteforce(self, wordlist: Optional[List[str]] = None, threads: int = 10) -> Set[str]:
        """
        Enumerate subdomains using DNS bruteforce.
        
        Args:
            wordlist: Custom wordlist (default: built-in common subdomains)
            threads: Number of concurrent threads
            
        Returns:
            Set of discovered subdomains
        """
        logger.info("Performing subdomain bruteforce...")
        subdomains = set()
        wordlist = wordlist or self.COMMON_SUBDOMAINS
        
        def check_subdomain(subdomain: str) -> Optional[str]:
            fqdn = f"{subdomain}.{self.domain}"
            try:
                socket.gethostbyname(fqdn)
                return fqdn
            except socket.gaierror:
                return None
        
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(check_subdomain, sub): sub for sub in wordlist}
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    subdomains.add(result)
        
        logger.info(f"Bruteforce: Found {len(subdomains)} subdomains")
        return subdomains
    
    def resolve_subdomains(self, subdomains: Set[str]) -> Dict[str, List[str]]:
        """
        Resolve IP addresses for discovered subdomains.
        
        Args:
            subdomains: Set of subdomains to resolve
            
        Returns:
            Dictionary mapping subdomains to IP addresses
        """
        resolved = {}
        
        def resolve(subdomain: str) -> tuple:
            try:
                ips = socket.gethostbyname_ex(subdomain)[2]
                return (subdomain, ips)
            except socket.gaierror:
                return (subdomain, [])
        
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(resolve, sub) for sub in subdomains]
            
            for future in as_completed(futures):
                subdomain, ips = future.result()
                if ips:
                    resolved[subdomain] = ips
        
        return resolved
    
    def enumerate(self, sources: Optional[List[str]] = None, bruteforce: bool = True) -> Dict[str, Any]:
        """
        Perform subdomain enumeration using specified sources.
        
        Args:
            sources: List of sources to use (crtsh, alienvault, hackertarget, threatcrowd)
            bruteforce: Whether to perform DNS bruteforce
            
        Returns:
            Dictionary containing enumeration results
        """
        if sources is None:
            sources = ['crtsh', 'alienvault', 'hackertarget']
        
        logger.info(f"Starting subdomain enumeration for: {self.domain}")
        
        result = {
            'domain': self.domain,
            'timestamp': self.timestamp.isoformat(),
            'success': False,
            'sources_used': sources,
            'subdomains': [],
            'resolved': {},
            'total_found': 0,
            'error': None
        }
        
        all_subdomains = set()
        
        try:
            # Source enumeration methods
            source_methods = {
                'crtsh': self.enumerate_crtsh,
                'alienvault': self.enumerate_alienvault,
                'hackertarget': self.enumerate_hackertarget,
                'threatcrowd': self.enumerate_threatcrowd,
            }
            
            # Enumerate from each source
            for source in sources:
                if source.lower() in source_methods:
                    try:
                        found = source_methods[source.lower()]()
                        all_subdomains.update(found)
                    except Exception as e:
                        logger.warning(f"Error with source {source}: {e}")
            
            # Bruteforce enumeration
            if bruteforce:
                try:
                    found = self.enumerate_bruteforce()
                    all_subdomains.update(found)
                except Exception as e:
                    logger.warning(f"Bruteforce error: {e}")
            
            # Sort and store results
            result['subdomains'] = sorted(list(all_subdomains))
            result['total_found'] = len(all_subdomains)
            
            # Resolve IP addresses
            if all_subdomains:
                logger.info("Resolving subdomain IP addresses...")
                result['resolved'] = self.resolve_subdomains(all_subdomains)
            
            result['success'] = True
            logger.info(f"Subdomain enumeration completed. Found {result['total_found']} subdomains")
        
        except Exception as e:
            result['error'] = str(e)
            logger.error(f"Subdomain enumeration error: {e}")
        
        return result
    
    def get_summary(self) -> str:
        """
        Get a human-readable summary of subdomain enumeration results.
        
        Returns:
            Formatted string summary
        """
        result = self.enumerate()
        
        if not result['success']:
            return f"Subdomain enumeration failed for {self.domain}: {result.get('error', 'Unknown error')}"
        
        summary = [
            f"\n{'='*60}",
            f"Subdomain Enumeration for: {self.domain}",
            f"{'='*60}",
            f"Timestamp: {result['timestamp']}",
            f"Sources Used: {', '.join(result['sources_used'])}",
            f"Total Subdomains Found: {result['total_found']}",
            "",
            "Discovered Subdomains:"
        ]
        
        for subdomain in result['subdomains'][:50]:  # Limit display to 50
            ips = result['resolved'].get(subdomain, [])
            ip_str = f" -> {', '.join(ips)}" if ips else ""
            summary.append(f"  - {subdomain}{ip_str}")
        
        if result['total_found'] > 50:
            summary.append(f"  ... and {result['total_found'] - 50} more")
        
        summary.append(f"\n{'='*60}\n")
        
        return '\n'.join(summary)


# CLI functionality when run directly
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Subdomain Enumeration Module")
    parser.add_argument("domain", help="Target domain for subdomain enumeration")
    parser.add_argument("-s", "--sources", nargs="+", 
                       choices=['crtsh', 'alienvault', 'hackertarget', 'threatcrowd'],
                       help="Sources to use for enumeration")
    parser.add_argument("--no-bruteforce", action="store_true", help="Disable bruteforce enumeration")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    args = parser.parse_args()
    
    # Configure logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=log_level, format='%(asctime)s - %(levelname)s - %(message)s')
    
    # Perform enumeration
    subenum = SubdomainEnumerator(args.domain)
    print(subenum.enumerate(sources=args.sources, bruteforce=not args.no_bruteforce))
