"""
WHOIS Lookup Module
===================
Performs WHOIS lookups to gather domain registration information.

Usage:
    from modules.passive import WhoisLookup
    
    whois = WhoisLookup(domain="example.com")
    result = whois.lookup()
"""

import socket
import logging
from typing import Dict, Any, Optional
from datetime import datetime

logger = logging.getLogger(__name__)


class WhoisLookup:
    """
    WHOIS lookup module for gathering domain registration information.
    
    Attributes:
        domain (str): Target domain for WHOIS lookup
        whois_servers (dict): Dictionary of TLD to WHOIS server mappings
    """
    
    # Common WHOIS servers by TLD
    WHOIS_SERVERS = {
        'com': 'whois.verisign-grs.com',
        'net': 'whois.verisign-grs.com',
        'org': 'whois.pir.org',
        'info': 'whois.afilias.net',
        'io': 'whois.nic.io',
        'co': 'whois.nic.co',
        'edu': 'whois.educause.edu',
        'gov': 'whois.dotgov.gov',
        'mil': 'whois.nic.mil',
        'biz': 'whois.biz',
        'us': 'whois.nic.us',
        'uk': 'whois.nic.uk',
        'ca': 'whois.cira.ca',
        'de': 'whois.denic.de',
        'fr': 'whois.nic.fr',
        'au': 'whois.auda.org.au',
        'in': 'whois.registry.in',
        'jp': 'whois.jprs.jp',
        'ru': 'whois.tcinet.ru',
        'cn': 'whois.cnnic.cn',
        'br': 'whois.registro.br',
    }
    
    def __init__(self, domain: str):
        """
        Initialize WHOIS lookup module.
        
        Args:
            domain: Target domain for WHOIS lookup
        """
        self.domain = domain.lower().strip()
        self.timestamp = datetime.now()
        logger.debug(f"WhoisLookup initialized for domain: {self.domain}")
    
    def _get_whois_server(self) -> str:
        """
        Determine the appropriate WHOIS server for the domain TLD.
        
        Returns:
            WHOIS server hostname
        """
        tld = self.domain.split('.')[-1].lower()
        server = self.WHOIS_SERVERS.get(tld, 'whois.iana.org')
        logger.debug(f"Using WHOIS server: {server} for TLD: {tld}")
        return server
    
    def _query_whois(self, server: str, query: str, port: int = 43) -> str:
        """
        Send WHOIS query to server.
        
        Args:
            server: WHOIS server hostname
            query: Query string (domain name)
            port: WHOIS port (default 43)
            
        Returns:
            Raw WHOIS response
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((server, port))
            sock.send((query + "\r\n").encode())
            
            response = b""
            while True:
                data = sock.recv(4096)
                if not data:
                    break
                response += data
            
            sock.close()
            return response.decode('utf-8', errors='ignore')
        except socket.timeout:
            logger.error(f"WHOIS query timed out for server: {server}")
            return f"Error: Connection timed out to {server}"
        except socket.error as e:
            logger.error(f"Socket error during WHOIS query: {e}")
            return f"Error: Socket error - {str(e)}"
        except Exception as e:
            logger.error(f"Unexpected error during WHOIS query: {e}")
            return f"Error: {str(e)}"
    
    def _parse_whois_response(self, raw_response: str) -> Dict[str, Any]:
        """
        Parse raw WHOIS response into structured data.
        
        Args:
            raw_response: Raw WHOIS response string
            
        Returns:
            Dictionary with parsed WHOIS data
        """
        parsed = {
            'raw': raw_response,
            'registrar': None,
            'creation_date': None,
            'expiration_date': None,
            'updated_date': None,
            'name_servers': [],
            'status': [],
            'registrant': {},
            'admin_contact': {},
            'tech_contact': {},
        }
        
        # Field mappings for parsing
        field_mappings = {
            'registrar': ['Registrar:', 'Sponsoring Registrar:', 'registrar:'],
            'creation_date': ['Creation Date:', 'Created Date:', 'created:', 'Registration Date:'],
            'expiration_date': ['Expiry Date:', 'Registry Expiry Date:', 'Registrar Registration Expiration Date:'],
            'updated_date': ['Updated Date:', 'Last Updated:', 'updated:'],
        }
        
        lines = raw_response.split('\n')
        
        for line in lines:
            line = line.strip()
            if not line or line.startswith('%') or line.startswith('#'):
                continue
            
            # Parse common fields
            for field, patterns in field_mappings.items():
                for pattern in patterns:
                    if line.lower().startswith(pattern.lower()):
                        value = line.split(':', 1)[-1].strip()
                        if value and not parsed[field]:
                            parsed[field] = value
                            break
            
            # Parse name servers
            if 'name server' in line.lower() or line.lower().startswith('nserver:'):
                ns = line.split(':')[-1].strip()
                if ns and ns not in parsed['name_servers']:
                    parsed['name_servers'].append(ns)
            
            # Parse status
            if 'status' in line.lower() and ':' in line:
                status = line.split(':')[-1].strip().split()[0]  # Get first word
                if status and status not in parsed['status']:
                    parsed['status'].append(status)
        
        return parsed
    
    def lookup(self) -> Dict[str, Any]:
        """
        Perform WHOIS lookup for the domain.
        
        Returns:
            Dictionary containing WHOIS information
        """
        logger.info(f"Performing WHOIS lookup for: {self.domain}")
        
        result = {
            'domain': self.domain,
            'timestamp': self.timestamp.isoformat(),
            'success': False,
            'data': {},
            'error': None
        }
        
        try:
            # Get appropriate WHOIS server
            server = self._get_whois_server()
            
            # Query WHOIS
            raw_response = self._query_whois(server, self.domain)
            
            if raw_response.startswith('Error:'):
                result['error'] = raw_response
                logger.warning(f"WHOIS lookup failed: {raw_response}")
            else:
                # Check for referral to another WHOIS server
                if 'Registrar WHOIS Server:' in raw_response:
                    for line in raw_response.split('\n'):
                        if 'Registrar WHOIS Server:' in line:
                            referral_server = line.split(':')[-1].strip()
                            if referral_server and referral_server != server:
                                logger.debug(f"Following WHOIS referral to: {referral_server}")
                                raw_response = self._query_whois(referral_server, self.domain)
                                break
                
                # Parse the response
                parsed_data = self._parse_whois_response(raw_response)
                result['data'] = parsed_data
                result['success'] = True
                logger.info(f"WHOIS lookup successful for: {self.domain}")
        
        except Exception as e:
            result['error'] = str(e)
            logger.error(f"WHOIS lookup error: {e}")
        
        return result
    
    def get_summary(self) -> str:
        """
        Get a human-readable summary of WHOIS information.
        
        Returns:
            Formatted string summary
        """
        result = self.lookup()
        
        if not result['success']:
            return f"WHOIS lookup failed for {self.domain}: {result.get('error', 'Unknown error')}"
        
        data = result['data']
        summary = [
            f"\n{'='*60}",
            f"WHOIS Information for: {self.domain}",
            f"{'='*60}",
            f"Timestamp: {result['timestamp']}",
            f"Registrar: {data.get('registrar', 'N/A')}",
            f"Creation Date: {data.get('creation_date', 'N/A')}",
            f"Expiration Date: {data.get('expiration_date', 'N/A')}",
            f"Updated Date: {data.get('updated_date', 'N/A')}",
            f"Name Servers: {', '.join(data.get('name_servers', [])) or 'N/A'}",
            f"Status: {', '.join(data.get('status', [])) or 'N/A'}",
            f"{'='*60}\n"
        ]
        
        return '\n'.join(summary)


# CLI functionality when run directly
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="WHOIS Lookup Module")
    parser.add_argument("domain", help="Target domain for WHOIS lookup")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    args = parser.parse_args()
    
    # Configure logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=log_level, format='%(asctime)s - %(levelname)s - %(message)s')
    
    # Perform lookup
    whois = WhoisLookup(args.domain)
    print(whois.get_summary())
