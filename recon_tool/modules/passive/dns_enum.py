"""
DNS Enumeration Module
======================
Performs DNS enumeration to gather DNS records (A, MX, TXT, NS, AAAA, CNAME, SOA).

Usage:
    from modules.passive import DNSEnumerator
    
    dns = DNSEnumerator(domain="example.com")
    result = dns.enumerate()
"""

import socket
import struct
import logging
import random
from typing import Dict, Any, List, Optional
from datetime import datetime

logger = logging.getLogger(__name__)


class DNSEnumerator:
    """
    DNS enumeration module for gathering DNS records.
    
    Supports: A, AAAA, MX, TXT, NS, CNAME, SOA records
    
    Attributes:
        domain (str): Target domain for DNS enumeration
        dns_servers (list): List of DNS servers to query
    """
    
    # DNS record types
    RECORD_TYPES = {
        'A': 1,
        'NS': 2,
        'CNAME': 5,
        'SOA': 6,
        'MX': 15,
        'TXT': 16,
        'AAAA': 28,
    }
    
    # Public DNS servers
    DNS_SERVERS = [
        '8.8.8.8',        # Google
        '8.8.4.4',        # Google
        '1.1.1.1',        # Cloudflare
        '1.0.0.1',        # Cloudflare
        '9.9.9.9',        # Quad9
        '208.67.222.222', # OpenDNS
    ]
    
    def __init__(self, domain: str, dns_server: Optional[str] = None):
        """
        Initialize DNS enumerator.
        
        Args:
            domain: Target domain for DNS enumeration
            dns_server: Specific DNS server to use (optional)
        """
        self.domain = domain.lower().strip()
        self.dns_server = dns_server or self.DNS_SERVERS[0]
        self.timestamp = datetime.now()
        logger.debug(f"DNSEnumerator initialized for domain: {self.domain}")
    
    def _build_dns_query(self, domain: str, record_type: int) -> bytes:
        """
        Build a DNS query packet.
        
        Args:
            domain: Domain to query
            record_type: DNS record type code
            
        Returns:
            DNS query packet as bytes
        """
        # Transaction ID
        transaction_id = random.randint(0, 65535)
        
        # Flags: Standard query
        flags = 0x0100
        
        # Questions, Answers, Authority, Additional
        questions = 1
        answers = 0
        authority = 0
        additional = 0
        
        # Header
        header = struct.pack('>HHHHHH', 
                           transaction_id, flags, 
                           questions, answers, 
                           authority, additional)
        
        # Question section
        question = b''
        for label in domain.split('.'):
            question += bytes([len(label)]) + label.encode()
        question += b'\x00'  # End of domain name
        
        # Type and Class
        question += struct.pack('>HH', record_type, 1)  # 1 = IN (Internet)
        
        return header + question
    
    def _parse_dns_response(self, response: bytes, record_type: str) -> List[str]:
        """
        Parse DNS response packet.
        
        Args:
            response: DNS response packet
            record_type: Type of record being parsed
            
        Returns:
            List of parsed records
        """
        records = []
        
        try:
            # Skip header (12 bytes)
            offset = 12
            
            # Skip question section
            while response[offset] != 0:
                offset += response[offset] + 1
            offset += 5  # Skip null byte, type, and class
            
            # Parse answer section
            answer_count = struct.unpack('>H', response[4:6])[0]
            
            for _ in range(answer_count):
                # Skip name (handle compression)
                if response[offset] & 0xC0 == 0xC0:
                    offset += 2
                else:
                    while response[offset] != 0:
                        offset += response[offset] + 1
                    offset += 1
                
                # Parse type, class, TTL, data length
                rtype, rclass, ttl, rdlength = struct.unpack('>HHIH', response[offset:offset+10])
                offset += 10
                
                # Parse record data based on type
                rdata = response[offset:offset+rdlength]
                
                if rtype == self.RECORD_TYPES.get('A') and len(rdata) == 4:
                    ip = '.'.join(str(b) for b in rdata)
                    records.append(ip)
                
                elif rtype == self.RECORD_TYPES.get('AAAA') and len(rdata) == 16:
                    ip = ':'.join(f'{rdata[i]:02x}{rdata[i+1]:02x}' for i in range(0, 16, 2))
                    records.append(ip)
                
                elif rtype == self.RECORD_TYPES.get('MX'):
                    priority = struct.unpack('>H', rdata[:2])[0]
                    mx = self._parse_name(response, offset + 2)
                    records.append(f"{priority} {mx}")
                
                elif rtype == self.RECORD_TYPES.get('TXT'):
                    txt_len = rdata[0]
                    txt = rdata[1:1+txt_len].decode('utf-8', errors='ignore')
                    records.append(txt)
                
                elif rtype in [self.RECORD_TYPES.get('NS'), self.RECORD_TYPES.get('CNAME')]:
                    name = self._parse_name(response, offset)
                    records.append(name)
                
                elif rtype == self.RECORD_TYPES.get('SOA'):
                    mname = self._parse_name(response, offset)
                    records.append(f"Primary NS: {mname}")
                
                offset += rdlength
        
        except Exception as e:
            logger.debug(f"Error parsing DNS response: {e}")
        
        return records
    
    def _parse_name(self, response: bytes, offset: int) -> str:
        """
        Parse a domain name from DNS response (handling compression).
        
        Args:
            response: DNS response packet
            offset: Starting offset
            
        Returns:
            Parsed domain name
        """
        labels = []
        max_jumps = 20
        jumps = 0
        
        while True:
            if jumps > max_jumps:
                break
            
            length = response[offset]
            
            if length == 0:
                break
            
            # Handle compression pointer
            if length & 0xC0 == 0xC0:
                pointer = struct.unpack('>H', response[offset:offset+2])[0] & 0x3FFF
                offset = pointer
                jumps += 1
                continue
            
            offset += 1
            labels.append(response[offset:offset+length].decode('utf-8', errors='ignore'))
            offset += length
        
        return '.'.join(labels)
    
    def _query_dns(self, record_type: str) -> List[str]:
        """
        Query DNS server for specific record type.
        
        Args:
            record_type: DNS record type (A, MX, TXT, etc.)
            
        Returns:
            List of records
        """
        if record_type not in self.RECORD_TYPES:
            logger.warning(f"Unsupported record type: {record_type}")
            return []
        
        try:
            # Build query
            query = self._build_dns_query(self.domain, self.RECORD_TYPES[record_type])
            
            # Send query via UDP
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(5)
            sock.sendto(query, (self.dns_server, 53))
            
            response, _ = sock.recvfrom(4096)
            sock.close()
            
            # Parse response
            records = self._parse_dns_response(response, record_type)
            logger.debug(f"Found {len(records)} {record_type} records")
            return records
        
        except socket.timeout:
            logger.warning(f"DNS query timeout for {record_type} records")
            return []
        except Exception as e:
            logger.error(f"DNS query error for {record_type}: {e}")
            return []
    
    def _resolve_with_socket(self) -> Dict[str, List[str]]:
        """
        Fallback method using socket.getaddrinfo for basic resolution.
        
        Returns:
            Dictionary with A and AAAA records
        """
        records = {'A': [], 'AAAA': []}
        
        try:
            # IPv4
            results = socket.getaddrinfo(self.domain, None, socket.AF_INET)
            for result in results:
                ip = result[4][0]
                if ip not in records['A']:
                    records['A'].append(ip)
        except socket.gaierror:
            logger.debug(f"No IPv4 address found for {self.domain}")
        
        try:
            # IPv6
            results = socket.getaddrinfo(self.domain, None, socket.AF_INET6)
            for result in results:
                ip = result[4][0]
                if ip not in records['AAAA']:
                    records['AAAA'].append(ip)
        except socket.gaierror:
            logger.debug(f"No IPv6 address found for {self.domain}")
        
        return records
    
    def enumerate(self, record_types: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Perform DNS enumeration for specified record types.
        
        Args:
            record_types: List of record types to query (default: all)
            
        Returns:
            Dictionary containing DNS enumeration results
        """
        if record_types is None:
            record_types = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA']
        
        logger.info(f"Performing DNS enumeration for: {self.domain}")
        
        result = {
            'domain': self.domain,
            'timestamp': self.timestamp.isoformat(),
            'dns_server': self.dns_server,
            'success': False,
            'records': {},
            'ip_addresses': [],
            'error': None
        }
        
        try:
            for rtype in record_types:
                records = self._query_dns(rtype)
                if records:
                    result['records'][rtype] = records
                    
                    # Collect IP addresses
                    if rtype in ['A', 'AAAA']:
                        result['ip_addresses'].extend(records)
            
            # Fallback if no A records found
            if 'A' not in result['records'] or not result['records']['A']:
                fallback = self._resolve_with_socket()
                if fallback['A']:
                    result['records']['A'] = fallback['A']
                    result['ip_addresses'].extend(fallback['A'])
                if fallback['AAAA']:
                    result['records']['AAAA'] = fallback['AAAA']
                    result['ip_addresses'].extend(fallback['AAAA'])
            
            # Remove duplicates from IP addresses
            result['ip_addresses'] = list(set(result['ip_addresses']))
            
            result['success'] = len(result['records']) > 0
            logger.info(f"DNS enumeration completed for: {self.domain}")
        
        except Exception as e:
            result['error'] = str(e)
            logger.error(f"DNS enumeration error: {e}")
        
        return result
    
    def get_summary(self) -> str:
        """
        Get a human-readable summary of DNS enumeration results.
        
        Returns:
            Formatted string summary
        """
        result = self.enumerate()
        
        if not result['success']:
            return f"DNS enumeration failed for {self.domain}: {result.get('error', 'No records found')}"
        
        summary = [
            f"\n{'='*60}",
            f"DNS Enumeration for: {self.domain}",
            f"{'='*60}",
            f"Timestamp: {result['timestamp']}",
            f"DNS Server: {result['dns_server']}",
            f"IP Addresses: {', '.join(result['ip_addresses']) or 'N/A'}",
            ""
        ]
        
        for rtype, records in result['records'].items():
            summary.append(f"{rtype} Records:")
            for record in records:
                summary.append(f"  - {record}")
            summary.append("")
        
        summary.append(f"{'='*60}\n")
        
        return '\n'.join(summary)


# CLI functionality when run directly
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="DNS Enumeration Module")
    parser.add_argument("domain", help="Target domain for DNS enumeration")
    parser.add_argument("-t", "--types", nargs="+", help="Record types to query")
    parser.add_argument("-s", "--server", help="DNS server to use")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    args = parser.parse_args()
    
    # Configure logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=log_level, format='%(asctime)s - %(levelname)s - %(message)s')
    
    # Perform enumeration
    dns = DNSEnumerator(args.domain, dns_server=args.server)
    print(dns.get_summary())
