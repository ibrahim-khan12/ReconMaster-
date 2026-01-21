"""
Banner Grabbing Module
======================
Performs banner grabbing to identify services running on open ports.

Usage:
    from modules.active import BannerGrabber
    
    grabber = BannerGrabber(target="example.com")
    result = grabber.grab()
"""

import socket
import ssl
import logging
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger(__name__)


class BannerGrabber:
    """
    Banner grabbing module for service identification.
    
    Attributes:
        target (str): Target hostname or IP address
        ports (list): List of ports to probe
        timeout (float): Connection timeout in seconds
    """
    
    # Default ports for banner grabbing
    DEFAULT_PORTS = [21, 22, 23, 25, 80, 110, 143, 443, 445, 3306, 3389, 5432, 8080]
    
    # Protocol-specific probes
    PROBES = {
        'http': b'GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: ReconMaster/1.0\r\nAccept: */*\r\nConnection: close\r\n\r\n',
        'https': b'GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: ReconMaster/1.0\r\nAccept: */*\r\nConnection: close\r\n\r\n',
        'ftp': b'',  # FTP sends banner on connect
        'ssh': b'',  # SSH sends banner on connect
        'smtp': b'EHLO reconmaster.local\r\n',
        'pop3': b'',
        'imap': b'',
        'telnet': b'',
        'mysql': b'',
        'generic': b'\r\n',
    }
    
    # Port to protocol mapping
    PORT_PROTOCOLS = {
        21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 80: 'http',
        110: 'pop3', 143: 'imap', 443: 'https', 465: 'smtp',
        587: 'smtp', 993: 'imap', 995: 'pop3', 3306: 'mysql',
        5432: 'generic', 8080: 'http', 8443: 'https'
    }
    
    def __init__(self, target: str, ports: Optional[List[int]] = None, timeout: float = 5.0):
        """
        Initialize banner grabber.
        
        Args:
            target: Target hostname or IP address
            ports: List of ports to probe (default: common service ports)
            timeout: Connection timeout in seconds
        """
        self.target = target.lower().strip()
        self.ports = ports or self.DEFAULT_PORTS
        self.timeout = timeout
        self.timestamp = datetime.now()
        self.target_ip = None
        logger.debug(f"BannerGrabber initialized for target: {self.target}")
    
    def _resolve_target(self) -> Optional[str]:
        """
        Resolve target hostname to IP address.
        
        Returns:
            IP address or None on failure
        """
        try:
            ip = socket.gethostbyname(self.target)
            logger.debug(f"Resolved {self.target} to {ip}")
            return ip
        except socket.gaierror as e:
            logger.error(f"Failed to resolve {self.target}: {e}")
            return None
    
    def _grab_banner_tcp(self, port: int, probe: bytes = b'') -> Optional[str]:
        """
        Grab banner from TCP service.
        
        Args:
            port: Port number
            probe: Optional probe data to send
            
        Returns:
            Banner string or None
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.target_ip, port))
            
            # Receive initial banner (for services like SSH, FTP)
            sock.setblocking(False)
            try:
                initial = sock.recv(1024)
            except:
                initial = b''
            sock.setblocking(True)
            
            # Send probe if specified
            if probe:
                probe_data = probe.replace(b'{host}', self.target.encode())
                sock.send(probe_data)
            
            # Receive response
            sock.settimeout(self.timeout)
            response = b''
            try:
                while True:
                    data = sock.recv(4096)
                    if not data:
                        break
                    response += data
                    if len(response) > 8192:  # Limit response size
                        break
            except socket.timeout:
                pass
            
            sock.close()
            
            banner = (initial + response).decode('utf-8', errors='ignore').strip()
            return banner[:2048] if banner else None  # Limit banner length
        
        except socket.timeout:
            logger.debug(f"Timeout grabbing banner from port {port}")
            return None
        except socket.error as e:
            logger.debug(f"Socket error on port {port}: {e}")
            return None
        except Exception as e:
            logger.debug(f"Error grabbing banner from port {port}: {e}")
            return None
    
    def _grab_banner_ssl(self, port: int, probe: bytes = b'') -> Tuple[Optional[str], Optional[Dict]]:
        """
        Grab banner from SSL/TLS service.
        
        Args:
            port: Port number
            probe: Optional probe data to send
            
        Returns:
            Tuple of (banner string, SSL certificate info)
        """
        banner = None
        cert_info = None
        
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            ssl_sock = context.wrap_socket(sock, server_hostname=self.target)
            ssl_sock.connect((self.target_ip, port))
            
            # Get certificate info
            cert = ssl_sock.getpeercert(binary_form=False)
            if cert:
                cert_info = {
                    'subject': dict(x[0] for x in cert.get('subject', [])),
                    'issuer': dict(x[0] for x in cert.get('issuer', [])),
                    'version': cert.get('version'),
                    'notBefore': cert.get('notBefore'),
                    'notAfter': cert.get('notAfter'),
                }
            
            # Get SSL version
            ssl_version = ssl_sock.version()
            
            # Send probe if specified
            if probe:
                probe_data = probe.replace(b'{host}', self.target.encode())
                ssl_sock.send(probe_data)
            
            # Receive response
            response = b''
            ssl_sock.settimeout(self.timeout)
            try:
                while True:
                    data = ssl_sock.recv(4096)
                    if not data:
                        break
                    response += data
                    if len(response) > 8192:
                        break
            except socket.timeout:
                pass
            
            ssl_sock.close()
            
            banner = response.decode('utf-8', errors='ignore').strip()
            if ssl_version:
                banner = f"[{ssl_version}] {banner}" if banner else f"[{ssl_version}]"
            
            return (banner[:2048] if banner else None, cert_info)
        
        except ssl.SSLError as e:
            logger.debug(f"SSL error on port {port}: {e}")
            return (None, None)
        except socket.timeout:
            logger.debug(f"Timeout on SSL port {port}")
            return (None, None)
        except Exception as e:
            logger.debug(f"Error on SSL port {port}: {e}")
            return (None, None)
    
    def _grab_single_port(self, port: int) -> Dict[str, Any]:
        """
        Grab banner from a single port.
        
        Args:
            port: Port number to probe
            
        Returns:
            Dictionary with banner information
        """
        result = {
            'port': port,
            'protocol': self.PORT_PROTOCOLS.get(port, 'generic'),
            'banner': None,
            'ssl_info': None,
            'state': 'closed'
        }
        
        protocol = result['protocol']
        probe = self.PROBES.get(protocol, self.PROBES['generic'])
        
        # Try SSL/TLS for HTTPS ports
        if protocol == 'https' or port in [443, 8443, 465, 993, 995]:
            banner, ssl_info = self._grab_banner_ssl(port, probe)
            if banner or ssl_info:
                result['banner'] = banner
                result['ssl_info'] = ssl_info
                result['state'] = 'open'
                return result
        
        # Try plain TCP
        banner = self._grab_banner_tcp(port, probe)
        if banner:
            result['banner'] = banner
            result['state'] = 'open'
        elif banner == '':
            result['state'] = 'open'
        
        return result
    
    def grab(self, ports: Optional[List[int]] = None) -> Dict[str, Any]:
        """
        Perform banner grabbing on specified ports.
        
        Args:
            ports: List of ports to probe (optional, uses default if not specified)
            
        Returns:
            Dictionary containing banner grabbing results
        """
        if ports:
            self.ports = ports
        
        logger.info(f"Starting banner grabbing on: {self.target}")
        
        result = {
            'target': self.target,
            'target_ip': None,
            'timestamp': self.timestamp.isoformat(),
            'success': False,
            'banners': [],
            'services_identified': [],
            'error': None
        }
        
        # Resolve target
        self.target_ip = self._resolve_target()
        if not self.target_ip:
            result['error'] = f"Could not resolve hostname: {self.target}"
            return result
        
        result['target_ip'] = self.target_ip
        
        try:
            logger.info(f"Probing {len(self.ports)} ports on {self.target_ip}")
            
            banners = []
            
            # Grab banners concurrently
            with ThreadPoolExecutor(max_workers=20) as executor:
                futures = {executor.submit(self._grab_single_port, port): port for port in self.ports}
                
                for future in as_completed(futures):
                    port_result = future.result()
                    if port_result['state'] == 'open':
                        banners.append(port_result)
                        
                        # Identify service from banner
                        if port_result['banner']:
                            service_id = self._identify_service(port_result['banner'])
                            if service_id:
                                result['services_identified'].append({
                                    'port': port_result['port'],
                                    'service': service_id
                                })
            
            # Sort by port number
            banners.sort(key=lambda x: x['port'])
            result['banners'] = banners
            result['success'] = True
            
            logger.info(f"Banner grabbing completed. Found {len(banners)} services")
        
        except Exception as e:
            result['error'] = str(e)
            logger.error(f"Banner grabbing error: {e}")
        
        return result
    
    def _identify_service(self, banner: str) -> Optional[str]:
        """
        Identify service from banner content.
        
        Args:
            banner: Banner string
            
        Returns:
            Service identification string
        """
        banner_lower = banner.lower()
        
        # Service signatures
        signatures = [
            ('OpenSSH', 'SSH'),
            ('SSH-', 'SSH'),
            ('Apache', 'Apache HTTP Server'),
            ('nginx', 'Nginx'),
            ('Microsoft-IIS', 'Microsoft IIS'),
            ('lighttpd', 'Lighttpd'),
            ('vsftpd', 'vsftpd FTP'),
            ('ProFTPD', 'ProFTPD'),
            ('FileZilla', 'FileZilla FTP'),
            ('220', 'FTP'),
            ('Postfix', 'Postfix SMTP'),
            ('Exim', 'Exim SMTP'),
            ('sendmail', 'Sendmail'),
            ('MySQL', 'MySQL'),
            ('MariaDB', 'MariaDB'),
            ('PostgreSQL', 'PostgreSQL'),
            ('Microsoft SQL', 'Microsoft SQL Server'),
            ('redis', 'Redis'),
            ('MongoDB', 'MongoDB'),
            ('Elasticsearch', 'Elasticsearch'),
            ('RabbitMQ', 'RabbitMQ'),
            ('Dovecot', 'Dovecot'),
            ('Courier', 'Courier'),
            ('TLSv1', 'TLS Service'),
        ]
        
        for pattern, service in signatures:
            if pattern.lower() in banner_lower:
                return service
        
        return None
    
    def get_summary(self) -> str:
        """
        Get a human-readable summary of banner grabbing results.
        
        Returns:
            Formatted string summary
        """
        result = self.grab()
        
        if not result['success']:
            return f"Banner grabbing failed for {self.target}: {result.get('error', 'Unknown error')}"
        
        summary = [
            f"\n{'='*60}",
            f"Banner Grabbing Results for: {self.target}",
            f"{'='*60}",
            f"Target IP: {result['target_ip']}",
            f"Timestamp: {result['timestamp']}",
            f"Services Found: {len(result['banners'])}",
            ""
        ]
        
        if result['banners']:
            for banner_info in result['banners']:
                summary.append(f"Port {banner_info['port']}/{banner_info['protocol']}:")
                if banner_info['banner']:
                    # Truncate long banners for display
                    banner_display = banner_info['banner'][:500]
                    if len(banner_info['banner']) > 500:
                        banner_display += '...'
                    summary.append(f"  Banner: {banner_display}")
                if banner_info['ssl_info']:
                    ssl = banner_info['ssl_info']
                    if ssl.get('subject'):
                        summary.append(f"  SSL Subject: {ssl['subject']}")
                    if ssl.get('issuer'):
                        summary.append(f"  SSL Issuer: {ssl['issuer']}")
                summary.append("")
        else:
            summary.append("No banners retrieved")
        
        if result['services_identified']:
            summary.append("Identified Services:")
            for svc in result['services_identified']:
                summary.append(f"  Port {svc['port']}: {svc['service']}")
        
        summary.append(f"\n{'='*60}\n")
        
        return '\n'.join(summary)


# CLI functionality when run directly
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Banner Grabbing Module")
    parser.add_argument("target", help="Target hostname or IP address")
    parser.add_argument("-p", "--ports", nargs="+", type=int, help="Specific ports to probe")
    parser.add_argument("--timeout", type=float, default=5.0, help="Connection timeout")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    args = parser.parse_args()
    
    # Configure logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=log_level, format='%(asctime)s - %(levelname)s - %(message)s')
    
    # Perform banner grabbing
    grabber = BannerGrabber(args.target, ports=args.ports, timeout=args.timeout)
    print(grabber.get_summary())
