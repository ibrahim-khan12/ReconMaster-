"""
Port Scanner Module
===================
Performs port scanning using socket connections.
Supports TCP connect scans with customizable port ranges.

Usage:
    from modules.active import PortScanner
    
    scanner = PortScanner(target="example.com")
    result = scanner.scan()
"""

import socket
import logging
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

logger = logging.getLogger(__name__)


class PortScanner:
    """
    Port scanner module for discovering open ports on target systems.
    
    Attributes:
        target (str): Target hostname or IP address
        ports (list): List of ports to scan
        timeout (float): Connection timeout in seconds
        threads (int): Number of concurrent scanning threads
    """
    
    # Common ports for quick scan
    COMMON_PORTS = [
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
        993, 995, 1723, 3306, 3389, 5432, 5900, 8080, 8443, 8888
    ]
    
    # Extended port list for comprehensive scan
    EXTENDED_PORTS = [
        20, 21, 22, 23, 25, 26, 53, 80, 81, 82, 88, 110, 111, 113, 119, 135,
        139, 143, 161, 179, 199, 389, 443, 445, 465, 514, 515, 548, 554, 587,
        631, 636, 993, 995, 1025, 1026, 1027, 1028, 1029, 1110, 1433, 1720,
        1723, 1755, 1900, 2000, 2001, 2049, 2121, 2717, 3000, 3128, 3306,
        3389, 3986, 4899, 5000, 5009, 5051, 5060, 5101, 5190, 5357, 5432,
        5631, 5666, 5800, 5900, 5901, 6000, 6001, 6646, 7002, 7070, 8000,
        8008, 8009, 8080, 8081, 8443, 8888, 9000, 9001, 9090, 9100, 9999,
        10000, 32768, 49152, 49153, 49154, 49155, 49156, 49157
    ]
    
    # Service name mappings
    SERVICE_NAMES = {
        20: 'ftp-data', 21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp',
        53: 'dns', 80: 'http', 110: 'pop3', 111: 'rpcbind', 135: 'msrpc',
        139: 'netbios-ssn', 143: 'imap', 443: 'https', 445: 'microsoft-ds',
        465: 'smtps', 587: 'submission', 993: 'imaps', 995: 'pop3s',
        1433: 'mssql', 1521: 'oracle', 1723: 'pptp', 3306: 'mysql',
        3389: 'rdp', 5432: 'postgresql', 5900: 'vnc', 6379: 'redis',
        8080: 'http-proxy', 8443: 'https-alt', 27017: 'mongodb'
    }
    
    def __init__(self, target: str, ports: Optional[List[int]] = None,
                 timeout: float = 1.0, threads: int = 100):
        """
        Initialize port scanner.
        
        Args:
            target: Target hostname or IP address
            ports: List of ports to scan (default: common ports)
            timeout: Connection timeout in seconds
            threads: Number of concurrent scanning threads
        """
        self.target = target.lower().strip()
        self.ports = ports or self.COMMON_PORTS
        self.timeout = timeout
        self.threads = threads
        self.timestamp = datetime.now()
        self.target_ip = None
        self._lock = threading.Lock()
        logger.debug(f"PortScanner initialized for target: {self.target}")
    
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
    
    def _scan_port(self, port: int) -> Tuple[int, bool, Optional[str]]:
        """
        Scan a single port using TCP connect.
        
        Args:
            port: Port number to scan
            
        Returns:
            Tuple of (port, is_open, service_name)
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            result = sock.connect_ex((self.target_ip, port))
            sock.close()
            
            if result == 0:
                service = self.SERVICE_NAMES.get(port, 'unknown')
                logger.debug(f"Port {port} is OPEN ({service})")
                return (port, True, service)
            else:
                return (port, False, None)
        
        except socket.timeout:
            return (port, False, None)
        except socket.error as e:
            logger.debug(f"Socket error scanning port {port}: {e}")
            return (port, False, None)
        except Exception as e:
            logger.debug(f"Error scanning port {port}: {e}")
            return (port, False, None)
    
    def scan(self, scan_type: str = 'common') -> Dict[str, Any]:
        """
        Perform port scan on target.
        
        Args:
            scan_type: Type of scan ('common', 'extended', 'full', 'custom')
            
        Returns:
            Dictionary containing scan results
        """
        logger.info(f"Starting port scan on: {self.target}")
        
        result = {
            'target': self.target,
            'target_ip': None,
            'timestamp': self.timestamp.isoformat(),
            'scan_type': scan_type,
            'success': False,
            'open_ports': [],
            'closed_ports_count': 0,
            'total_scanned': 0,
            'error': None
        }
        
        # Resolve target
        self.target_ip = self._resolve_target()
        if not self.target_ip:
            result['error'] = f"Could not resolve hostname: {self.target}"
            return result
        
        result['target_ip'] = self.target_ip
        
        # Determine ports to scan
        if scan_type == 'extended':
            ports_to_scan = self.EXTENDED_PORTS
        elif scan_type == 'full':
            ports_to_scan = list(range(1, 65536))
        elif scan_type == 'top100':
            ports_to_scan = self.COMMON_PORTS + [
                8000, 8001, 8002, 8081, 8082, 8181, 8282, 8383, 8484,
                9000, 9001, 9090, 9091, 10000, 10001
            ]
        else:  # common or custom
            ports_to_scan = self.ports
        
        result['total_scanned'] = len(ports_to_scan)
        
        try:
            logger.info(f"Scanning {len(ports_to_scan)} ports on {self.target_ip}")
            
            open_ports = []
            closed_count = 0
            
            # Scan ports concurrently
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = {executor.submit(self._scan_port, port): port for port in ports_to_scan}
                
                for future in as_completed(futures):
                    port, is_open, service = future.result()
                    
                    if is_open:
                        open_ports.append({
                            'port': port,
                            'state': 'open',
                            'service': service
                        })
                    else:
                        closed_count += 1
            
            # Sort open ports by port number
            open_ports.sort(key=lambda x: x['port'])
            
            result['open_ports'] = open_ports
            result['closed_ports_count'] = closed_count
            result['success'] = True
            
            logger.info(f"Port scan completed. Found {len(open_ports)} open ports")
        
        except Exception as e:
            result['error'] = str(e)
            logger.error(f"Port scan error: {e}")
        
        return result
    
    def scan_range(self, start_port: int, end_port: int) -> Dict[str, Any]:
        """
        Scan a specific range of ports.
        
        Args:
            start_port: Starting port number
            end_port: Ending port number
            
        Returns:
            Dictionary containing scan results
        """
        self.ports = list(range(start_port, end_port + 1))
        return self.scan(scan_type='custom')
    
    def get_summary(self) -> str:
        """
        Get a human-readable summary of port scan results.
        
        Returns:
            Formatted string summary
        """
        result = self.scan()
        
        if not result['success']:
            return f"Port scan failed for {self.target}: {result.get('error', 'Unknown error')}"
        
        summary = [
            f"\n{'='*60}",
            f"Port Scan Results for: {self.target}",
            f"{'='*60}",
            f"Target IP: {result['target_ip']}",
            f"Timestamp: {result['timestamp']}",
            f"Scan Type: {result['scan_type']}",
            f"Total Ports Scanned: {result['total_scanned']}",
            f"Open Ports: {len(result['open_ports'])}",
            f"Closed/Filtered Ports: {result['closed_ports_count']}",
            "",
            "Open Ports:"
        ]
        
        if result['open_ports']:
            for port_info in result['open_ports']:
                summary.append(f"  {port_info['port']}/tcp  open  {port_info['service']}")
        else:
            summary.append("  No open ports found")
        
        summary.append(f"\n{'='*60}\n")
        
        return '\n'.join(summary)


# CLI functionality when run directly
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Port Scanner Module")
    parser.add_argument("target", help="Target hostname or IP address")
    parser.add_argument("-p", "--ports", nargs="+", type=int, help="Specific ports to scan")
    parser.add_argument("-t", "--type", choices=['common', 'extended', 'full', 'top100'],
                       default='common', help="Scan type")
    parser.add_argument("--timeout", type=float, default=1.0, help="Connection timeout")
    parser.add_argument("--threads", type=int, default=100, help="Number of threads")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    args = parser.parse_args()
    
    # Configure logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=log_level, format='%(asctime)s - %(levelname)s - %(message)s')
    
    # Perform scan
    scanner = PortScanner(args.target, ports=args.ports, timeout=args.timeout, threads=args.threads)
    print(scanner.get_summary())
