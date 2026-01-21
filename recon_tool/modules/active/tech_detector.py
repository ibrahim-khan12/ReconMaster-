"""
Technology Detection Module
===========================
Detects web technologies, frameworks, and server software from HTTP responses.

Uses HTTP header analysis, HTML content inspection, and common fingerprinting techniques.

Usage:
    from modules.active import TechDetector
    
    detector = TechDetector(target="example.com")
    result = detector.detect()
"""

import socket
import ssl
import re
import json
import logging
from typing import Dict, Any, List, Optional, Set
from datetime import datetime
import http.client
from html.parser import HTMLParser

logger = logging.getLogger(__name__)


class MetaTagParser(HTMLParser):
    """Parser to extract meta tags and other technology indicators from HTML."""
    
    def __init__(self):
        super().__init__()
        self.meta_tags = []
        self.scripts = []
        self.links = []
        self.generators = []
        self.powered_by = []
    
    def handle_starttag(self, tag, attrs):
        attrs_dict = dict(attrs)
        
        if tag == 'meta':
            self.meta_tags.append(attrs_dict)
            # Look for generator meta tag
            if attrs_dict.get('name', '').lower() == 'generator':
                self.generators.append(attrs_dict.get('content', ''))
        
        elif tag == 'script':
            src = attrs_dict.get('src', '')
            if src:
                self.scripts.append(src)
        
        elif tag == 'link':
            href = attrs_dict.get('href', '')
            rel = attrs_dict.get('rel', '')
            if href:
                self.links.append({'href': href, 'rel': rel})


class TechDetector:
    """
    Technology detection module for identifying web technologies.
    
    Detects:
    - Web servers (Apache, Nginx, IIS, etc.)
    - Programming languages (PHP, ASP.NET, Python, etc.)
    - CMS platforms (WordPress, Drupal, Joomla, etc.)
    - JavaScript frameworks (React, Vue, Angular, jQuery, etc.)
    - Security headers and configurations
    
    Attributes:
        target (str): Target URL or domain
        timeout (int): Request timeout in seconds
    """
    
    # Technology signatures based on HTTP headers
    HEADER_SIGNATURES = {
        'server': {
            'apache': 'Apache',
            'nginx': 'Nginx',
            'microsoft-iis': 'Microsoft IIS',
            'lighttpd': 'Lighttpd',
            'cloudflare': 'Cloudflare',
            'gunicorn': 'Gunicorn',
            'uvicorn': 'Uvicorn',
            'openresty': 'OpenResty',
            'litespeed': 'LiteSpeed',
            'caddy': 'Caddy',
        },
        'x-powered-by': {
            'php': 'PHP',
            'asp.net': 'ASP.NET',
            'express': 'Express.js',
            'next.js': 'Next.js',
            'nuxt': 'Nuxt.js',
            'django': 'Django',
            'flask': 'Flask',
            'laravel': 'Laravel',
            'rails': 'Ruby on Rails',
            'servlet': 'Java Servlet',
        },
        'x-aspnet-version': {
            '': 'ASP.NET',
        },
        'x-drupal-cache': {
            '': 'Drupal',
        },
    }
    
    # Content-based signatures
    CONTENT_SIGNATURES = {
        # CMS Detection
        'wp-content': 'WordPress',
        'wp-includes': 'WordPress',
        '/wp-json/': 'WordPress',
        'drupal': 'Drupal',
        'sites/all/': 'Drupal',
        'joomla': 'Joomla',
        '/media/jui/': 'Joomla',
        'typo3': 'TYPO3',
        'magento': 'Magento',
        'shopify': 'Shopify',
        'squarespace': 'Squarespace',
        'wix.com': 'Wix',
        'webflow': 'Webflow',
        'ghost': 'Ghost',
        
        # JavaScript Frameworks
        'react': 'React',
        '__NEXT_DATA__': 'Next.js',
        '__NUXT__': 'Nuxt.js',
        'ng-app': 'AngularJS',
        'ng-version': 'Angular',
        'vue': 'Vue.js',
        'svelte': 'Svelte',
        'ember': 'Ember.js',
        'backbone': 'Backbone.js',
        
        # JavaScript Libraries
        'jquery': 'jQuery',
        'bootstrap': 'Bootstrap',
        'tailwind': 'Tailwind CSS',
        'foundation': 'Foundation',
        'bulma': 'Bulma',
        
        # Analytics & Marketing
        'google-analytics': 'Google Analytics',
        'gtag': 'Google Tag Manager',
        'facebook.net/': 'Facebook Pixel',
        'hotjar': 'Hotjar',
        'mixpanel': 'Mixpanel',
        'segment': 'Segment',
        
        # Security
        'cloudflare': 'Cloudflare',
        'akamai': 'Akamai',
        'fastly': 'Fastly',
        'incapsula': 'Imperva',
        'sucuri': 'Sucuri',
        
        # Other Technologies
        'recaptcha': 'Google reCAPTCHA',
        'stripe': 'Stripe',
        'paypal': 'PayPal',
        'twilio': 'Twilio',
        'aws': 'Amazon Web Services',
        'azure': 'Microsoft Azure',
        'firebase': 'Firebase',
    }
    
    # Security headers to check
    SECURITY_HEADERS = [
        'Strict-Transport-Security',
        'Content-Security-Policy',
        'X-Content-Type-Options',
        'X-Frame-Options',
        'X-XSS-Protection',
        'Referrer-Policy',
        'Permissions-Policy',
        'Feature-Policy',
        'Access-Control-Allow-Origin',
    ]
    
    def __init__(self, target: str, timeout: int = 10):
        """
        Initialize technology detector.
        
        Args:
            target: Target URL or domain
            timeout: Request timeout in seconds
        """
        # Clean and normalize target
        self.target = target.lower().strip()
        if self.target.startswith('http://') or self.target.startswith('https://'):
            self.target = self.target.split('://')[1].split('/')[0]
        
        self.timeout = timeout
        self.timestamp = datetime.now()
        logger.debug(f"TechDetector initialized for target: {self.target}")
    
    def _make_request(self, use_https: bool = True) -> Optional[Dict[str, Any]]:
        """
        Make HTTP/HTTPS request and return response data.
        
        Args:
            use_https: Whether to use HTTPS
            
        Returns:
            Dictionary with headers and body, or None on failure
        """
        try:
            if use_https:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                conn = http.client.HTTPSConnection(self.target, timeout=self.timeout, context=context)
            else:
                conn = http.client.HTTPConnection(self.target, timeout=self.timeout)
            
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Connection': 'close',
            }
            
            conn.request('GET', '/', headers=headers)
            response = conn.getresponse()
            
            result = {
                'status': response.status,
                'headers': dict(response.getheaders()),
                'body': response.read().decode('utf-8', errors='ignore'),
            }
            
            conn.close()
            return result
        
        except Exception as e:
            logger.debug(f"Request error ({'HTTPS' if use_https else 'HTTP'}): {e}")
            return None
    
    def _detect_from_headers(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """
        Detect technologies from HTTP headers.
        
        Args:
            headers: HTTP response headers
            
        Returns:
            Dictionary with detected technologies
        """
        detected = {
            'server': None,
            'technologies': [],
            'security_headers': {},
            'cookies': [],
        }
        
        headers_lower = {k.lower(): v for k, v in headers.items()}
        
        # Server header
        if 'server' in headers_lower:
            detected['server'] = headers_lower['server']
            for pattern, tech in self.HEADER_SIGNATURES['server'].items():
                if pattern in headers_lower['server'].lower():
                    detected['technologies'].append(tech)
        
        # X-Powered-By header
        if 'x-powered-by' in headers_lower:
            powered_by = headers_lower['x-powered-by']
            for pattern, tech in self.HEADER_SIGNATURES['x-powered-by'].items():
                if pattern in powered_by.lower():
                    detected['technologies'].append(tech)
        
        # Other technology headers
        tech_headers = {
            'x-aspnet-version': 'ASP.NET',
            'x-drupal-cache': 'Drupal',
            'x-generator': None,
            'x-shopify-stage': 'Shopify',
            'x-wix-request-id': 'Wix',
        }
        
        for header, tech in tech_headers.items():
            if header in headers_lower:
                if tech:
                    detected['technologies'].append(tech)
                elif header == 'x-generator':
                    detected['technologies'].append(f"Generator: {headers_lower[header]}")
        
        # Security headers analysis
        for header in self.SECURITY_HEADERS:
            header_lower = header.lower()
            if header_lower in headers_lower:
                detected['security_headers'][header] = headers_lower[header_lower]
        
        # Cookie analysis for technology hints
        if 'set-cookie' in headers_lower:
            cookies = headers_lower['set-cookie']
            # Check for technology-specific cookies
            cookie_hints = {
                'PHPSESSID': 'PHP',
                'ASP.NET': 'ASP.NET',
                'JSESSIONID': 'Java',
                'wp_': 'WordPress',
                'drupal': 'Drupal',
                'laravel': 'Laravel',
            }
            for pattern, tech in cookie_hints.items():
                if pattern.lower() in cookies.lower():
                    if tech not in detected['technologies']:
                        detected['technologies'].append(tech)
            
            detected['cookies'].append(cookies)
        
        return detected
    
    def _detect_from_content(self, body: str) -> List[str]:
        """
        Detect technologies from HTML content.
        
        Args:
            body: HTML response body
            
        Returns:
            List of detected technologies
        """
        detected = set()
        body_lower = body.lower()
        
        # Check content signatures
        for pattern, tech in self.CONTENT_SIGNATURES.items():
            if pattern.lower() in body_lower:
                detected.add(tech)
        
        # Parse HTML for more specific detection
        try:
            parser = MetaTagParser()
            parser.feed(body)
            
            # Check generator meta tag
            for generator in parser.generators:
                detected.add(f"Generator: {generator}")
            
            # Check script sources
            for script in parser.scripts:
                script_lower = script.lower()
                script_patterns = {
                    'jquery': 'jQuery',
                    'react': 'React',
                    'vue': 'Vue.js',
                    'angular': 'Angular',
                    'bootstrap': 'Bootstrap',
                    'modernizr': 'Modernizr',
                    'lodash': 'Lodash',
                    'moment': 'Moment.js',
                    'axios': 'Axios',
                    'gsap': 'GSAP',
                }
                for pattern, tech in script_patterns.items():
                    if pattern in script_lower:
                        detected.add(tech)
        
        except Exception as e:
            logger.debug(f"HTML parsing error: {e}")
        
        # Check for specific framework patterns
        framework_patterns = [
            (r'data-reactroot', 'React'),
            (r'ng-version="(\d+)', 'Angular'),
            (r'__vue__', 'Vue.js'),
            (r'Powered by ([^<]+)', None),  # Generic powered by
        ]
        
        for pattern, tech in framework_patterns:
            match = re.search(pattern, body, re.IGNORECASE)
            if match:
                if tech:
                    detected.add(tech)
                elif match.group(1):
                    detected.add(f"Powered by: {match.group(1)[:50]}")
        
        return list(detected)
    
    def _get_ssl_info(self) -> Optional[Dict[str, Any]]:
        """
        Get SSL certificate information.
        
        Returns:
            Dictionary with SSL certificate details
        """
        try:
            context = ssl.create_default_context()
            conn = context.wrap_socket(
                socket.socket(socket.AF_INET),
                server_hostname=self.target
            )
            conn.settimeout(self.timeout)
            conn.connect((self.target, 443))
            
            cert = conn.getpeercert()
            conn.close()
            
            if cert:
                return {
                    'subject': dict(x[0] for x in cert.get('subject', [])),
                    'issuer': dict(x[0] for x in cert.get('issuer', [])),
                    'version': cert.get('version'),
                    'notBefore': cert.get('notBefore'),
                    'notAfter': cert.get('notAfter'),
                    'serialNumber': cert.get('serialNumber'),
                    'subjectAltName': cert.get('subjectAltName', []),
                }
        except Exception as e:
            logger.debug(f"SSL info error: {e}")
        
        return None
    
    def detect(self) -> Dict[str, Any]:
        """
        Perform technology detection on target.
        
        Returns:
            Dictionary containing detection results
        """
        logger.info(f"Starting technology detection for: {self.target}")
        
        result = {
            'target': self.target,
            'timestamp': self.timestamp.isoformat(),
            'success': False,
            'https_available': False,
            'server': None,
            'technologies': [],
            'security_headers': {},
            'security_score': 0,
            'ssl_info': None,
            'error': None
        }
        
        try:
            # Try HTTPS first
            response = self._make_request(use_https=True)
            if response:
                result['https_available'] = True
                # Get SSL info
                result['ssl_info'] = self._get_ssl_info()
            else:
                # Fall back to HTTP
                response = self._make_request(use_https=False)
            
            if not response:
                result['error'] = "Could not connect to target"
                return result
            
            # Detect from headers
            header_detection = self._detect_from_headers(response['headers'])
            result['server'] = header_detection['server']
            result['technologies'].extend(header_detection['technologies'])
            result['security_headers'] = header_detection['security_headers']
            
            # Detect from content
            content_technologies = self._detect_from_content(response['body'])
            result['technologies'].extend(content_technologies)
            
            # Remove duplicates and sort
            result['technologies'] = sorted(list(set(result['technologies'])))
            
            # Calculate security score
            result['security_score'] = self._calculate_security_score(result)
            
            result['success'] = True
            logger.info(f"Technology detection completed. Found {len(result['technologies'])} technologies")
        
        except Exception as e:
            result['error'] = str(e)
            logger.error(f"Technology detection error: {e}")
        
        return result
    
    def _calculate_security_score(self, result: Dict[str, Any]) -> int:
        """
        Calculate a basic security score based on headers.
        
        Args:
            result: Detection results
            
        Returns:
            Security score (0-100)
        """
        score = 0
        max_score = 100
        
        # HTTPS available (+20)
        if result['https_available']:
            score += 20
        
        # Security headers (+10 each, max 60)
        important_headers = [
            'Strict-Transport-Security',
            'Content-Security-Policy',
            'X-Content-Type-Options',
            'X-Frame-Options',
            'X-XSS-Protection',
            'Referrer-Policy',
        ]
        
        for header in important_headers:
            if header in result['security_headers']:
                score += 10
        
        # SSL certificate valid (+20)
        if result.get('ssl_info'):
            score += 20
        
        return min(score, max_score)
    
    def get_summary(self) -> str:
        """
        Get a human-readable summary of technology detection results.
        
        Returns:
            Formatted string summary
        """
        result = self.detect()
        
        if not result['success']:
            return f"Technology detection failed for {self.target}: {result.get('error', 'Unknown error')}"
        
        summary = [
            f"\n{'='*60}",
            f"Technology Detection for: {self.target}",
            f"{'='*60}",
            f"Timestamp: {result['timestamp']}",
            f"HTTPS Available: {'Yes' if result['https_available'] else 'No'}",
            f"Server: {result['server'] or 'Not disclosed'}",
            f"Security Score: {result['security_score']}/100",
            "",
            "Detected Technologies:"
        ]
        
        if result['technologies']:
            for tech in result['technologies']:
                summary.append(f"  • {tech}")
        else:
            summary.append("  No technologies detected")
        
        summary.append("")
        summary.append("Security Headers:")
        
        if result['security_headers']:
            for header, value in result['security_headers'].items():
                # Truncate long values
                value_display = value[:60] + '...' if len(value) > 60 else value
                summary.append(f"  • {header}: {value_display}")
        else:
            summary.append("  No security headers found")
        
        # Missing important headers
        missing = []
        important = ['Strict-Transport-Security', 'Content-Security-Policy', 'X-Frame-Options']
        for header in important:
            if header not in result['security_headers']:
                missing.append(header)
        
        if missing:
            summary.append("")
            summary.append("Missing Security Headers:")
            for header in missing:
                summary.append(f"  ⚠ {header}")
        
        if result['ssl_info']:
            summary.append("")
            summary.append("SSL Certificate:")
            ssl = result['ssl_info']
            if ssl.get('subject'):
                summary.append(f"  Subject: {ssl['subject']}")
            if ssl.get('issuer'):
                summary.append(f"  Issuer: {ssl['issuer']}")
            if ssl.get('notAfter'):
                summary.append(f"  Expires: {ssl['notAfter']}")
        
        summary.append(f"\n{'='*60}\n")
        
        return '\n'.join(summary)


# CLI functionality when run directly
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Technology Detection Module")
    parser.add_argument("target", help="Target URL or domain")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    args = parser.parse_args()
    
    # Configure logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=log_level, format='%(asctime)s - %(levelname)s - %(message)s')
    
    # Perform detection
    detector = TechDetector(args.target, timeout=args.timeout)
    print(detector.get_summary())
