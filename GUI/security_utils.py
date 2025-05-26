import ssl
import socket
import requests
from urllib.parse import urlparse
import time
from functools import wraps
from flask import request, jsonify
import ipwhois
import dns.resolver
import concurrent.futures
from datetime import datetime, timedelta

class SecurityUtils:
    def __init__(self):
        pass

    def check_ssl_certificate(self, url):
        """Check SSL certificate validity"""
        try:
            # Extract domain from URL
            domain = urlparse(url).netloc
            
            # First check if domain is resolvable
            try:
                socket.gethostbyname(domain)
            except socket.gaierror:
                return {
                    'valid': False,
                    'error': f"Domain '{domain}' cannot be resolved. This could indicate a phishing attempt or the website is no longer active."
                }
            
            # Create SSL context
            context = ssl.create_default_context()
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED
            
            # Try to establish SSL connection
            try:
                with socket.create_connection((domain, 443), timeout=10) as sock:
                    with context.wrap_socket(sock, server_hostname=domain) as ssock:
                        cert = ssock.getpeercert()
                        
                        # Check certificate expiration
                        not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                        if not_after < datetime.now():
                            return {
                                'valid': False,
                                'error': "⚠️ Security Warning: This website's security certificate has expired. This indicates the website may not be properly maintained."
                            }
                        
                        return {
                            'valid': True,
                            'cert': cert
                        }
            except ssl.SSLError as e:
                error_msg = str(e)
                if "CERTIFICATE_VERIFY_FAILED" in error_msg:
                    return {
                        'valid': False,
                        'error': "⚠️ Security Warning: This website's security certificate cannot be verified. This could mean the website is not properly secured or is trying to impersonate a legitimate site."
                    }
                elif "CERTIFICATE_HAS_EXPIRED" in error_msg:
                    return {
                        'valid': False,
                        'error': "⚠️ Security Warning: This website's security certificate has expired. This indicates the website may not be properly maintained."
                    }
                else:
                    return {
                        'valid': False,
                        'error': "⚠️ Security Warning: This website's security certificate has issues that prevent secure connection."
                    }
            except socket.timeout:
                return {
                    'valid': False,
                    'error': "⚠️ Security Warning: Connection timed out while checking the website's security certificate."
                }
            except ConnectionRefusedError:
                return {
                    'valid': False,
                    'error': "⚠️ Security Warning: The website is not accepting secure connections."
                }
            except Exception as e:
                return {
                    'valid': False,
                    'error': "⚠️ Security Warning: Unable to verify this website's security certificate."
                }
                
        except Exception as e:
            return {
                'valid': False,
                'error': "⚠️ Security Warning: Unable to check this website's security certificate."
            }

    def check_redirect_chain(self, url):
        """Check complete redirect chain for suspicious patterns"""
        try:
            redirect_chain = []
            current_url = url
            max_redirects = 10
            redirect_count = 0
            
            while redirect_count < max_redirects:
                response = requests.head(current_url, allow_redirects=False)
                redirect_chain.append({
                    'url': current_url,
                    'status_code': response.status_code,
                    'headers': dict(response.headers)
                })
                
                if response.status_code not in [301, 302, 303, 307, 308]:
                    break
                    
                if 'Location' not in response.headers:
                    break
                    
                current_url = response.headers['Location']
                redirect_count += 1
            
            # Analyze redirect chain for suspicious patterns
            analysis = {
                'chain': redirect_chain,
                'suspicious': False,
                'reasons': []
            }
            
            # Check for suspicious patterns
            for redirect in redirect_chain:
                # Check for protocol downgrade
                if redirect['url'].startswith('https://') and current_url.startswith('http://'):
                    analysis['suspicious'] = True
                    analysis['reasons'].append('Protocol downgrade detected')
                
                # Check for suspicious TLD changes
                if self._is_suspicious_tld_change(redirect['url'], current_url):
                    analysis['suspicious'] = True
                    analysis['reasons'].append('Suspicious TLD change detected')
            
            return analysis
        except Exception as e:
            return {
                'error': str(e),
                'chain': [],
                'suspicious': True,
                'reasons': ['Error analyzing redirect chain']
            }

    def _check_dns_records(self, domain):
        """Check if domain has valid DNS records"""
        try:
            # Check multiple DNS record types
            has_records = False
            warnings = []
            
            # Check A records
            try:
                answers = dns.resolver.resolve(domain, 'A')
                if answers:
                    has_records = True
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                pass
            
            # Check CNAME records
            try:
                answers = dns.resolver.resolve(domain, 'CNAME')
                if answers:
                    has_records = True
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                pass
            
            # Check MX records
            try:
                answers = dns.resolver.resolve(domain, 'MX')
                if answers:
                    has_records = True
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                pass
            
            # Check NS records
            try:
                answers = dns.resolver.resolve(domain, 'NS')
                if answers:
                    has_records = True
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                pass
            
            # Check TXT records
            try:
                answers = dns.resolver.resolve(domain, 'TXT')
                if answers:
                    has_records = True
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                pass
            
            if not has_records:
                warnings.append("This website appears to be inactive or improperly configured. Legitimate websites should have proper internet settings.")
            
            return {
                'is_valid': has_records,
                'warnings': warnings
            }
            
        except Exception as e:
            print(f"Error checking DNS records: {str(e)}")
            return {
                'is_valid': False,
                'warnings': ["This website appears to be inactive or improperly configured. Legitimate websites should have proper internet settings."]
            }

    def check_ip_reputation(self, url):
        """Check IP reputation using multiple services"""
        try:
            parsed_url = urlparse(url)
            hostname = parsed_url.netloc
            
            # Check DNS records first
            dns_check = self._check_dns_records(hostname)
            if not dns_check['is_valid']:
                return {
                    'is_suspicious': True,
                    'warnings': dns_check['warnings'],
                    'error': dns_check['warnings'][0]
                }
            
            # Resolve IP address
            try:
                ip_address = socket.gethostbyname(hostname)
            except socket.gaierror:
                return {
                    'is_suspicious': True,
                    'warnings': [f"Could not find this website's internet address. This is unusual for legitimate websites."],
                    'error': f"Could not verify this website's internet address"
                }
            
            # Get IP information
            try:
                ip_info = ipwhois.IPWhois(ip_address).lookup_whois()
            except Exception as e:
                ip_info = {
                    'asn': None,
                    'asn_description': None,
                    'country': None
                }
            
            # Check if IP is in known bad IP ranges
            is_suspicious = self._check_suspicious_ip_ranges(ip_address)
            
            return {
                'ip_address': ip_address,
                'asn': ip_info.get('asn'),
                'asn_description': ip_info.get('asn_description'),
                'country': ip_info.get('country'),
                'dns_records': dns_check['records'],
                'warnings': dns_check['warnings'],
                'is_suspicious': is_suspicious
            }
        except Exception as e:
            return {
                'error': str(e),
                'warnings': ["Could not verify this website's security settings"],
                'is_suspicious': True
            }

    def _check_suspicious_ip_ranges(self, ip_address):
        """Check if IP is in known suspicious ranges"""
        # This is a simplified version. In production, you would want to:
        # 1. Use a proper IP reputation database
        # 2. Check against known malicious IP ranges
        # 3. Consider geolocation
        return False

    def _is_suspicious_tld_change(self, url1, url2):
        """Check if TLD change between redirects is suspicious"""
        tld1 = urlparse(url1).netloc.split('.')[-1]
        tld2 = urlparse(url2).netloc.split('.')[-1]
        
        suspicious_tlds = ['tk', 'ml', 'ga', 'cf', 'gq', 'xyz']
        
        return tld1 != tld2 and (tld2 in suspicious_tlds or tld1 in suspicious_tlds) 