# coding: utf-8

# packages
import pandas as pd
from urllib.parse import urlparse
import re
from bs4 import BeautifulSoup
import whois
import urllib.request
import time
import socket
from urllib.error import HTTPError
from datetime import  datetime
import ssl
import requests
from tld import get_tld
import tldextract
import numpy as np
from difflib import SequenceMatcher
from sklearn.metrics import confusion_matrix, accuracy_score, precision_score, recall_score, f1_score


class FeatureExtraction:
    def __init__(self):
        # Initialize with basic known banks
        self.known_banks = [
            'nabilbank.com',
            'nicasiabank.com',
            'nepalbank.com.np',
            'bankofamerica.com',  # Add Bank of America
            # ... other initial banks ...
        ]
        
        # Common legitimate domains that are often targeted for typo-squatting
        self.common_legitimate_domains = {
            'google.com': 'Google',
            'amazon.com': 'Amazon',
            'facebook.com': 'Facebook',
            'microsoft.com': 'Microsoft',
            'apple.com': 'Apple',
            'netflix.com': 'Netflix',
            'paypal.com': 'PayPal',
            'linkedin.com': 'LinkedIn',
            'twitter.com': 'Twitter',
            'instagram.com': 'Instagram',
            'youtube.com': 'YouTube',
            'yahoo.com': 'Yahoo',
            'ebay.com': 'eBay',
            'walmart.com': 'Walmart',
            'target.com': 'Target',
            'bestbuy.com': 'Best Buy',
            'nike.com': 'Nike',
            'adidas.com': 'Adidas',
            'spotify.com': 'Spotify',
            'dropbox.com': 'Dropbox',
            'bankofamerica.com': 'Bank of America',  # Add Bank of America
            'wellsfargo.com': 'Wells Fargo',
            'chase.com': 'Chase',
            'citibank.com': 'Citibank'
        }
        
        # Load known legitimate domains from file
        self.known_legitimate_domains = self.load_known_domains()
        
        # Load blacklisted domains
        self.blacklisted_domains = self.load_blacklisted_domains()
        
        # Trusted TLDs for Nepal
        self.trusted_tlds = ['.np', '.com.np', '.org.np', '.edu.np', '.gov.np']
        
        # Trusted organizations
        self.trusted_orgs = [
            'nrb.org.np',  # Nepal Rastra Bank
            'sebon.gov.np',  # Securities Board of Nepal
            'ird.gov.np',   # Inland Revenue Department
            'mof.gov.np'    # Ministry of Finance
        ]
        
        # Cache for domain trust scores
        self.domain_trust_cache = {}
        
        # List of known suspicious TLDs
        self.suspicious_tlds = [
            'to', 'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'work', 'site', 'online',
            'click', 'link', 'bid', 'loan', 'download', 'stream', 'live', 'video'
        ]
        
        # List of known suspicious domains
        self.suspicious_domains = [
            '1337x', 'piratebay', 'rarbg', 'yts', 'eztv', 'limetorrents', 'torrentz',
            'kickass', 'extratorrent', 'torrentz2', 'torrentproject', 'torrentfunk',
            'bittorrent', 'utorrent', 'transmission', 'qbittorrent', 'deluge'
        ]
    
    def load_known_domains(self):
        """Load known legitimate domains from a file"""
        try:
            with open('known_domains.txt', 'r') as f:
                return set(line.strip() for line in f)
        except FileNotFoundError:
            return set()
    
    def save_known_domains(self):
        """Save known legitimate domains to a file"""
        with open('known_domains.txt', 'w') as f:
            for domain in self.known_legitimate_domains:
                f.write(f"{domain}\n")
    
    def load_blacklisted_domains(self):
        """Load blacklisted domains from a file"""
        try:
            with open('blacklisted_domains.txt', 'r') as f:
                return set(line.strip() for line in f)
        except FileNotFoundError:
            # Create file with some initial blacklisted domains if it doesn't exist
            initial_blacklist = {
                'phishing-example.com',
                'fake-bank-login.com',
                'suspicious-site.net',
                'malicious-domain.org',
                'fake-gov-site.gov',
                'scam-website.com',
                'fake-login-page.com',
                'suspicious-bank.com',
                'malware-site.com',
                'fake-payment.com'
            }
            with open('blacklisted_domains.txt', 'w') as f:
                for domain in initial_blacklist:
                    f.write(f"{domain}\n")
            return initial_blacklist
    
    def save_blacklisted_domain(self, domain):
        """Add a domain to the blacklist"""
        self.blacklisted_domains.add(domain)
        with open('blacklisted_domains.txt', 'a') as f:
            f.write(f"{domain}\n")
    
    def is_blacklisted(self, url):
        """Check if a URL is in the blacklist"""
        try:
            domain = self.get_domain(url)
            return domain in self.blacklisted_domains
        except:
            return False
    
    def check_blacklist(self, url):
        """Check URL against blacklist and return details"""
        try:
            domain = self.get_domain(url)
            if domain in self.blacklisted_domains:
                return {
                    'is_blacklisted': True,
                    'domain': domain,
                    'reason': 'This domain is known to be malicious'
                }
            
            # Check for similar domains (typo-squatting)
            for blacklisted in self.blacklisted_domains:
                if self.is_similar_domain(domain, blacklisted):
                    return {
                        'is_blacklisted': True,
                        'domain': domain,
                        'similar_to': blacklisted,
                        'reason': f'This domain is similar to a known malicious domain: {blacklisted}'
                    }
            
            return {
                'is_blacklisted': False,
                'domain': domain
            }
        except:
            return {
                'is_blacklisted': False,
                'domain': url,
                'error': 'Could not process domain'
            }
    
    def is_similar_domain(self, domain1, domain2):
        """Check if two domains are similar (for typo-squatting detection)"""
        # Remove common TLDs for comparison
        tlds = ['.com', '.net', '.org', '.gov', '.edu', '.np', '.com.np']
        d1 = domain1.lower()
        d2 = domain2.lower()
        
        for tld in tlds:
            d1 = d1.replace(tld, '')
            d2 = d2.replace(tld, '')
        
        # Calculate similarity ratio
        similarity = SequenceMatcher(None, d1, d2).ratio()
        
        # Consider domains similar if they're 80% similar
        return similarity > 0.8

    def is_trusted_domain(self, url):
        """Check if a domain is trusted based on multiple factors"""
        try:
            domain = self.get_domain(url)
            
            # Check cache first
            if domain in self.domain_trust_cache:
                return self.domain_trust_cache[domain]
            
            # Check if it's already in our known domains
            if domain in self.known_legitimate_domains:
                return True
            
            # Check for trusted TLDs
            if any(tld in domain for tld in self.trusted_tlds):
                return True
            
            # Check for trusted organizations
            if any(org in domain for org in self.trusted_orgs):
                return True
            
            # Check SSL certificate
            if self.check_ssl_certificate(url):
                # Check domain age
                if not self.check_domain_age(url):
                    # Check for suspicious patterns
                    if not self.check_suspicious_domain(url):
                        # Add to known domains if it passes all checks
                        self.known_legitimate_domains.add(domain)
                        self.save_known_domains()
                        self.domain_trust_cache[domain] = True
                        return True
            
            self.domain_trust_cache[domain] = False
            return False
            
        except:
            return False

    def havingIP(self,url):
        """If the domain part has IP then it is phishing otherwise legitimate"""
        match=re.search('(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  #IPv4
                    '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)'  #IPv4 in hexadecimal
                    '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}',url)     #Ipv6
        if match:
            return 1            # phishing
        else:
            return 0            # legitimate
    
    def long_url(self,url):
        """This function is defined in order to differntiate website based on the length of the URL"""
        if len(url) < 54:
            return 0            # legitimate
        else:
            return 1            # phishing
    
    def have_at_symbol(self,url):
        """This function is used to check whether the URL contains @ symbol or not"""
        if "@" in url:
            return 1            # phishing
        else:
            return 0            # legitimate
    
    def redirection(self,url):
        """If the url has symbol(//) after protocol then such URL is to be classified as phishing """
        if "//" in urlparse(url).path:
            return 1            # phishing
        else:
            return 0            # legitimate
        
    def prefix_suffix_separation(self,url):
        """If the domain has '-' symbol then it is considered as phishing site"""
        if "-" in urlparse(url).netloc:
            return 1            # phishing
        else:
            return 0            # legitimate
        
    def sub_domains(self,url):
        """If the url has more than 3 dots then it is a phishing"""
        if url.count(".") < 3:
            return 0            # legitimate
        else:
            return 1            # phishing
        
    def shortening_service(self,url):
        """Tiny URL -> phishing otherwise legitimate"""
        match=re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                    'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                    'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                    'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                    'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                    'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                    'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|tr\.im|link\.zip\.net',url)
        if match:
            return 1               # phishing
        else:
            return 0               # legitimate
        
    def domain_registration_length(self, url):
        """Check domain registration length with better error handling"""
        try:
            # Set a timeout for WHOIS lookup
            import socket
            socket.setdefaulttimeout(5)
            
            domain_name = whois.whois(urlparse(url).netloc)
            
            # If WHOIS lookup fails, try alternative checks
            if not domain_name or not domain_name.expiration_date:
                # Check if domain is in our known legitimate domains
                if self.is_trusted_domain(url):
                    return 0  # Trusted domain, assume legitimate
                
                # Check if domain has valid SSL
                if self.check_ssl_certificate(url):
                    return 0  # Has valid SSL, assume legitimate
                
                # Check if domain is in our blacklist
                if self.is_blacklisted(url):
                    return 1  # Blacklisted, mark as suspicious
                
                return 1  # Unknown domain with no WHOIS data, mark as suspicious
            
            expiration_date = domain_name.expiration_date
            today = time.strftime('%Y-%m-%d')
            today = datetime.strptime(today, '%Y-%m-%d')
            
            if isinstance(expiration_date, list):
                expiration_date = expiration_date[0]
            
            if isinstance(expiration_date, str):
                try:
                    expiration_date = datetime.strptime(expiration_date, '%Y-%m-%d')
                except:
                    return 1
            
            registration_length = abs((expiration_date - today).days)
            return 1 if registration_length / 182 <= 1 else 0
            
        except Exception as e:
            print(f"WHOIS lookup failed for {url}: {str(e)}")
            # If WHOIS fails, use alternative checks
            if self.is_trusted_domain(url):
                return 0  # Trusted domain, assume legitimate
            if self.check_ssl_certificate(url):
                return 0  # Has valid SSL, assume legitimate
            if self.is_blacklisted(url):
                return 1  # Blacklisted, mark as suspicious
            return 1  # Unknown domain with WHOIS failure, mark as suspicious

    def age_domain(self, url):
        """Check domain age with better error handling"""
        try:
            # Set a timeout for WHOIS lookup
            import socket
            socket.setdefaulttimeout(5)
            
            domain = urlparse(url).netloc
            domain_info = whois.whois(domain)
            
            # If WHOIS lookup fails, try alternative checks
            if not domain_info or not domain_info.creation_date:
                # Check if domain is in our known legitimate domains
                if self.is_trusted_domain(url):
                    return 0  # Trusted domain, assume legitimate
                
                # Check if domain has valid SSL
                if self.check_ssl_certificate(url):
                    return 0  # Has valid SSL, assume legitimate
                
                # Check if domain is in our blacklist
                if self.is_blacklisted(url):
                    return 1  # Blacklisted, mark as suspicious
                
                return 1  # Unknown domain with no WHOIS data, mark as suspicious
            
            creation_date = domain_info.creation_date
            
            # Handle different date formats and types
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            
            if isinstance(creation_date, str):
                try:
                    # Try different date formats
                    for date_format in ['%Y-%m-%d', '%Y-%m-%d %H:%M:%S', '%d-%b-%Y', '%Y/%m/%d']:
                        try:
                            creation_date = datetime.strptime(creation_date, date_format)
                            break
                        except ValueError:
                            continue
                except:
                    return 1
            
            # Calculate domain age in days
            current_date = datetime.now()
            domain_age_days = (current_date - creation_date).days
            
            # Check if domain is less than 6 months old
            return 1 if domain_age_days < 180 else 0
                
        except Exception as e:
            print(f"Error in age_domain for {url}: {str(e)}")
            # If WHOIS fails, use alternative checks
            if self.is_trusted_domain(url):
                return 0  # Trusted domain, assume legitimate
            if self.check_ssl_certificate(url):
                return 0  # Has valid SSL, assume legitimate
            if self.is_blacklisted(url):
                return 1  # Blacklisted, mark as suspicious
            return 1  # Unknown domain with WHOIS failure, mark as suspicious

    def dns_record(self, url):
        """Check DNS record with better error handling"""
        try:
            # Set a timeout for DNS lookup
            import socket
            socket.setdefaulttimeout(5)
            
            domain_name = urlparse(url).netloc
            
            # Try to resolve the domain
            try:
                socket.gethostbyname(domain_name)
                return 0  # DNS record exists
            except socket.gaierror:
                # If DNS lookup fails, try alternative checks
                if self.is_trusted_domain(url):
                    return 0  # Trusted domain, assume legitimate
                if self.check_ssl_certificate(url):
                    return 0  # Has valid SSL, assume legitimate
                if self.is_blacklisted(url):
                    return 1  # Blacklisted, mark as suspicious
                return 1  # No DNS record, mark as suspicious
                
        except Exception as e:
            print(f"DNS lookup failed for {url}: {str(e)}")
            # If DNS check fails, use alternative checks
            if self.is_trusted_domain(url):
                return 0  # Trusted domain, assume legitimate
            if self.check_ssl_certificate(url):
                return 0  # Has valid SSL, assume legitimate
            if self.is_blacklisted(url):
                return 1  # Blacklisted, mark as suspicious
            return 1  # Unknown domain with DNS failure, mark as suspicious
        
    def statistical_report(self,url):
        hostname = url
        h = [(x.start(0), x.end(0)) for x in re.finditer('https://|http://|www.|https://www.|http://www.', hostname)]
        z = int(len(h))
        if z != 0:
            y = h[0][1]
            hostname = hostname[y:]
            h = [(x.start(0), x.end(0)) for x in re.finditer('/', hostname)]
            z = int(len(h))
            if z != 0:
                hostname = hostname[:h[0][0]]
        url_match=re.search('at\.ua|usa\.cc|baltazarpresentes\.com\.br|pe\.hu|esy\.es|hol\.es|sweddy\.com|myjino\.ru|96\.lt|ow\.ly',url)
        try:
            ip_address = socket.gethostbyname(hostname)
            ip_match=re.search('146\.112\.61\.108|213\.174\.157\.151|121\.50\.168\.88|192\.185\.217\.116|78\.46\.211\.158|181\.174\.165\.13|46\.242\.145\.103|121\.50\.168\.40|83\.125\.22\.219|46\.242\.145\.98|107\.151\.148\.44|107\.151\.148\.107|64\.70\.19\.203|199\.184\.144\.27|107\.151\.148\.108|107\.151\.148\.109|119\.28\.52\.61|54\.83\.43\.69|52\.69\.166\.231|216\.58\.192\.225|118\.184\.25\.86|67\.208\.74\.71|23\.253\.126\.58|104\.239\.157\.210|175\.126\.123\.219|141\.8\.224\.221|10\.10\.10\.10|43\.229\.108\.32|103\.232\.215\.140|69\.172\.201\.153|216\.218\.185\.162|54\.225\.104\.146|103\.243\.24\.98|199\.59\.243\.120|31\.170\.160\.61|213\.19\.128\.77|62\.113\.226\.131|208\.100\.26\.234|195\.16\.127\.102|195\.16\.127\.157|34\.196\.13\.28|103\.224\.212\.222|172\.217\.4\.225|54\.72\.9\.51|192\.64\.147\.141|198\.200\.56\.183|23\.253\.164\.103|52\.48\.191\.26|52\.214\.197\.72|87\.98\.255\.18|209\.99\.17\.27|216\.38\.62\.18|104\.130\.124\.96|47\.89\.58\.141|78\.46\.211\.158|54\.86\.225\.156|54\.82\.156\.19|37\.157\.192\.102|204\.11\.56\.48|110\.34\.231\.42',ip_address)  
        except:
            return 1

        if url_match:
            return 1
        else:
            return 0
        
    def https_token(self,url):
        match=re.search('https://|http://',url)
        try:
            if match.start(0)==0 and match.start(0) is not None:
                url=url[match.end(0):]
                match=re.search('http|https',url)
                if match:
                    return 1
                else:
                    return 0
        except:
            return 1

    def check_ssl_certificate(self, url):
        """Check if the website has a valid SSL certificate"""
        try:
            hostname = urlparse(url).netloc
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    # Additional check for certificate issuer
                    issuer = dict(x[0] for x in cert['issuer'])
                    if 'organizationName' in issuer:
                        org = issuer['organizationName'].lower()
                        if 'government' not in org and 'gov' not in org and 'state' not in org:
                            return 0
                    return 1
        except:
            return 0

    def check_suspicious_words(self, url):
        """Check for suspicious words in the URL"""
        suspicious_words = ['login', 'signin', 'account', 'banking', 'secure', 'webscr', 'password', 'verify', 'confirm']
        url_lower = url.lower()
        return 1 if any(word in url_lower for word in suspicious_words) else 0

    def check_url_entropy(self, url):
        """Calculate the entropy of the URL to detect random-looking domains"""
        def entropy(string):
            counts = {}
            for char in string:
                counts[char] = counts.get(char, 0) + 1
            probs = [float(count) / len(string) for count in counts.values()]
            return -sum(p * np.log2(p) for p in probs)
        
        domain = urlparse(url).netloc
        return 1 if entropy(domain) > 3.5 else 0

    def check_domain_trust(self, url):
        """Check if the domain is from a trusted TLD"""
        trusted_tlds = ['com', 'org', 'net', 'edu', 'gov']
        try:
            tld = get_tld(url, fail_silently=True)
            return 0 if tld in trusted_tlds else 1
        except:
            return 1

    def check_redirect_chain(self, url):
        """Check for suspicious redirect chains"""
        try:
            response = requests.get(url, allow_redirects=True)
            if len(response.history) > 2:
                return 1
            # Check if final URL is different from original
            if response.url != url:
                return 1
            return 0
        except:
            return 1

    def check_suspicious_tld(self, url):
        """Check for suspicious top-level domains"""
        suspicious_tlds = ['.to', '.tk', '.xyz', '.info', '.biz']
        try:
            domain = self.get_domain(url)
            return any(tld in domain for tld in suspicious_tlds)
        except:
            return False

    def check_suspicious_domain(self, url):
        """Check for suspicious domain patterns"""
        suspicious_patterns = [
            'verify-', 'secure-', 'login-', 'signin-', 'account-',
            'update-', 'confirm-', 'validate-', 'check-', 'verify.',
            'secure.', 'login.', 'signin.', 'account.', 'update.',
            'confirm.', 'validate.', 'check.'
        ]
        try:
            domain = self.get_domain(url)
            # Skip check for known legitimate domains
            if self.is_known_bank(url):
                return False
            return any(pattern in domain for pattern in suspicious_patterns)
        except:
            return False

    def check_domain_hyphens(self, url):
        """Check for multiple hyphens in domain name"""
        domain = urlparse(url).netloc
        return 1 if domain.count('-') > 1 else 0

    def check_suspicious_port(self, url):
        """Check if URL uses non-standard ports"""
        parsed = urlparse(url)
        if parsed.port and parsed.port not in [80, 443]:
            return 1
        return 0

    def check_suspicious_path(self, url):
        """Check for suspicious patterns in URL path"""
        suspicious_patterns = ['/wp-content/', '/wp-admin/', '/admin/', '/login/', '/signin/']
        path = urlparse(url).path.lower()
        return 1 if any(pattern in path for pattern in suspicious_patterns) else 0

    def check_domain_age(self, url):
        """Check if domain is very new (less than 6 months)"""
        try:
            domain = whois.whois(urlparse(url).netloc)
            if domain.creation_date:
                if isinstance(domain.creation_date, list):
                    creation_date = domain.creation_date[0]
                else:
                    creation_date = domain.creation_date
                age_days = (datetime.now() - creation_date).days
                return 1 if age_days < 180 else 0
        except:
            pass
        return 1

    def check_gov_spoofing(self, url):
        """Check for potential government website spoofing"""
        try:
            # Extract domain and path
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            path = parsed.path.lower()
            
            # Check for common government website spoofing patterns
            suspicious_patterns = [
                'gov-', 'gov_', 'gov.', 'government-', 'government_',
                'verify-', 'secure-', 'login-', 'signin-', 'update-',
                'confirm-', 'validate-', 'check-', 'verify.', 'secure.',
                'login.', 'signin.', 'update.', 'confirm.', 'validate.',
                'check.'
            ]
            
            # Check domain for suspicious patterns
            for pattern in suspicious_patterns:
                if pattern in domain:
                    return 1
            
            # Check for mismatched SSL certificate
            if not self.check_ssl_certificate(url):
                return 1
            
            # Check for suspicious redirects
            if self.check_redirect_chain(url):
                return 1
            
            # Check for IP address in domain
            if self.havingIP(url):
                return 1
            
            # Check for multiple subdomains (common in spoofing)
            if domain.count('.') > 2:
                return 1
            
            return 0
        except:
            return 1

    def is_known_bank(self, url):
        """Check if the URL belongs to a known legitimate bank or financial institution"""
        try:
            domain = self.get_domain(url)
            return any(bank in domain for bank in self.known_banks)
        except:
            return False

    def get_domain(self, url):
        """Extract and normalize domain from URL"""
        try:
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
            
            # Parse the URL
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            
            # Remove 'www.' if present
            if domain.startswith('www.'):
                domain = domain[4:]
            
            return domain
        except:
            return url.lower()

    def check_typo_squatting(self, url):
        """Check if a domain is a typo-squatting attempt of a legitimate domain"""
        try:
            domain = self.get_domain(url)
            
            # First check if this is a legitimate domain
            if domain in self.common_legitimate_domains:
                return {
                    'is_typo_squatting': False
                }
            
            # Check if domain is in our known legitimate domains
            if domain in self.known_legitimate_domains:
                return {
                    'is_typo_squatting': False
                }
            
            # Check if domain has valid SSL certificate
            if self.check_ssl_certificate(url):
                return {
                    'is_typo_squatting': False
                }
            
            # Remove common TLDs for comparison
            tlds = ['.com', '.net', '.org', '.gov', '.edu', '.np', '.com.np']
            domain_no_tld = domain
            for tld in tlds:
                domain_no_tld = domain_no_tld.replace(tld, '')
            
            # Common number-to-letter substitutions
            number_to_letter = {
                '0': 'o',
                '1': 'i',
                '3': 'e',
                '4': 'a',
                '5': 's',
                '8': 'b',
                '9': 'g'
            }
            
            # Common letter-to-letter substitutions
            letter_to_letter = {
                'vv': 'w',
                'rn': 'm',
                'cl': 'd',
                'vvv': 'w',
                'rnrn': 'm',
                'clcl': 'd'
            }
            
            # Check against common legitimate domains
            for legit_domain, company_name in self.common_legitimate_domains.items():
                legit_no_tld = legit_domain.replace('.com', '')
                
                # Skip if the domains are identical
                if domain_no_tld == legit_no_tld:
                    continue
                
                # Calculate base similarity ratio
                similarity = SequenceMatcher(None, domain_no_tld, legit_no_tld).ratio()
                
                # Only proceed with typo-squatting checks if domains are similar enough
                if similarity > 0.8:
                    # Check for number substitutions in domain
                    domain_with_substitutions = domain_no_tld
                    for num, letter in number_to_letter.items():
                        domain_with_substitutions = domain_with_substitutions.replace(num, letter)
                    
                    # Check for letter substitutions
                    for wrong, correct in letter_to_letter.items():
                        domain_with_substitutions = domain_with_substitutions.replace(wrong, correct)
                    
                    # Check if the domain matches after substitutions
                    if domain_with_substitutions == legit_no_tld:
                        return {
                            'is_typo_squatting': True,
                            'original_domain': legit_domain,
                            'company_name': company_name,
                            'similarity': 0.9,
                            'reason': f'This domain appears to be impersonating {company_name} using number/letter substitutions'
                        }
                    
                    # Check for high similarity with specific conditions
                    if (len(domain_no_tld) == len(legit_no_tld) and  # Same length
                        sum(1 for a, b in zip(domain_no_tld, legit_no_tld) if a != b) <= 2):  # At most 2 differences
                        return {
                            'is_typo_squatting': True,
                            'original_domain': legit_domain,
                            'company_name': company_name,
                            'similarity': similarity,
                            'reason': f'This domain appears to be impersonating {company_name} with slight misspellings'
                        }
            
            # Check for number substitutions in TLD
            tld = domain.split('.')[-1]
            for num, letter in number_to_letter.items():
                if tld.replace(num, letter) in ['com', 'net', 'org', 'gov', 'edu']:
                    return {
                        'is_typo_squatting': True,
                        'original_domain': f"{domain_no_tld}.{tld.replace(num, letter)}",
                        'company_name': 'Unknown',
                        'similarity': 0.9,
                        'reason': 'This domain uses number substitutions in the TLD to impersonate a legitimate domain'
                    }
            
            # Check for any number substitutions in the entire domain
            if any(num in domain for num in number_to_letter.keys()):
                # Check if it's similar to any known domain after number substitutions
                domain_with_all_substitutions = domain
                for num, letter in number_to_letter.items():
                    domain_with_all_substitutions = domain_with_all_substitutions.replace(num, letter)
                
                for legit_domain, company_name in self.common_legitimate_domains.items():
                    if domain_with_all_substitutions == legit_domain:
                        return {
                            'is_typo_squatting': True,
                            'original_domain': legit_domain,
                            'company_name': company_name,
                            'similarity': 0.9,
                            'reason': f'This domain uses number substitutions to impersonate {company_name}'
                        }
            
            # If no typo-squatting detected, add domain to known legitimate domains if it passes basic checks
            if (self.check_ssl_certificate(url) and 
                not self.check_suspicious_domain(url) and 
                not self.check_suspicious_tld(url)):
                self.known_legitimate_domains.add(domain)
                self.save_known_domains()
            
            return {
                'is_typo_squatting': False
            }
        except:
            return {
                'is_typo_squatting': False
            }

    def calculate_confusion_matrix(self, predictions, actual_labels):
        """Calculate confusion matrix for model evaluation"""
        # Calculate confusion matrix
        cm = confusion_matrix(actual_labels, predictions)
        
        # Calculate metrics
        accuracy = accuracy_score(actual_labels, predictions)
        precision = precision_score(actual_labels, predictions)
        recall = recall_score(actual_labels, predictions)
        f1 = f1_score(actual_labels, predictions)
        
        return {
            'confusion_matrix': cm,
            'accuracy': accuracy,
            'precision': precision,
            'recall': recall,
            'f1_score': f1
        }

    def reduce_false_positives(self, url, features):
        """Apply additional checks to reduce false positives"""
        try:
            # Check if domain is in trusted list
            if self.is_trusted_domain(url):
                return False  # Not phishing
            
            # Check SSL certificate
            if self.check_ssl_certificate(url):
                # Additional checks for SSL-certified domains
                if not self.check_suspicious_domain(url) and not self.check_suspicious_tld(url):
                    return False  # Not phishing
            
            # Check domain age with more lenient threshold
            try:
                domain_info = whois.whois(urlparse(url).netloc)
                if domain_info and domain_info.creation_date:
                    creation_date = domain_info.creation_date
                    if isinstance(creation_date, list):
                        creation_date = creation_date[0]
                    if isinstance(creation_date, str):
                        creation_date = datetime.strptime(creation_date, '%Y-%m-%d')
                    domain_age_days = (datetime.now() - creation_date).days
                    if domain_age_days > 365:  # More lenient age threshold
                        return False  # Not phishing
            except:
                pass
            
            # Check for legitimate business patterns
            if (not self.check_suspicious_words(url) and 
                not self.check_suspicious_domain(url) and 
                not self.check_suspicious_tld(url)):
                return False  # Not phishing
            
            # If all checks pass, return original prediction
            return True  # Phishing
            
        except Exception as e:
            print(f"Error in reduce_false_positives: {str(e)}")
            return True  # Default to phishing on error

    def getAttributess(self, url):
        """Get attributes for URL classification with specific phishing reasons"""
        try:
            # Initialize reasons list
            phishing_reasons = []
            
            # First check if this is a known legitimate domain
            domain = self.get_domain(url)
            if domain in self.known_legitimate_domains or domain in self.common_legitimate_domains:
                return pd.DataFrame([{
                    'long_url': 0,
                    'having_@_symbol': 0,
                    'redirection_//_symbol': 0,
                    'prefix_suffix_seperation': 0,
                    'sub_domains': 0,
                    'having_ip_address': 0,
                    'shortening_service': 0,
                    'https_token': 0,
                    'web_traffic': 0,
                    'domain_registration_length': 0,
                    'dns_record': 0,
                    'age_of_domain': 0,
                    'statistical_report': 0
                }]), []

            # Quick checks first (typo-squatting and blacklist)
            typo_check = self.check_typo_squatting(url)
            if typo_check['is_typo_squatting']:
                phishing_reasons.append(typo_check['reason'])
                return pd.DataFrame([{
                    'long_url': 1,
                    'having_@_symbol': 0,
                    'redirection_//_symbol': 0,
                    'prefix_suffix_seperation': 1,
                    'sub_domains': 0,
                    'having_ip_address': 0,
                    'shortening_service': 0,
                    'https_token': 0,
                    'web_traffic': 1,
                    'domain_registration_length': 1,
                    'dns_record': 0,
                    'age_of_domain': 1,
                    'statistical_report': 1
                }]), phishing_reasons

            # Quick feature checks that don't require network calls
            features = {}
            reasons = {
                'long_url': 'URL is suspiciously long',
                'having_@_symbol': 'URL contains @ symbol which is suspicious',
                'redirection_//_symbol': 'URL contains suspicious redirection',
                'prefix_suffix_seperation': 'URL contains suspicious prefix/suffix separation',
                'sub_domains': 'URL contains suspicious number of subdomains',
                'having_ip_address': 'URL contains IP address instead of domain name',
                'shortening_service': 'URL uses URL shortening service',
                'https_token': 'URL has suspicious HTTPS token'
            }

            # Check each feature and collect reasons
            for feature, check_method in [
                ('long_url', self.long_url),
                ('having_@_symbol', self.have_at_symbol),
                ('redirection_//_symbol', self.redirection),
                ('prefix_suffix_seperation', self.prefix_suffix_separation),
                ('sub_domains', self.sub_domains),
                ('having_ip_address', self.havingIP),
                ('shortening_service', self.shortening_service),
                ('https_token', self.https_token)
            ]:
                result = check_method(url)
                features[feature] = result
                if result == 1 and feature in reasons:
                    phishing_reasons.append(reasons[feature])

            # If any of the quick checks indicate phishing, set other features to suspicious
            if any(features.values()):
                features.update({
                    'web_traffic': 1,
                    'domain_registration_length': 1,
                    'dns_record': 0,
                    'age_of_domain': 1,
                    'statistical_report': 1
                })
                
                # Apply false positive reduction
                if not self.reduce_false_positives(url, features):
                    # Reset features to legitimate if false positive reduction passes
                    features = {k: 0 for k in features.keys()}
                    phishing_reasons = []  # Clear reasons if it's a false positive
                    
                    # Add domain to known legitimate domains if it passes all checks
                    if self.check_ssl_certificate(url):
                        self.known_legitimate_domains.add(domain)
                        self.save_known_domains()
                
                return pd.DataFrame([features]), phishing_reasons

            # Only perform slow checks if quick checks passed
            try:
                # Set a timeout for WHOIS and DNS checks
                import socket
                socket.setdefaulttimeout(5)  # 5 second timeout
                
                slow_features = {
                    'web_traffic': self.statistical_report(url),
                    'domain_registration_length': self.domain_registration_length(url),
                    'dns_record': self.dns_record(url),
                    'age_of_domain': self.age_domain(url),
                    'statistical_report': self.statistical_report(url)
                }
                
                # Add reasons for slow checks
                slow_reasons = {
                    'web_traffic': 'Suspicious web traffic patterns detected',
                    'domain_registration_length': 'Domain registration period is suspiciously short',
                    'dns_record': 'No valid DNS record found',
                    'age_of_domain': 'Domain is suspiciously new',
                    'statistical_report': 'Statistical analysis indicates suspicious patterns'
                }
                
                for feature, value in slow_features.items():
                    features[feature] = value
                    if value == 1 and feature in slow_reasons:
                        phishing_reasons.append(slow_reasons[feature])
                
                # Apply false positive reduction
                if not self.reduce_false_positives(url, features):
                    # Reset features to legitimate if false positive reduction passes
                    features = {k: 0 for k in features.keys()}
                    phishing_reasons = []  # Clear reasons if it's a false positive
                    
                    # Add domain to known legitimate domains if it passes all checks
                    if self.check_ssl_certificate(url):
                        self.known_legitimate_domains.add(domain)
                        self.save_known_domains()
                    
            except:
                # If slow checks fail, assume suspicious
                features.update({
                    'web_traffic': 1,
                    'domain_registration_length': 1,
                    'dns_record': 1,
                    'age_of_domain': 1,
                    'statistical_report': 1
                })
                phishing_reasons.append('Unable to verify domain legitimacy')
        
            # Create DataFrame with features in the correct order
            feature_order = [
                'long_url',
                'having_@_symbol',
                'redirection_//_symbol',
                'prefix_suffix_seperation',
                'sub_domains',
                'having_ip_address',
                'shortening_service',
                'https_token',
                'web_traffic',
                'domain_registration_length',
                'dns_record',
                'age_of_domain',
                'statistical_report'
            ]
            
            return pd.DataFrame([features])[feature_order], phishing_reasons

        except Exception as e:
            print(f"Error in getAttributess: {str(e)}")
            # Return suspicious features on error
            return pd.DataFrame([{
                'long_url': 1,
                'having_@_symbol': 0,
                'redirection_//_symbol': 0,
                'prefix_suffix_seperation': 1,
                'sub_domains': 0,
                'having_ip_address': 0,
                'shortening_service': 0,
                'https_token': 0,
                'web_traffic': 1,
                'domain_registration_length': 1,
                'dns_record': 1,
                'age_of_domain': 1,
                'statistical_report': 1
            }]), ['Error occurred during URL analysis']

    def validate_url(self, url):
        """Validates if the provided string is a valid URL"""
        try:
            # Check if URL is empty or None
            if not url or not url.strip():
                return False, "Please provide a URL"

            # Add http:// if no protocol is specified
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url

            # Parse the URL
            parsed = urlparse(url)
            
            # Check if domain is present
            if not parsed.netloc:
                return False, "Invalid URL: No domain found"

            # Check if domain has at least one dot
            if '.' not in parsed.netloc:
                return False, "Invalid URL: Domain must contain at least one dot (.)"

            # Check if domain is too short
            if len(parsed.netloc) < 3:
                return False, "Invalid URL: Domain is too short"

            # Check for invalid characters in domain
            invalid_chars = [' ', '<', '>', '{', '}', '|', '\\', '^', '~', '[', ']', '`']
            if any(char in parsed.netloc for char in invalid_chars):
                return False, "Invalid URL: Contains invalid characters"

            # Check if domain ends with a dot
            if parsed.netloc.endswith('.'):
                return False, "Invalid URL: Domain cannot end with a dot"

            # Check if domain has valid TLD
            tld = parsed.netloc.split('.')[-1]
            if len(tld) < 2:
                return False, "Invalid URL: Top-level domain is too short"

            # Check for consecutive dots
            if '..' in parsed.netloc:
                return False, "Invalid URL: Domain contains consecutive dots"

            # Check for valid domain name format
            domain_parts = parsed.netloc.split('.')
            for part in domain_parts:
                if not part or len(part) < 1:
                    return False, "Invalid URL: Domain parts cannot be empty"
                if part.startswith('-') or part.endswith('-'):
                    return False, "Invalid URL: Domain parts cannot start or end with a hyphen"

            return True, url
        except Exception as e:
            return False, f"Invalid URL: {str(e)}"

    