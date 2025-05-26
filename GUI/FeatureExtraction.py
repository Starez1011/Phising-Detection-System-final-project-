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
import os


class FeatureExtraction:
    def __init__(self):
        self.suspicious_tlds = ['tk', 'ml', 'ga', 'cf', 'gq', 'xyz']
        self.suspicious_domains = ['login', 'signin', 'account', 'secure', 'webscr', 'banking']
        self.legitimate_tlds = ['com', 'org', 'net', 'edu', 'gov', 'co', 'io']
        self.legitimate_domains = ['google', 'microsoft', 'apple', 'amazon', 'facebook']

    def getAttributess(self, url):
        """Extract features from URL and return them along with any phishing reasons"""
        try:
            # Validate URL first
            is_valid, validated_url = self.validate_url(url)
            if not is_valid:
                return None, [validated_url]  # Return error message as reason
            
            url = validated_url
            print(f"Processing URL: {url}")
            
            # Extract features
            features = {}
            phishing_reasons = []
            
            # Basic URL features
            features['long_url'] = 1 if len(url) > 150 else 0  # Increased threshold
            if features['long_url']:
                phishing_reasons.append("URL is unusually long")
            
            # Check for @ symbol
            features['having_@_symbol'] = 1 if '@' in url else 0
            if features['having_@_symbol']:
                phishing_reasons.append("URL contains @ symbol (high risk)")
            
            # Check for redirection
            features['redirection_//_symbol'] = 1 if '//' in url[8:] else 0
            if features['redirection_//_symbol']:
                phishing_reasons.append("URL contains suspicious redirection")
            
            # Check for prefix-suffix separation
            domain = urlparse(url).netloc
            features['prefix_suffix_seperation'] = 1 if '-' in domain and len(domain.split('-')) > 2 else 0
            if features['prefix_suffix_seperation']:
                phishing_reasons.append("Domain contains multiple hyphens")
            
            # Check subdomains
            subdomain_count = len(domain.split('.'))
            features['sub_domains'] = 1 if subdomain_count > 4 else 0  # Increased threshold
            if features['sub_domains']:
                phishing_reasons.append("URL has excessive subdomains")
            
            # Check for IP address
            features['having_ip_address'] = 1 if self._is_ip_address(domain) else 0
            if features['having_ip_address']:
                phishing_reasons.append("URL contains IP address (high risk)")
            
            # Check for URL shortening
            features['shortening_service'] = 1 if self._is_shortening_service(url) else 0
            if features['shortening_service']:
                phishing_reasons.append("URL uses URL shortening service (high risk)")
            
            # Check for HTTPS token
            features['https_token'] = 1 if 'https' in domain else 0
            if features['https_token']:
                phishing_reasons.append("Domain contains 'https' (suspicious)")
            
            # Check web traffic (simplified)
            features['web_traffic'] = 0  # This would normally check Alexa rank or similar
            
            # Check domain registration length (simplified)
            features['domain_registration_length'] = 0  # This would normally check WHOIS data
            
            # Check DNS record
            features['dns_record'] = 1 if not self._has_dns_record(domain) else 0
            if features['dns_record']:
                phishing_reasons.append("No DNS record found")
            
            # Check domain age (simplified)
            features['age_of_domain'] = 0  # This would normally check WHOIS data
            
            # Statistical report (simplified)
            features['statistical_report'] = 1 if self._is_suspicious_pattern(url) else 0
            if features['statistical_report']:
                phishing_reasons.append("URL contains suspicious patterns")
            
            # Check for typo-squatting
            typo_check = self.check_typo_squatting(url)
            if typo_check['is_typo_squatting']:
                phishing_reasons.append(f"⚠️ HIGH RISK: This appears to be a typo-squatting attempt")
                phishing_reasons.append(f"This domain is trying to impersonate {typo_check['company_name']}'s official website ({typo_check['original_domain']})")
            
            # Check for suspicious TLD
            if self.check_suspicious_tld(url):
                phishing_reasons.append("WARNING: This website uses a suspicious top-level domain commonly associated with malicious sites")
            
            # Check for suspicious domain patterns
            if self.check_suspicious_domain(url):
                phishing_reasons.append("WARNING: This domain contains suspicious patterns that may indicate phishing")
            
            # If no suspicious features found, return empty reasons list
            if not any(features.values()):
                phishing_reasons = []
            
            return pd.DataFrame([features]), phishing_reasons
            
        except Exception as e:
            print(f"Error in getAttributess: {str(e)}")
            return None, [f"Error processing URL: {str(e)}"]

    def _is_ip_address(self, hostname):
        """Check if the hostname is an IP address"""
        try:
            parts = hostname.split('.')
            return len(parts) == 4 and all(part.isdigit() and 0 <= int(part) <= 255 for part in parts)
        except:
            return False

    def _is_shortening_service(self, url):
        """Check if URL is from a known URL shortening service"""
        shorteners = ['bit.ly', 't.co', 'goo.gl', 'tinyurl.com', 'is.gd', 'cli.gs', 'ow.ly', 'yfrog.com', 'migre.me', 'ff.im', 'tiny.cc', 'url4.eu', 'tr.im', 'twit.ac', 'su.pr', 'twurl.nl', 'snipurl.com', 'short.to', 'BudURL.com', 'ping.fm', 'post.ly', 'Just.as', 'bkite.com', 'snipr.com', 'fic.kr', 'loopt.us', 'doiop.com', 'twitthis.com', 'htxt.it', 'alturl.com', 'tiny.pl', 'urlzen.com', 'migre.me', 'xlinkz.info', 'metamark.net', 'sn.im', 'short.ie', 'kl.am', 'wp.me', 'rubyurl.com', 'om.ly', 'to.ly', 'bit.do', 't.co', 'lnkd.in', 'db.tt', 'qr.ae', 'adf.ly', 'goo.gl', 'bitly.com', 'cur.lv', 'tiny.pl', 'ow.ly', 'bit.ly', 'adcrun.ch', 'ity.im', 'q.gs', 'is.gd', 'po.st', 'bc.vc', 'twitthis.com', 'htxt.it', 'alturl.com', 'tiny.pl', 'urlzen.com', 'migre.me', 'xlinkz.info', 'metamark.net', 'sn.im', 'short.ie', 'kl.am', 'wp.me', 'rubyurl.com', 'om.ly', 'to.ly', 'bit.do', 't.co', 'lnkd.in', 'db.tt', 'qr.ae', 'adf.ly', 'goo.gl', 'bitly.com', 'cur.lv', 'tiny.pl', 'ow.ly', 'bit.ly', 'adcrun.ch', 'ity.im', 'q.gs', 'is.gd', 'po.st', 'bc.vc']
        return any(shortener in url.lower() for shortener in shorteners)

    def _has_dns_record(self, hostname):
        """Check if the hostname has DNS records"""
        try:
            socket.gethostbyname(hostname)
            return True
        except:
            return False

    def _is_suspicious_pattern(self, url):
        """Check for suspicious patterns in the URL"""
        suspicious_patterns = [
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',  # IP address
            r'[^a-zA-Z0-9\-\.]',  # Special characters
            r'(?:login|signin|account|secure|webscr|banking)(?:[^a-zA-Z]|$)',  # Suspicious keywords at word boundaries
            r'\.(tk|ml|ga|cf|gq|xyz)$'  # Suspicious TLDs
        ]
        return any(re.search(pattern, url, re.IGNORECASE) for pattern in suspicious_patterns)

    def check_typo_squatting(self, url):
        """Check for typo-squatting attempts"""
        try:
            domain = urlparse(url).netloc.lower()
            
            # Common typo patterns
            typo_patterns = {
                'google': ['gooogle', 'gogle', 'googel'],
                'microsoft': ['microsft', 'mircosoft', 'microsfot'],
                'apple': ['appel', 'applle', 'appl'],
                'amazon': ['amazn', 'amazoon', 'amaz0n'],
                'facebook': ['facebok', 'faceboook', 'fasebook'],
                'paypal': ['paypall', 'payypal', 'paypaal'],
                'netflix': ['netflx', 'netfliix', 'netfli'],
                'twitter': ['twiter', 'twtter', 'twittr'],
                'instagram': ['instagrm', 'instagrram', 'instagr'],
                'linkedin': ['linkdin', 'linkedinn', 'linkd'],
                'yahoo': ['yaho', 'yahooo', 'yah'],
                'hotmail': ['hotmal', 'hotmaill', 'hotm'],
                'gmail': ['gmal', 'gmaiil', 'gmai'],
                'outlook': ['outlok', 'outlooook', 'outl'],
                'bankofamerica': ['bankofameric', 'bankofamerika', 'bofa'],
                'wellsfargo': ['wellsfarg', 'wellsfargo', 'wells'],
                'chase': ['chas', 'chasee', 'chas'],
                'citibank': ['citibnk', 'citibankk', 'citi'],
                'hsbc': ['hsb', 'hsbcc', 'hs'],
                'barclays': ['barclay', 'barclayss', 'barcl'],
                'santander': ['santandr', 'santanderr', 'sant'],
                'deutschebank': ['deutschebnk', 'deutschebankk', 'deutsche'],
                'rbs': ['rb', 'rbss', 'royalbank'],
                'lloyds': ['lloyd', 'lloydss', 'lloy'],
                'halifax': ['halifx', 'halifaxx', 'halif'],
                'natwest': ['natwst', 'natwestt', 'natw'],
                'tsb': ['ts', 'tsbb', 'trustee'],
                'nationwide': ['nationwid', 'nationwidee', 'nation'],
                'metrobank': ['metrobnk', 'metrobankk', 'metro'],
                'standardchartered': ['standardcharterd', 'standardchartered', 'standard'],
                'hsbc': ['hsb', 'hsbcc', 'hs'],
                'barclays': ['barclay', 'barclayss', 'barcl'],
                'santander': ['santandr', 'santanderr', 'sant'],
                'deutschebank': ['deutschebnk', 'deutschebankk', 'deutsche'],
                'rbs': ['rb', 'rbss', 'royalbank'],
                'lloyds': ['lloyd', 'lloydss', 'lloy'],
                'halifax': ['halifx', 'halifaxx', 'halif'],
                'natwest': ['natwst', 'natwestt', 'natw'],
                'tsb': ['ts', 'tsbb', 'trustee'],
                'nationwide': ['nationwid', 'nationwidee', 'nation'],
                'metrobank': ['metrobnk', 'metrobankk', 'metro'],
                'standardchartered': ['standardcharterd', 'standardchartered', 'standard']
            }
            
            # Check for typo-squatting
            for company, typos in typo_patterns.items():
                if any(typo in domain for typo in typos):
                    return {
                        'is_typo_squatting': True,
                        'company_name': company.capitalize(),
                        'original_domain': f'https://www.{company}.com'
                    }
            
            return {'is_typo_squatting': False}
            
        except Exception as e:
            print(f"Error in check_typo_squatting: {str(e)}")
            return {'is_typo_squatting': False}

    def check_suspicious_tld(self, url):
        """Check if the URL uses a suspicious TLD"""
        try:
            tld = urlparse(url).netloc.split('.')[-1].lower()
            return tld in self.suspicious_tlds
        except:
            return False

    def check_suspicious_domain(self, url):
        """Check if the domain contains suspicious patterns"""
        try:
            domain = urlparse(url).netloc.lower()
            return any(suspicious in domain for suspicious in self.suspicious_domains)
        except:
            return False

    def validate_url(self, url):
        """Validate and clean the URL"""
        try:
            # Add scheme if missing
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
            
            # Parse URL
            parsed = urlparse(url)
            
            # Basic validation
            if not parsed.netloc:
                return False, "Invalid URL: No domain found"
            
            if not parsed.scheme in ['http', 'https']:
                return False, "Invalid URL: Only http and https schemes are allowed"
            
            # Clean URL
            cleaned_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            if parsed.query:
                cleaned_url += f"?{parsed.query}"
            if parsed.fragment:
                cleaned_url += f"#{parsed.fragment}"
            
            return True, cleaned_url
            
        except Exception as e:
            return False, f"Invalid URL: {str(e)}"

    