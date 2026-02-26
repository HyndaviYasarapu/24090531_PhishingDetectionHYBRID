"""
Feature Extraction Module for Phishing Detection
Extracts URL-based, domain-based, and content-based features
"""

import re
import math
from urllib.parse import urlparse, parse_qs
from collections import Counter
import tldextract
import requests
from bs4 import BeautifulSoup
import dns.resolver
import whois
from datetime import datetime
import warnings
warnings.filterwarnings('ignore')

from config import (
    TIMEOUT_SECONDS, USER_AGENT, SUSPICIOUS_KEYWORDS,
    SUSPICIOUS_TLDS, SHORTENING_SERVICES
)


class FeatureExtractor:
    """Extract features from URLs for phishing detection"""
    
    def __init__(self):
        self.timeout = TIMEOUT_SECONDS
        self.headers = {'User-Agent': USER_AGENT}
    
    def extract_all_features(self, url):
        """Extract all features from a URL"""
        features = {}
        
        # URL-based features (fast, no network required)
        features.update(self.extract_url_features(url))
        
        # Lexical features
        features.update(self.extract_lexical_features(url))
        
        # Domain-based features (may require network)
        features.update(self.extract_domain_features(url))
        
        # Content-based features (requires fetching page)
        features.update(self.extract_content_features(url))
        
        return features
    
    def extract_url_features(self, url):
        """Extract features from URL structure"""
        features = {}
        
        try:
            parsed = urlparse(url)
            ext = tldextract.extract(url)
            
            # Basic URL characteristics
            features['url_length'] = len(url)
            
            # Check for IP address in URL
            ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
            features['has_ip'] = 1 if re.search(ip_pattern, parsed.netloc) else 0
            
            # Subdomain count
            subdomain = ext.subdomain
            features['subdomain_count'] = len(subdomain.split('.')) if subdomain else 0
            
            # Special character counts
            features['dot_count'] = url.count('.')
            features['hyphen_count'] = url.count('-')
            features['at_symbol'] = 1 if '@' in url else 0
            
            # Double slash redirecting (after protocol)
            features['double_slash_redirecting'] = 1 if url.count('//') > 1 else 0
            
            # Prefix or suffix with hyphen in domain
            features['prefix_suffix'] = 1 if '-' in ext.domain else 0
            
            # URL shortening service
            features['shortening_service'] = 1 if any(s in url.lower() for s in SHORTENING_SERVICES) else 0
            
            # Suspicious TLD
            tld = ext.suffix
            features['suspicious_tld'] = 1 if any(tld.endswith(s) for s in SUSPICIOUS_TLDS) else 0
            
        except Exception as e:
            print(f"Error extracting URL features: {e}")
            # Return default values
            features = {
                'url_length': 0, 'has_ip': 0, 'subdomain_count': 0,
                'dot_count': 0, 'hyphen_count': 0, 'at_symbol': 0,
                'double_slash_redirecting': 0, 'prefix_suffix': 0,
                'shortening_service': 0, 'suspicious_tld': 0
            }
        
        return features
    
    def extract_lexical_features(self, url):
        """Extract lexical features from URL"""
        features = {}
        
        try:
            # Count digits, letters, special characters
            features['digit_count'] = sum(c.isdigit() for c in url)
            features['letter_count'] = sum(c.isalpha() for c in url)
            features['special_char_count'] = sum(not c.isalnum() for c in url)
            
            # Calculate Shannon entropy
            features['entropy'] = self._calculate_entropy(url)
            
        except Exception as e:
            print(f"Error extracting lexical features: {e}")
            features = {
                'digit_count': 0, 'letter_count': 0,
                'special_char_count': 0, 'entropy': 0
            }
        
        return features
    
    def extract_domain_features(self, url):
        """Extract domain-based features"""
        features = {}
        
        try:
            parsed = urlparse(url)
            ext = tldextract.extract(url)
            domain = f"{ext.domain}.{ext.suffix}"
            
            # HTTPS
            features['has_https'] = 1 if parsed.scheme == 'https' else 0
            
            # Domain age (requires WHOIS lookup)
            features['domain_age_days'] = self._get_domain_age(domain)
            
            # DNS record check
            features['has_dns_record'] = self._has_dns_record(domain)
            
        except Exception as e:
            print(f"Error extracting domain features: {e}")
            features = {
                'has_https': 0,
                'domain_age_days': -1,
                'has_dns_record': 0
            }
        
        return features
    
    def extract_content_features(self, url):
        """Extract features from webpage content"""
        features = {
            'num_external_links': 0,
            'num_internal_links': 0,
            'has_form': 0,
            'num_scripts': 0,
            'num_iframes': 0,
            'has_login_form': 0,
            'suspicious_keywords_count': 0
        }
        
        try:
            # Fetch webpage content
            response = requests.get(url, headers=self.headers, timeout=self.timeout, verify=False)
            
            if response.status_code == 200:
                soup = BeautifulSoup(response.content, 'html.parser')
                parsed_url = urlparse(url)
                domain = parsed_url.netloc
                
                # Count links
                links = soup.find_all('a', href=True)
                for link in links:
                    href = link['href']
                    if href.startswith('http'):
                        if domain in href:
                            features['num_internal_links'] += 1
                        else:
                            features['num_external_links'] += 1
                
                # Check for forms
                forms = soup.find_all('form')
                features['has_form'] = 1 if forms else 0
                
                # Check for login forms (forms with password input)
                for form in forms:
                    if form.find('input', {'type': 'password'}):
                        features['has_login_form'] = 1
                        break
                
                # Count scripts and iframes
                features['num_scripts'] = len(soup.find_all('script'))
                features['num_iframes'] = len(soup.find_all('iframe'))
                
                # Count suspicious keywords in page text
                text = soup.get_text().lower()
                features['suspicious_keywords_count'] = sum(
                    text.count(keyword) for keyword in SUSPICIOUS_KEYWORDS
                )
                
        except Exception as e:
            print(f"Error extracting content features from {url}: {e}")
        
        return features
    
    def _calculate_entropy(self, string):
        """Calculate Shannon entropy of a string"""
        if not string:
            return 0
        
        # Calculate character frequency
        char_freq = Counter(string)
        string_len = len(string)
        
        # Calculate entropy
        entropy = 0
        for freq in char_freq.values():
            probability = freq / string_len
            entropy -= probability * math.log2(probability)
        
        return entropy
    
    def _get_domain_age(self, domain):
        """Get domain age in days using WHOIS"""
        try:
            domain_info = whois.whois(domain)
            if domain_info.creation_date:
                creation_date = domain_info.creation_date
                if isinstance(creation_date, list):
                    creation_date = creation_date[0]
                
                age = (datetime.now() - creation_date).days
                return age if age >= 0 else -1
        except Exception:
            pass
        
        return -1  # Unknown age
    
    def _has_dns_record(self, domain):
        """Check if domain has DNS record"""
        try:
            dns.resolver.resolve(domain, 'A')
            return 1
        except Exception:
            return 0


def extract_features_from_dataset(df, url_column='url'):
    """
    Extract features from a dataframe containing URLs
    
    Args:
        df: pandas DataFrame with URLs
        url_column: name of column containing URLs
    
    Returns:
        DataFrame with extracted features
    """
    import pandas as pd
    from tqdm import tqdm
    
    extractor = FeatureExtractor()
    features_list = []
    
    print("Extracting features from URLs...")
    for idx, row in tqdm(df.iterrows(), total=len(df)):
        url = row[url_column]
        features = extractor.extract_all_features(url)
        
        # Add label if exists
        if 'label' in df.columns:
            features['label'] = row['label']
        
        features_list.append(features)
    
    return pd.DataFrame(features_list)


if __name__ == "__main__":
    # Test feature extraction
    test_urls = [
        "https://www.google.com",
        "http://secure-paypal-verify.com/login.php?user=12345",
        "http://192.168.1.1/admin"
    ]
    
    extractor = FeatureExtractor()
    
    for url in test_urls:
        print(f"\nURL: {url}")
        features = extractor.extract_all_features(url)
        for key, value in features.items():
            print(f"  {key}: {value}")
