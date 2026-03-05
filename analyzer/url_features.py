import math
import re
import tldextract
from urllib.parse import urlparse

SUSPICIOUS_KEYWORDS = ['login', 'secure', 'account', 'update', 'verify', 'banking', 'paypal', 'apple', 'microsoft', 'google', 'signin', 'auth', 'billing', 'confirm']

def calculate_entropy(text):
    if not text:
        return 0
    entropy = 0
    for x in set(text):
        p_x = float(text.count(x)) / len(text)
        entropy += - p_x * math.log(p_x, 2)
    return entropy

def extract_url_features(url):
    """
    Extracts numerical and boolean features from a given URL to detect phishing.
    """
    if not url.startswith('http'):
        url = 'http://' + url
        
    parsed_url = urlparse(url)
    ext = tldextract.extract(url)
    domain = ext.domain
    subdomain = ext.subdomain
    suffix = ext.suffix
    
    full_domain = f"{subdomain}.{domain}.{suffix}" if subdomain else f"{domain}.{suffix}"
    
    features = {}
    
    # Length features
    features['url_length'] = len(url)
    features['domain_length'] = len(full_domain)
    
    # Entropy (useful for DGA detection)
    features['url_entropy'] = calculate_entropy(url)
    features['domain_entropy'] = calculate_entropy(full_domain)
    
    # Special character counts
    features['num_dots'] = url.count('.')
    features['num_hyphens'] = url.count('-')
    features['num_at_symbols'] = url.count('@')
    features['num_queries'] = url.count('?')
    features['num_ampersands'] = url.count('&')
    features['num_equals'] = url.count('=')
    
    # Subdomain count
    features['num_subdomains'] = len(subdomain.split('.')) if subdomain else 0
    
    # Has IP in domain
    # Regex to check for IPv4
    ip_pattern = re.compile(r'(([01]?\d\d?|2[0-4]\d|25[0-5])\.){3}([01]?\d\d?|2[0-4]\d|25[0-5])')
    features['has_ip_in_domain'] = 1 if ip_pattern.search(full_domain) else 0
    
    # HTTP vs HTTPS
    features['is_https'] = 1 if parsed_url.scheme == 'https' else 0
    
    # Suspicious keywords presence
    suspicious_count = 0
    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in url.lower():
            suspicious_count += 1
    features['suspicious_keyword_count'] = suspicious_count
    
    return features

if __name__ == '__main__':
    # Test
    print(extract_url_features("https://secure.paypal.com.account-update.info/login.php"))
