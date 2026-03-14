import urllib.parse
import re

def extract_features(url):
    """
    Extracts numerical features from a given URL for machine learning.
    Now returns a structured dictionary (Improvement 3).
    
    Args:
        url (str): The URL to extract features from.
        
    Returns:
        dict: A dictionary of extracted numerical features.
    """
    # Safe fallback if input is bad
    if not isinstance(url, str):
        url = ""
        
    features = {}
    
    # Feature 1: URL length
    features['url_length'] = len(url)
    
    # Feature 2: Number of dots
    features['num_dots'] = url.count('.')
    
    # Feature 3: Number of hyphens
    features['num_hyphens'] = url.count('-')
    
    # Feature 4: Presence of '@' symbol (1 if present, 0 if not)
    features['has_at_symbol'] = 1 if '@' in url else 0
    
    # Feature 5: Presence of IP address in URL
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    features['has_ip_address'] = 1 if re.search(ip_pattern, url) else 0
    
    # Feature 6: HTTPS usage
    parsed_url = urllib.parse.urlparse(url)
    features['uses_https'] = 1 if parsed_url.scheme == 'https' else 0
    
    # Feature 7: Suspicious keywords in URL
    suspicious_keywords = ['login', 'verify', 'secure', 'account', 'update', 'password', 'auth', 'billing', 'banking']
    features['suspicious_keyword_count'] = sum(1 for word in suspicious_keywords if word in url.lower())
    
    return features

def get_feature_names():
    """Returns the names of the extracted features in correct order."""
    return [
        'url_length',
        'num_dots',
        'num_hyphens',
        'has_at_symbol',
        'has_ip_address',
        'uses_https',
        'suspicious_keyword_count'
    ]

# Simple test block
if __name__ == "__main__":
    test_urls = [
        "https://google.com",
        "http://amaz0n-login-security.xyz"
    ]
    for test_url in test_urls:
        print(f"URL: {test_url}")
        print(f"Features: {extract_features(test_url)}")
        print("-" * 30)
