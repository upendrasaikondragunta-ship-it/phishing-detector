import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse

def analyze_webpage_content(url):
    """
    Analyzes the HTML content of a webpage for phishing indicators.
    (Improvement 5 - Cross domain form detection and robust parsing)
    
    Args:
        url (str): The URL to analyze.
        
    Returns:
        dict: A dictionary of extracted features and error status.
    """
    
    # Initialize default features in case of failure
    features = {
        'num_login_forms': 0,
        'has_password_fields': 0,
        'num_iframes': 0,
        'num_external_scripts': 0,
        'has_hidden_fields': 0,
        'forms_submit_different_domain': 0,
        'suspicious_keyword_in_text': 0,
        'error': None
    }
    
    try:
        # Avoid hanging requests
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'}
        response = requests.get(url, headers=headers, timeout=5)
        response.raise_for_status() # Check for HTTP errors
        
        soup = BeautifulSoup(response.text, 'html.parser')
        
        base_domain = urlparse(url).netloc.replace('www.', '')
        
        # Analyze Forms
        forms = soup.find_all('form')
        login_forms = 0
        different_domain_forms = 0
        
        for form in forms:
            action = form.get('action', '').lower()
            
            # Check for cross-domain form submission
            if action.startswith('http') and base_domain not in action:
                different_domain_forms += 1
                
            # Check for login forms
            if 'login' in action:
                login_forms += 1
            # If a form has a password input, it's a login form
            elif form.find('input', type='password'):
                login_forms += 1
                
        features['num_login_forms'] = login_forms
        features['forms_submit_different_domain'] = different_domain_forms
        
        # 2. Presence of password input fields anywhere on the page
        password_inputs = soup.find_all('input', type='password')
        features['has_password_fields'] = 1 if len(password_inputs) > 0 else 0
        
        # 3. Number of iframe elements (often used in phishing to load external fake content)
        iframes = soup.find_all('iframe')
        features['num_iframes'] = len(iframes)
        
        # 4. Number of external scripts (loading scripts from other domains)
        scripts = soup.find_all('script', src=True)
        external_scripts = sum(1 for script in scripts if script.get('src', '').startswith('http') and base_domain not in script.get('src', ''))
        features['num_external_scripts'] = external_scripts
        
        # 5. Hidden input fields (used in phishing forms to pass standard data)
        hidden_inputs = soup.find_all('input', type='hidden')
        features['has_hidden_fields'] = 1 if len(hidden_inputs) > 0 else 0
        
        # 6. Suspicious keywords in page text
        text = soup.get_text().lower()
        suspicious_keywords = ['login', 'verify your account', 'secure your account', 'update payment', 'password reset']
        keyword_count = sum(1 for keyword in suspicious_keywords if keyword in text)
        features['suspicious_keyword_in_text'] = keyword_count
        
        return features

    except Exception as e:
        # If the page cannot be fetched (site down, blocked, etc)
        # We flag it as an error but keep features at 0
        features['error'] = str(e)
        return features

if __name__ == "__main__":
    # Test cases
    print("Testing Google:")
    print(analyze_webpage_content("https://google.com"))
