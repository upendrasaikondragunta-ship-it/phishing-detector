import whois
from datetime import datetime, timezone
from urllib.parse import urlparse

def check_domain_age(url):
    """
    Checks the age of the domain using WHOIS lookup.
    (Improvement 4 - Handle failures gracefully & structured reasons)
    
    Args:
        url (str): The URL to analyze.
        
    Returns:
        dict: A dictionary containing domain age information, risk status, and explainer.
    """
    try:
        # Extract just the domain part from the URL
        domain = urlparse(url).netloc
        
        # In case the URL is just 'example.com' without scheme
        if not domain:
            domain = url
            
        # Remove any 'www.' prefix
        domain = domain.replace('www.', '')
        
        # Perform WHOIS lookup
        # Sometimes whois throws uncatchable errors inside the library if connection is blocked
        # so this is risky but we try our best.
        domain_info = whois.whois(domain)
        
        # Get creation date
        creation_date = domain_info.creation_date
        
        if not creation_date:
            return {
                "age_days": -1,
                "is_suspicious": True,
                "reason": "Domain WHOIS information is hidden or unavailable (Common in phishing)",
                "error": "Creation date not found in WHOIS record"
            }
            
        # WHOIS sometimes returns a list of dates (creation and update)
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
            
        # Calculate domain age in days
        now = datetime.now()
        
        # Handle timezone-aware vs naive datetimes
        if creation_date.tzinfo is not None:
             now = datetime.now(timezone.utc)
             
        age = now - creation_date
        age_days = age.days
        
        # Determine if it's suspicious (less than 30 days old)
        is_suspicious = age_days < 30
        
        reason = None
        if is_suspicious:
            reason = f"Domain is newly registered (Age: {age_days} days). Phishing domains are often new."
            
        return {
            "age_days": age_days,
            "is_suspicious": is_suspicious,
            "reason": reason,
            "error": None
        }
        
    except Exception as e:
        # If WHOIS lookup fails entirely, treat as potentially suspicious
        # Phishers often use domains that don't have standard WHOIS records
        return {
            "age_days": -1,
            "is_suspicious": True,
            "reason": "Failed to look up domain age. The registry might be blocking connections or the domain is fake.",
            "error": str(e)
        }

if __name__ == "__main__":
    # Test cases
    print("Testing Google:")
    print(check_domain_age("https://google.com"))
    
    print("\nTesting a likely non-existent domain:")
    print(check_domain_age("http://thisdomainshouldnotexist123456789.xyz"))
