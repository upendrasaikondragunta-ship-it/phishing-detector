import csv
import random

def generate_dataset(filename):
    """
    Generates a synthetic dataset of 600 URLs (300 safe, 300 phishing)
    with realistic distributions to avoid 100% artificial accuracy.
    """
    safe_domains = [
        "google.com", "github.com", "wikipedia.org", "stackoverflow.com", 
        "youtube.com", "amazon.com", "netflix.com", "apple.com", 
        "microsoft.com", "developer.mozilla.org", "yahoo.com", "reddit.com",
        "linkedin.com", "nytimes.com", "bbc.co.uk", "cnn.com", "twitch.tv"
    ]
    
    phishing_keywords = ["login", "verify", "secure", "account", "update", "password", "auth", "banking", "billing"]
    safe_paths = ["/about", "/contact", "/home", "/user/settings", "/docs", "/api/v1", "/help", ""]
    
    records = []
    
    # Generate 300 Safe URLs
    for _ in range(300):
        domain = random.choice(safe_domains)
        protocol = "https://" if random.random() < 0.95 else "http://" # 95% use https
        path = random.choice(safe_paths)
        
        # occasionally add subdomains
        if random.random() < 0.3:
            domain = f"www.{domain}"
        
        url = f"{protocol}{domain}{path}"
        
        records.append([url, 0]) # label 0 for safe
        
    # Generate 300 Phishing URLs
    for _ in range(300):
        # 30% chance to use raw IP
        if random.random() < 0.3:
            ip = f"{random.randint(11,254)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}"
            domain = ip
        else:
            # Fake domains mimicking real ones with hyphens or numbers
            base = random.choice(["amazon", "paypal", "apple", "netflix", "microsoft", "chase", "bofa"])
            suffix = random.choice(["-security.com", "-login.net", "0.xyz", "-verify.info", "-update.org"])
            domain = f"{base}{suffix}"
            
        protocol = "http://" if random.random() < 0.70 else "https://" # 70% use http
        
        # Path with lots of keywords
        path = f"/{random.choice(phishing_keywords)}/{random.choice(phishing_keywords)}.php?id={random.randint(1000,9999)}"
        
        # 10% chance to use @ symbol trick
        if random.random() < 0.1:
            url = f"{protocol}www.google.com@{domain}{path}"
        else:
            url = f"{protocol}{domain}{path}"
            
        records.append([url, 1]) # label 1 for phishing
        
    # Shuffle the dataset
    random.shuffle(records)
    
    # Save to CSV
    with open(filename, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(["url", "label"])
        writer.writerows(records)
        
    print(f"Dataset generated successfully at {filename} with 600 records.")

if __name__ == "__main__":
    import os
    # Assuming script is run from backend folder
    output_path = os.path.join("..", "dataset", "phishing_dataset.csv")
    generate_dataset(output_path)
