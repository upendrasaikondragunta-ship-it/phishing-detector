import whois
from datetime import datetime, timezone
from urllib.parse import urlparse


def check_domain_age(url):
    """
    Check domain age using WHOIS.

    WHOIS failures are treated as UNKNOWN rather than automatically
    marking the domain as suspicious.
    """

    try:
        parsed = urlparse(url)

        domain = parsed.hostname

        if not domain:
            domain = url.split("/")[0]

        domain = domain.lower().strip()

        if domain.startswith("www."):
            domain = domain[4:]

        # Reject obvious IP addresses from WHOIS lookup
        if domain.replace(".", "").isdigit():
            return {
                "age_days": -1,
                "is_suspicious": False,
                "reason": None,
                "status": "unknown",
                "error": "IP address detected; WHOIS domain-age check skipped."
            }

        domain_info = whois.whois(domain)
        creation_date = domain_info.creation_date

        # WHOIS record exists but creation date is unavailable
        if not creation_date:
            return {
                "age_days": -1,
                "is_suspicious": False,
                "reason": None,
                "status": "unknown",
                "error": "Creation date not available in WHOIS record."
            }

        # Some registries return multiple dates
        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        # Normalize timezone
        if creation_date.tzinfo is None:
            now = datetime.now()
        else:
            now = datetime.now(timezone.utc)

        age_days = max(0, (now - creation_date).days)

        # Newly registered domains are a supporting phishing signal
        if age_days < 30:
            return {
                "age_days": age_days,
                "is_suspicious": True,
                "reason": (
                    f"Domain is newly registered "
                    f"(Age: {age_days} days)."
                ),
                "status": "known",
                "error": None
            }

        return {
            "age_days": age_days,
            "is_suspicious": False,
            "reason": None,
            "status": "known",
            "error": None
        }

    except Exception as e:
        # WHOIS failure = UNKNOWN, NOT phishing
        return {
            "age_days": -1,
            "is_suspicious": False,
            "reason": None,
            "status": "unknown",
            "error": str(e)
        }


if __name__ == "__main__":
    print("Testing Google:")
    print(check_domain_age("https://google.com"))

    print("\nTesting suspicious-looking domain:")
    print(check_domain_age("http://amaz0n-login-security.xyz"))