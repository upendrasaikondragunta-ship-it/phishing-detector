import ipaddress
import socket
import requests

from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin


# ---------------------------------------------------------
# Security Configuration
# ---------------------------------------------------------

REQUEST_TIMEOUT = 5

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36"
)


# ---------------------------------------------------------
# Default Feature Structure
# ---------------------------------------------------------

def get_default_features():
    """
    Returns the default webpage-analysis feature structure.
    """

    return {
        "num_login_forms": 0,
        "has_password_fields": 0,
        "num_iframes": 0,
        "num_external_scripts": 0,
        "has_hidden_fields": 0,
        "forms_submit_different_domain": 0,
        "suspicious_keyword_in_text": 0,
        "error": None
    }


# ---------------------------------------------------------
# SSRF Protection
# ---------------------------------------------------------

def is_private_or_local_host(hostname):
    """
    Determines whether a hostname resolves to a private,
    loopback, link-local, or otherwise unsafe IP address.

    This prevents SSRF attacks against internal services.
    """

    if not hostname:
        return True, "Missing hostname"

    hostname = hostname.lower().strip()

    # Block obvious local hostnames
    blocked_hostnames = {
        "localhost",
        "localhost.localdomain",
        "ip6-localhost",
        "ip6-loopback",
        "0.0.0.0",
        "::1"
    }

    if hostname in blocked_hostnames:
        return True, "Localhost access is not allowed"

    try:
        # If hostname itself is an IP address
        ip = ipaddress.ip_address(hostname)

        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
            or ip.is_unspecified
        ):
            return True, f"Private or reserved IP address: {ip}"

        return False, None

    except ValueError:
        # Hostname is a domain name.
        pass

    # Resolve domain to IP addresses
    try:

        resolved_addresses = socket.getaddrinfo(
            hostname,
            None
        )

        for result in resolved_addresses:

            resolved_ip = result[4][0]

            try:
                ip = ipaddress.ip_address(
                    resolved_ip
                )

                if (
                    ip.is_private
                    or ip.is_loopback
                    or ip.is_link_local
                    or ip.is_reserved
                    or ip.is_multicast
                    or ip.is_unspecified
                ):
                    return (
                        True,
                        f"Domain resolves to unsafe IP: {ip}"
                    )

            except ValueError:
                continue

    except socket.gaierror:

        # DNS failure is not necessarily malicious.
        # Let requests handle the final connection failure.
        pass

    return False, None


# ---------------------------------------------------------
# Domain Utilities
# ---------------------------------------------------------

def normalize_domain(url):
    """
    Extracts a normalized hostname from a URL.
    """

    try:

        hostname = urlparse(url).hostname

        if not hostname:
            return ""

        hostname = hostname.lower()

        if hostname.startswith("www."):
            hostname = hostname[4:]

        return hostname

    except Exception:
        return ""


def is_same_domain(url1, url2):
    """
    Safely determines whether two URLs belong to the same
    domain or subdomain.

    Prevents false matches such as:

        github.com
        evil-github.com
    """

    domain1 = normalize_domain(url1)
    domain2 = normalize_domain(url2)

    if not domain1 or not domain2:
        return False

    if domain1 == domain2:
        return True

    return (
        domain1.endswith("." + domain2)
        or domain2.endswith("." + domain1)
    )


# ---------------------------------------------------------
# URL Validation
# ---------------------------------------------------------

def validate_url(url):
    """
    Validates the URL before making an outbound request.
    """

    if not isinstance(url, str):
        return False, "URL must be a string"

    url = url.strip()

    if not url:
        return False, "URL is empty"

    try:

        parsed = urlparse(url)

    except Exception:
        return False, "Invalid URL"

    # Only allow web protocols
    if parsed.scheme.lower() not in {
        "http",
        "https"
    }:
        return (
            False,
            "Only HTTP and HTTPS URLs are supported"
        )

    if not parsed.hostname:
        return False, "URL does not contain a valid hostname"

    unsafe, reason = is_private_or_local_host(
        parsed.hostname
    )

    if unsafe:
        return False, reason

    return True, None


# ---------------------------------------------------------
# Main Webpage Analyzer
# ---------------------------------------------------------

def analyze_webpage_content(url):
    """
    Analyzes webpage HTML for phishing indicators.

    Security features:

    - SSRF protection
    - Private IP blocking
    - Localhost blocking
    - URL validation
    - Request timeout
    - Safer domain comparison
    - Robust HTML parsing
    """

    features = get_default_features()

    # -----------------------------------------------------
    # Validate URL BEFORE Network Request
    # -----------------------------------------------------

    valid, error_message = validate_url(url)

    if not valid:

        features["error"] = error_message

        return features

    try:

        headers = {
            "User-Agent": USER_AGENT
        }

        # -------------------------------------------------
        # Fetch Webpage
        # -------------------------------------------------

        response = requests.get(
            url,
            headers=headers,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=True
        )

        response.raise_for_status()

        # -------------------------------------------------
        # Validate Final Redirect Destination
        # -------------------------------------------------

        final_url = response.url

        valid_final, final_error = validate_url(
            final_url
        )

        if not valid_final:

            features["error"] = (
                "Redirect blocked for security: "
                + final_error
            )

            return features

        # -------------------------------------------------
        # Parse HTML
        # -------------------------------------------------

        soup = BeautifulSoup(
            response.text,
            "html.parser"
        )

        base_domain = normalize_domain(
            final_url
        )

        # -------------------------------------------------
        # Forms
        # -------------------------------------------------

        forms = soup.find_all("form")

        login_forms = 0
        different_domain_forms = 0

        for form in forms:

            action = form.get(
                "action",
                ""
            ).strip()

            # Empty action means same page
            if not action:
                action_url = final_url

            else:
                action_url = urljoin(
                    final_url,
                    action
                )

            # ---------------------------------------------
            # Cross-Domain Form Detection
            # ---------------------------------------------

            if not is_same_domain(
                final_url,
                action_url
            ):

                different_domain_forms += 1

            # ---------------------------------------------
            # Login Form Detection
            # ---------------------------------------------

            action_lower = action.lower()

            has_password = form.find(
                "input",
                type="password"
            ) is not None

            if (
                "login" in action_lower
                or "signin" in action_lower
                or "sign-in" in action_lower
                or has_password
            ):

                login_forms += 1

        features[
            "num_login_forms"
        ] = login_forms

        features[
            "forms_submit_different_domain"
        ] = different_domain_forms

        # -------------------------------------------------
        # Password Fields
        # -------------------------------------------------

        password_inputs = soup.find_all(
            "input",
            attrs={
                "type": "password"
            }
        )

        features[
            "has_password_fields"
        ] = int(
            len(password_inputs) > 0
        )

        # -------------------------------------------------
        # Iframes
        # -------------------------------------------------

        iframes = soup.find_all(
            "iframe"
        )

        features[
            "num_iframes"
        ] = len(iframes)

        # -------------------------------------------------
        # External Scripts
        # -------------------------------------------------

        scripts = soup.find_all(
            "script",
            src=True
        )

        external_scripts = 0

        for script in scripts:

            src = script.get(
                "src",
                ""
            ).strip()

            if not src:
                continue

            script_url = urljoin(
                final_url,
                src
            )

            if not is_same_domain(
                final_url,
                script_url
            ):

                external_scripts += 1

        features[
            "num_external_scripts"
        ] = external_scripts

        # -------------------------------------------------
        # Hidden Fields
        # -------------------------------------------------

        hidden_inputs = soup.find_all(
            "input",
            attrs={
                "type": "hidden"
            }
        )

        features[
            "has_hidden_fields"
        ] = int(
            len(hidden_inputs) > 0
        )

        # -------------------------------------------------
        # Suspicious Keywords
        # -------------------------------------------------

        text = soup.get_text(
            " ",
            strip=True
        ).lower()

        suspicious_keywords = [
            "login",
            "verify your account",
            "secure your account",
            "update payment",
            "password reset",
            "confirm your identity",
            "verify your identity",
            "account suspended",
            "unusual activity",
            "payment failed"
        ]

        keyword_count = sum(
            1
            for keyword in suspicious_keywords
            if keyword in text
        )

        features[
            "suspicious_keyword_in_text"
        ] = keyword_count

        return features

    except requests.exceptions.Timeout:

        features["error"] = (
            "Website request timed out"
        )

        return features

    except requests.exceptions.ConnectionError:

        features["error"] = (
            "Unable to connect to website"
        )

        return features

    except requests.exceptions.HTTPError as e:

        features["error"] = (
            f"HTTP error: {e}"
        )

        return features

    except Exception as e:

        features["error"] = str(e)

        return features


# ---------------------------------------------------------
# Local Testing
# ---------------------------------------------------------

if __name__ == "__main__":

    print("=" * 60)
    print("WEBPAGE CONTENT ANALYZER SECURITY TEST")
    print("=" * 60)

    print("\n[1] Testing Google")

    print(
        analyze_webpage_content(
            "https://google.com"
        )
    )

    print("\n[2] Testing localhost")

    print(
        analyze_webpage_content(
            "http://localhost:5000"
        )
    )

    print("\n[3] Testing private IP")

    print(
        analyze_webpage_content(
            "http://192.168.1.1"
        )
    )

    print("\n[4] Testing loopback IP")

    print(
        analyze_webpage_content(
            "http://127.0.0.1"
        )
    )

    print("\n" + "=" * 60)
    print("TEST COMPLETE")
    print("=" * 60)