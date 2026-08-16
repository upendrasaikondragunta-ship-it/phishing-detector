import math
import re
import urllib.parse


# =========================================================
# SECURITY VOCABULARY
# =========================================================

SUSPICIOUS_KEYWORDS = [
    "login",
    "verify",
    "secure",
    "account",
    "update",
    "password",
    "auth",
    "billing",
    "banking",
    "signin",
    "confirm",
    "wallet",
    "payment",
    "recover",
    "unlock",
]


SUSPICIOUS_TLDS = {
    "xyz",
    "top",
    "click",
    "zip",
    "review",
    "country",
    "work",
    "gq",
    "tk",
    "ml",
    "cf",
}


# =========================================================
# BRANDS
# =========================================================

KNOWN_BRANDS = {
    "paypal",
    "amazon",
    "microsoft",
    "apple",
    "netflix",
    "google",
    "facebook",
    "instagram",
    "linkedin",
}


# =========================================================
# ENTROPY
# =========================================================

def calculate_entropy(value):
    """Calculate Shannon entropy for a string."""

    if not value:
        return 0.0

    length = len(value)
    frequencies = {}

    for char in value:
        frequencies[char] = frequencies.get(char, 0) + 1

    entropy = 0.0

    for count in frequencies.values():

        probability = count / length

        entropy -= (
            probability *
            math.log2(probability)
        )

    return entropy


# =========================================================
# BRAND / IMPERSONATION HELPERS
# =========================================================

def normalize_brand_text(value):
    """
    Normalizes common character substitutions used in
    phishing URLs.

    Examples:

        amaz0n  -> amazon
        paypa1  -> paypal
        g00gle  -> google
        micr0soft -> microsoft
    """

    translation_table = str.maketrans({
        "0": "o",
        "1": "l",
        "3": "e",
        "4": "a",
        "5": "s",
        "7": "t",
    })

    return value.lower().translate(
        translation_table
    )


def detect_brand_impersonation(
    hostname,
    path
):
    """
    Detects suspicious brand impersonation.

    A legitimate domain such as:

        microsoft.com

    should NOT be flagged.

    But examples such as:

        microsoft-account-security-login.xyz
        micr0soft-login.xyz
        paypal-verification.xyz
        g00gle-security.xyz

    should be flagged.
    """

    hostname_lower = hostname.lower()
    path_lower = path.lower()

    normalized_host = normalize_brand_text(
        hostname_lower
    )

    normalized_path = normalize_brand_text(
        path_lower
    )

    # -----------------------------------------------------
    # Suspicious words commonly paired with brands
    # -----------------------------------------------------

    phishing_context = [
        "login",
        "signin",
        "verify",
        "verification",
        "secure",
        "security",
        "account",
        "update",
        "password",
        "billing",
        "payment",
        "recover",
        "unlock",
        "confirm",
    ]

    suspicious_context = any(
        word in hostname_lower
        or word in path_lower
        for word in phishing_context
    )

    # -----------------------------------------------------
    # Check known brands
    # -----------------------------------------------------

    for brand in KNOWN_BRANDS:

        # Direct brand
        brand_present = (
            brand in hostname_lower
            or brand in path_lower
        )

        # Obfuscated brand
        normalized_brand_present = (
            brand in normalized_host
            or brand in normalized_path
        )

        if not (
            brand_present
            or normalized_brand_present
        ):
            continue

        # -------------------------------------------------
        # Legitimate exact domain
        # -------------------------------------------------

        legitimate_domains = {
            f"{brand}.com",
            f"www.{brand}.com",
        }

        if hostname_lower in legitimate_domains:

            continue

        # -------------------------------------------------
        # Brand + suspicious context
        # -------------------------------------------------

        if suspicious_context:

            return 1

        # -------------------------------------------------
        # Brand appears in a non-standard hostname
        # -------------------------------------------------

        if (
            brand in hostname_lower
            and hostname_lower != f"{brand}.com"
        ):

            return 1

        # -------------------------------------------------
        # Obfuscated brand
        # -------------------------------------------------

        if normalized_brand_present:

            return 1

    return 0


# =========================================================
# NUMERIC DOMAIN ANALYSIS
# =========================================================

def detect_suspicious_numeric_hostname(hostname):
    """
    Detects domains that contain an unusually high amount
    of numeric characters.

    Example:

        123456789-login-security.xyz

    This is different from simply detecting an IP address.
    """

    if not hostname:
        return 0

    hostname_without_tld = hostname

    # Remove final TLD
    parts = hostname.split(".")

    if len(parts) >= 2:

        hostname_without_tld = ".".join(
            parts[:-1]
        )

    alphanumeric = re.sub(
        r"[^a-zA-Z0-9]",
        "",
        hostname_without_tld
    )

    if not alphanumeric:
        return 0

    digit_count = sum(
        char.isdigit()
        for char in alphanumeric
    )

    digit_ratio = (
        digit_count /
        len(alphanumeric)
    )

    # Strong numeric dominance
    if (
        digit_count >= 6
        and digit_ratio >= 0.45
    ):
        return 1

    return 0


# =========================================================
# MAIN FEATURE EXTRACTION
# =========================================================

def extract_features(url):
    """
    Extract lexical and security-oriented features.

    IMPORTANT:
    This function intentionally preserves the original
    27-feature schema so the training and prediction
    pipeline remain compatible.
    """

    if not isinstance(
        url,
        str
    ):
        url = ""

    url = url.strip()

    parsed = urllib.parse.urlparse(
        url
    )

    hostname = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""

    # -----------------------------------------------------
    # Hostname normalization
    # -----------------------------------------------------

    normalized_hostname = hostname.lower()

    if normalized_hostname.startswith(
        "www."
    ):

        normalized_hostname = (
            normalized_hostname[4:]
        )

    labels = [
        part
        for part in normalized_hostname.split(".")
        if part
    ]

    tld = (
        labels[-1]
        if len(labels) >= 2
        else ""
    )

    # =====================================================
    # BASIC URL FEATURES
    # =====================================================

    suspicious_keyword_count = sum(
        1
        for keyword in SUSPICIOUS_KEYWORDS
        if keyword in url.lower()
    )

    digit_count = sum(
        char.isdigit()
        for char in url
    )

    special_character_count = sum(
        char in "@?#%=&;_~"
        for char in url
    )

    # =====================================================
    # IP ADDRESS
    # =====================================================

    ip_pattern = (
        r"^(?:\d{1,3}\.){3}\d{1,3}$"
    )

    has_ip_address = (
        1
        if re.match(
            ip_pattern,
            hostname
        )
        else 0
    )

    # =====================================================
    # OTHER URL SECURITY FEATURES
    # =====================================================

    has_punycode = (
        1
        if "xn--" in normalized_hostname
        else 0
    )

    has_port = (
        1
        if parsed.port is not None
        else 0
    )

    has_double_slash_path = (
        1
        if "//" in path
        else 0
    )

    encoded_character_count = len(
        re.findall(
            r"%[0-9A-Fa-f]{2}",
            url
        )
    )

    subdomain_count = max(
        len(labels) - 2,
        0
    )

    # =====================================================
    # URL SHORTENERS
    # =====================================================

    shortener_domains = {
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl",
        "is.gd",
        "ow.ly",
        "buff.ly",
        "cutt.ly",
    }

    is_url_shortener = (
        1
        if normalized_hostname
        in shortener_domains
        else 0
    )

    # =====================================================
    # TLD
    # =====================================================

    suspicious_tld = (
        1
        if tld in SUSPICIOUS_TLDS
        else 0
    )

    # =====================================================
    # @ SYMBOL
    # =====================================================

    has_at_symbol = (
        1
        if "@" in url
        else 0
    )

    # =====================================================
    # HTTPS
    # =====================================================

    uses_https = (
        1
        if parsed.scheme.lower() == "https"
        else 0
    )

    # =====================================================
    # BRAND COUNT
    # =====================================================

    brand_keyword_count = sum(
        1
        for brand in KNOWN_BRANDS
        if (
            brand in normalized_hostname
            or brand in path.lower()
        )
    )

    # =====================================================
    # ADVANCED BRAND IMPERSONATION
    # =====================================================

    brand_impersonation = detect_brand_impersonation(
        normalized_hostname,
        path
    )

    # Numeric-heavy suspicious hostname is also treated
    # as a high-risk impersonation/obfuscation signal.

    numeric_hostname = (
        detect_suspicious_numeric_hostname(
            normalized_hostname
        )
    )

    has_brand_impersonation = max(
        brand_impersonation,
        numeric_hostname
    )

    # =====================================================
    # ENTROPY
    # =====================================================

    url_entropy = calculate_entropy(
        url
    )

    hostname_entropy = calculate_entropy(
        hostname
    )

    path_entropy = calculate_entropy(
        path
    )

    # =====================================================
    # FINAL 27 FEATURES
    # =====================================================

    features = {

        "url_length":
            len(url),

        "hostname_length":
            len(hostname),

        "path_length":
            len(path),

        "query_length":
            len(query),

        "num_dots":
            url.count("."),

        "num_hyphens":
            url.count("-"),

        "num_underscores":
            url.count("_"),

        "num_slashes":
            url.count("/"),

        "digit_count":
            digit_count,

        "special_character_count":
            special_character_count,

        "has_at_symbol":
            has_at_symbol,

        "has_ip_address":
            has_ip_address,

        "uses_https":
            uses_https,

        "suspicious_keyword_count":
            suspicious_keyword_count,

        "subdomain_count":
            subdomain_count,

        "has_punycode":
            has_punycode,

        "has_port":
            has_port,

        "has_double_slash_path":
            has_double_slash_path,

        "encoded_character_count":
            encoded_character_count,

        "is_url_shortener":
            is_url_shortener,

        "suspicious_tld":
            suspicious_tld,

        "brand_keyword_count":
            brand_keyword_count,

        "has_brand_impersonation":
            has_brand_impersonation,

        "url_entropy":
            url_entropy,

        "hostname_entropy":
            hostname_entropy,

        "path_entropy":
            path_entropy,

        "query_parameter_count":
            (
                len(
                    urllib.parse.parse_qs(
                        query
                    )
                )
                if query
                else 0
            ),
    }

    return features


# =========================================================
# FEATURE ORDER
# =========================================================

def get_feature_names():
    """
    Return feature names in the exact training/
    prediction order.

    IMPORTANT:
    Keep this order unchanged.
    """

    return [

        "url_length",

        "hostname_length",

        "path_length",

        "query_length",

        "num_dots",

        "num_hyphens",

        "num_underscores",

        "num_slashes",

        "digit_count",

        "special_character_count",

        "has_at_symbol",

        "has_ip_address",

        "uses_https",

        "suspicious_keyword_count",

        "subdomain_count",

        "has_punycode",

        "has_port",

        "has_double_slash_path",

        "encoded_character_count",

        "is_url_shortener",

        "suspicious_tld",

        "brand_keyword_count",

        "has_brand_impersonation",

        "url_entropy",

        "hostname_entropy",

        "path_entropy",

        "query_parameter_count",
    ]


# =========================================================
# LOCAL TEST
# =========================================================

if __name__ == "__main__":

    test_urls = [

        "https://google.com",

        "https://microsoft.com",

        "https://microsoft-account-security-login.xyz",

        "http://amaz0n-login-security.xyz",

        "https://123456789-login-security.xyz",

        "http://192.168.1.10/login",
    ]

    print("=" * 70)
    print("FEATURE EXTRACTOR SECURITY TEST")
    print("=" * 70)

    for test_url in test_urls:

        print(
            f"\nURL: {test_url}"
        )

        features = extract_features(
            test_url
        )

        print(
            "Brand impersonation:",
            features[
                "has_brand_impersonation"
            ]
        )

        print(
            "Brand count:",
            features[
                "brand_keyword_count"
            ]
        )

        print(
            "Suspicious keywords:",
            features[
                "suspicious_keyword_count"
            ]
        )

        print(
            "Suspicious TLD:",
            features[
                "suspicious_tld"
            ]
        )

        print(
            "Digit count:",
            features[
                "digit_count"
            ]
        )