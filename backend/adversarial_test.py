import requests
from tabulate import tabulate


API_URL = "http://127.0.0.1:5000/predict"


# =========================================================
# TEST CASES
# =========================================================

TEST_CASES = [

    # -----------------------------------------------------
    # SAFE DOMAINS
    # -----------------------------------------------------

    {
        "name": "GitHub",
        "url": "https://github.com",
        "expected": "SAFE"
    },

    {
        "name": "Google",
        "url": "https://google.com",
        "expected": "SAFE"
    },

    {
        "name": "Microsoft",
        "url": "https://microsoft.com",
        "expected": "SAFE"
    },

    {
        "name": "Python",
        "url": "https://python.org",
        "expected": "SAFE"
    },

    # -----------------------------------------------------
    # BRAND IMPERSONATION
    # -----------------------------------------------------

    {
        "name": "Amazon Lookalike",
        "url": "http://amaz0n-login-security.xyz",
        "expected": "PHISHING"
    },

    {
        "name": "PayPal Fake Login",
        "url": "https://paypal-verification-security.xyz/login",
        "expected": "PHISHING"
    },

    {
        "name": "Google Fake Verification",
        "url": "https://google-account-verify-security.xyz/login",
        "expected": "PHISHING"
    },

    {
        "name": "Microsoft Fake Login",
        "url": "https://microsoft-account-security-login.xyz",
        "expected": "PHISHING"
    },

    # -----------------------------------------------------
    # SUSPICIOUS URL STRUCTURES
    # -----------------------------------------------------

    {
        "name": "IP Address",
        "url": "http://192.168.1.100/login",

        # IMPORTANT:
        # Backend security layer blocks private IPs
        # with HTTP 400 instead of analyzing them.
        "expected": "BLOCKED"
    },

    {
        "name": "Long Suspicious URL",
        "url": (
            "https://secure-login-account-verification.example.com/"
            "verify/user/account/password/reset/security/login"
        ),
        "expected": "PHISHING"
    },

    {
        "name": "Suspicious Query",
        "url": (
            "https://example.com/login?"
            "verify=true&password=reset&account=secure"
        ),
        "expected": "SUSPICIOUS"
    },

    # -----------------------------------------------------
    # URL OBFUSCATION
    # -----------------------------------------------------

    {
        "name": "At Symbol Trick",
        "url": "https://google.com@evil-login-security.xyz",
        "expected": "PHISHING"
    },

    {
        "name": "Many Subdomains",
        "url": (
            "https://login.secure.verify.account.security."
            "evil-login-example.xyz"
        ),
        "expected": "PHISHING"
    },

    {
        "name": "Numeric Domain",
        "url": "https://123456789-login-security.xyz",
        "expected": "PHISHING"
    },
]


# =========================================================
# RUN SINGLE TEST
# =========================================================

def test_url(test_case):

    try:

        response = requests.post(
            API_URL,
            json={
                "url": test_case["url"],
                "demo_mode": False
            },
            timeout=30
        )

        # -------------------------------------------------
        # SECURITY BLOCK
        # -------------------------------------------------

        if response.status_code != 200:

            actual = f"HTTP {response.status_code}"

            # A private/reserved IP should be blocked
            passed = (
                test_case["expected"] == "BLOCKED"
                and response.status_code == 400
            )

            return {
                "name": test_case["name"],
                "url": test_case["url"],
                "expected": test_case["expected"],
                "actual": actual,
                "score": "-",
                "confidence": "-",
                "result": "PASS" if passed else "FAIL"
            }

        # -------------------------------------------------
        # NORMAL RESPONSE
        # -------------------------------------------------

        data = response.json()

        actual = data.get(
            "status",
            "UNKNOWN"
        )

        score = data.get(
            "threat_score",
            "-"
        )

        confidence = data.get(
            "confidence",
            "-"
        )

        passed = (
            actual == test_case["expected"]
        )

        return {
            "name": test_case["name"],
            "url": test_case["url"],
            "expected": test_case["expected"],
            "actual": actual,
            "score": score,
            "confidence": confidence,
            "result": "PASS" if passed else "FAIL"
        }

    except Exception as e:

        print(
            f"\nError testing {test_case['name']}: {e}"
        )

        return {
            "name": test_case["name"],
            "url": test_case["url"],
            "expected": test_case["expected"],
            "actual": "ERROR",
            "score": "-",
            "confidence": "-",
            "result": "ERROR"
        }


# =========================================================
# MAIN
# =========================================================

def main():

    print("=" * 80)
    print(
        "AI PHISHING DETECTOR - ADVERSARIAL TEST SUITE"
    )
    print("=" * 80)

    print(
        f"\nTesting API: {API_URL}\n"
    )

    results = []

    # -----------------------------------------------------
    # RUN ALL TESTS
    # -----------------------------------------------------

    for index, test_case in enumerate(
        TEST_CASES,
        start=1
    ):

        print(
            f"[{index}/{len(TEST_CASES)}] "
            f"Testing: {test_case['name']}"
        )

        result = test_url(
            test_case
        )

        results.append(
            result
        )

    # =====================================================
    # RESULTS TABLE
    # =====================================================

    print("\n" + "=" * 80)
    print("TEST RESULTS")
    print("=" * 80)

    table = []

    for result in results:

        table.append([
            result["name"],
            result["expected"],
            result["actual"],
            result["score"],
            result["confidence"],
            result["result"]
        ])

    print(
        tabulate(
            table,
            headers=[
                "Test",
                "Expected",
                "Actual",
                "Score",
                "Confidence",
                "Result"
            ],
            tablefmt="grid"
        )
    )

    # =====================================================
    # SUMMARY
    # =====================================================

    passed = sum(
        r["result"] == "PASS"
        for r in results
    )

    failed = sum(
        r["result"] == "FAIL"
        for r in results
    )

    errors = sum(
        r["result"] == "ERROR"
        for r in results
    )

    total = len(results)

    accuracy = (
        passed / total * 100
        if total
        else 0
    )

    print("\n" + "=" * 80)
    print("ADVERSARIAL TEST SUMMARY")
    print("=" * 80)

    print(
        f"Total Tests : {total}"
    )

    print(
        f"Passed      : {passed}"
    )

    print(
        f"Failed      : {failed}"
    )

    print(
        f"Errors      : {errors}"
    )

    print(
        f"Test Score  : {accuracy:.2f}%"
    )

    # =====================================================
    # FINAL RESULT
    # =====================================================

    if failed == 0 and errors == 0:

        print(
            "\n🎉 ALL ADVERSARIAL TESTS PASSED!"
        )

    else:

        print(
            "\n⚠️ Some tests require investigation."
        )


# =========================================================
# ENTRY POINT
# =========================================================

if __name__ == "__main__":
    main()