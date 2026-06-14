import requests
import sys
import urllib.parse

# Payloads to test for reflected input
# NOTE: At least one of these should be encoded or obfuscated to test variant reflection
payloads = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(2)>",
    "%3Csvg%2Fonload%3Dalert(3)%3E"  # Encoded variant
]

def test_payload(base_url, payload):
    """
    Submit payload to target URL and check if it's reflected in the response.
    """
    try:
        full_url = base_url + payload
        response = requests.get(full_url, timeout=5)

        # Check for non-200 status (required by autograder)
        if response.status_code != 200:
            return False

        # Detect if payload appears in response (consider encoded variants)
        # Exact match first
        if payload in response.text:
            return True
        # Then try URL-decoded version
        decoded = urllib.parse.unquote(payload)
        if decoded != payload and decoded in response.text:
            return True
        return False

    except requests.exceptions.RequestException as e:
        print(f"[!] Request failed for payload: {payload}")
        print(f"    Error: {e}")
        return False

def main():
    # Get target URL from command line (autograder requirement)
    if len(sys.argv) != 2:
        print("Usage: python web_scanner.py <target_url>")
        print("Example: python web_scanner.py 'http://localhost:5000/search?q='")
        sys.exit(1)

    base_url = sys.argv[1]

    print("\n[+] Starting web vulnerability scan...\n")

    vulnerable_count = 0
    total = len(payloads)

    # Loop through all payloads and call test_payload()
    for payload in payloads:
        vulnerable = test_payload(base_url, payload)
        if vulnerable:
            print(f"vulnerable payload {payload}")
            vulnerable_count += 1
        else:
            print(f"secure payload {payload}")

    # Print a summary at the end
    print(f"summary: {vulnerable_count} of {total} payloads")

if __name__ == "__main__":
    main()