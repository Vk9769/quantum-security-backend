import requests
import time

API_URL = "https://api.ssllabs.com/api/v3/analyze"

def analyze_domain(domain):
    params = {
        "host": domain,
        "publish": "off",
        "startNew": "on",
        "all": "done"
    }

    print(f"Starting SSL scan for: {domain}")
    
    while True:
        response = requests.get(API_URL, params=params)
        data = response.json()

        status = data.get("status")
        print(f"Status: {status}")

        if status == "READY":
            return data
        elif status == "ERROR":
            print("Error:", data)
            return None

        time.sleep(10)

def print_summary(data):
    if not data:
        return
    
    print("\n=== SSL REPORT ===")
    print("Domain:", data.get("host"))

    for endpoint in data.get("endpoints", []):
        print("\nIP:", endpoint.get("ipAddress"))
        print("Grade:", endpoint.get("grade"))
        print("Status:", endpoint.get("statusMessage"))

if __name__ == "__main__":
    domain = "digiel.pnb.bank.in"   # change domain here
    result = analyze_domain(domain)
    print_summary(result)