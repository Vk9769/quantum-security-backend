import requests


def detect_waf(host):

    try:

        r = requests.get(f"https://{host}", timeout=5, verify=False)

        server = r.headers.get("Server","").lower()

        if "cloudflare" in server:
            return "Cloudflare"

        if "akamai" in server:
            return "Akamai"

        if "bigip" in server:
            return "F5"

        if "imperva" in server:
            return "Imperva"

        if "netscaler" in server:
            return "Citrix"

        return None

    except:
        return None