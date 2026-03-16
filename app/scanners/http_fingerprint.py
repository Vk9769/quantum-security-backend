import requests

def fingerprint(host):

    try:

        r = requests.get(
            f"https://{host}",
            timeout=5,
            verify=False,
            headers={"User-Agent":"Mozilla/5.0"}
        )

        headers = r.headers

        return {
            "server": headers.get("Server"),
            "powered_by": headers.get("X-Powered-By"),
            "framework": headers.get("X-AspNet-Version"),
            "technologies": headers.get("X-Generator")
        }

    except:
        return None