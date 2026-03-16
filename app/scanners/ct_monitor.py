import requests


def check_ct_logs(domain):

    url = f"https://crt.sh/?q=%25.{domain}&output=json"

    try:

        r = requests.get(url, timeout=30)

        data = r.json()

        return len(data)

    except:
        return 0