import logging
import requests
import urllib3
from typing import Optional, Dict, Any

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger("HTTPFingerprint")


def safe_lower_text(value) -> str:
    if value is None:
        return ""
    return str(value).lower()


def fingerprint(host: str) -> Optional[Dict[str, Any]]:
    """
    Fingerprint a web host using HTTP response headers + light HTML clues.
    """

    urls = [
        f"https://{host}",
        f"http://{host}"
    ]

    headers_req = {
        "User-Agent": "Mozilla/5.0"
    }

    for url in urls:
        try:
            logger.info(f"HTTP fingerprint trying → {url}")

            r = requests.get(
                url,
                timeout=8,
                verify=False,
                headers=headers_req,
                allow_redirects=True
            )

            headers = r.headers or {}
            html = safe_lower_text(r.text)

            technologies = headers.get("X-Generator")
            if technologies is None:
                technologies = ""

            if isinstance(technologies, list):
                technologies = ", ".join([str(x) for x in technologies])
            else:
                technologies = str(technologies)

            # Basic HTML clue fallback
            if not technologies:
                if "wp-content" in html or "wordpress" in html:
                    technologies = "WordPress"
                elif "__next_data__" in html or "/_next/" in html:
                    technologies = "Next.js"
                elif "drupal" in html:
                    technologies = "Drupal"
                elif "joomla" in html:
                    technologies = "Joomla"
                elif "shopify" in html:
                    technologies = "Shopify"
                elif "wixstatic.com" in html:
                    technologies = "Wix"

            title = None
            try:
                if "<title>" in html and "</title>" in html:
                    title = html.split("<title>", 1)[1].split("</title>", 1)[0].strip()
            except Exception:
                title = None

            result = {
                "server": headers.get("Server"),
                "powered_by": headers.get("X-Powered-By"),
                "framework": headers.get("X-AspNet-Version"),
                "technologies": technologies or None,
                "final_url": r.url,
                "status_code": r.status_code,
                "title": title
            }

            logger.info(
                f"HTTP fingerprint success → {host} | "
                f"server={result.get('server')} | "
                f"powered_by={result.get('powered_by')} | "
                f"framework={result.get('framework')} | "
                f"tech={result.get('technologies')}"
            )

            return result

        except requests.exceptions.Timeout:
            logger.warning(f"HTTP fingerprint timeout → {url}")
        except requests.exceptions.ConnectionError:
            logger.warning(f"HTTP fingerprint connection failed → {url}")
        except requests.exceptions.RequestException as e:
            logger.warning(f"HTTP fingerprint request failed → {url} | {e}")
        except Exception as e:
            logger.warning(f"HTTP fingerprint unknown error → {url} | {e}")

    logger.warning(f"HTTP fingerprint failed completely → {host}")
    return None