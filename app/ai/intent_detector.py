import re
from urllib.parse import urlparse

# =========================================================
# SCAN INTENT PATTERNS
# =========================================================

SCAN_PATTERNS = [
    r"(scan|check|analyze|test)\s+(https?:\/\/[^\s]+|[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})",
    r"(start scan for)\s+(https?:\/\/[^\s]+|[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})",
    r"(scan domain)\s+(https?:\/\/[^\s]+|[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})",
]

# =========================================================
# CLEAN DOMAIN
# =========================================================

def clean_domain(domain: str) -> str:

    domain = domain.strip().lower()

    # Remove protocol if present
    if domain.startswith("http://") or domain.startswith("https://"):
        parsed = urlparse(domain)
        domain = parsed.netloc

    # Remove path if accidentally included
    domain = domain.split("/")[0]

    # Remove port if included
    domain = domain.split(":")[0]

    # Remove www
    if domain.startswith("www."):
        domain = domain[4:]

    return domain

# =========================================================
# VALIDATE DOMAIN
# =========================================================

def is_valid_domain(domain: str) -> bool:

    domain_regex = (
        r"^(?:[a-zA-Z0-9]"
        r"(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
        r"[a-zA-Z]{2,}$"
    )

    return re.match(domain_regex, domain) is not None

# =========================================================
# DETECT SCAN INTENT
# =========================================================

def detect_scan_intent(message: str):

    if not message:
        return None

    message = message.strip()

    for pattern in SCAN_PATTERNS:

        match = re.search(pattern, message, re.IGNORECASE)

        if match:

            raw_domain = match.group(2)

            domain = clean_domain(raw_domain)

            if not is_valid_domain(domain):

                return {
                    "action": "invalid_domain",
                    "domain": raw_domain,
                    "success": False,
                    "message": "Invalid domain provided."
                }

            return {
                "action": "start_scan",
                "domain": domain,
                "success": True
            }

    return None