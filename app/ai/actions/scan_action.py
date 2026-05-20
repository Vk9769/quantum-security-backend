import traceback
from urllib.parse import urlparse

from scripts.run_scanner import start_scan


# ======================================================
# CLEAN DOMAIN
# ======================================================

def normalize_domain(domain: str) -> str:

    if not domain:
        return ""

    domain = domain.strip().lower()

    if domain.startswith("http://") or domain.startswith("https://"):

        parsed = urlparse(domain)

        domain = parsed.netloc

    domain = domain.split("/")[0]
    domain = domain.split(":")[0]

    if domain.startswith("www."):

        domain = domain[4:]

    return domain


# ======================================================
# EXECUTE SCAN
# ======================================================

async def execute_scan(domain: str):

    try:

        print("\n" + "=" * 60)
        print("AI AGENT EXECUTE SCAN")
        print("RAW INPUT:", domain)
        print("=" * 60)

        # ============================================
        # CLEAN DOMAIN
        # ============================================

        domain = normalize_domain(domain)

        print("NORMALIZED DOMAIN:", domain)

        if not domain:

            return {
                "success": False,
                "action": "start_scan",
                "message": "Domain is empty"
            }

        # ============================================
        # START SCAN
        # ============================================

        print("\n" + "=" * 60)
        print(f"STARTING REAL SCAN -> {domain}")
        print("=" * 60)

        scan_id = start_scan(domain)

        print("\n" + "=" * 60)
        print("SCAN STARTED")
        print("DOMAIN:", domain)
        print("SCAN ID:", scan_id)
        print("=" * 60)

        # ============================================
        # SUCCESS RESPONSE
        # ============================================

        return {

            "success": True,

            "action": "start_scan",

            "scan_id": scan_id,

            "domain": domain,

            "status": "queued",

            "message":
                f"Security scan pipeline started successfully for {domain}",

            "next_stage": [

                "asset_discovery",

                "subdomain_scan",

                "port_scan",

                "tls_scan",

                "certificate_scan",

                "cbom_generation",

                "risk_analysis",

                "report_generation"
            ]
        }

    except Exception as e:

        print("\n" + "=" * 60)
        print("SCAN ACTION ERROR")
        print(str(e))
        traceback.print_exc()
        print("=" * 60)

        return {

            "success": False,

            "action": "start_scan",

            "domain": domain,

            "error": str(e),

            "message":
                "Failed to start scan pipeline"
        }