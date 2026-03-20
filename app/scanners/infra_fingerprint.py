import socket
import logging
import hashlib
import base64
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import requests
import dns.resolver

from app.scanners.reverse_dns_scanner import reverse_dns_lookup
from app.scanners.http_fingerprint import fingerprint as http_fingerprint
from app.scanners.certificate_scanner import get_certificate_info
from app.scanners.tls_scanner import scan_tls
from app.scanners.waf_detector import detect_waf
from app.scanners.asn_scanner import enrich_asn, resolve_ip

logger = logging.getLogger("InfraFingerprint")


# ============================================================
# Helpers
# ============================================================

def normalize_host(asset_identifier: str) -> str:
    if not asset_identifier:
        return ""

    asset_identifier = asset_identifier.strip().replace(" ", "")

    if asset_identifier.startswith("http://") or asset_identifier.startswith("https://"):
        parsed = urlparse(asset_identifier)
        return (parsed.hostname or asset_identifier).strip().lower()

    return asset_identifier.split("/")[0].strip().lower()


def get_parent_domains(host: str) -> List[str]:
    parts = host.split(".")
    parents = []

    for i in range(1, len(parts) - 1):
        candidate = ".".join(parts[i:])
        if candidate and candidate != host:
            parents.append(candidate)

    return parents


def safe_get(url: str, timeout: int = 8, verify: bool = False, allow_redirects: bool = True):
    try:
        return requests.get(
            url,
            timeout=timeout,
            verify=verify,
            allow_redirects=allow_redirects,
            headers={"User-Agent": "Mozilla/5.0"}
        )
    except Exception:
        return None


def unique_list(items: List[Any]) -> List[Any]:
    seen = set()
    out = []
    for item in items:
        key = str(item)
        if item is not None and key not in seen:
            seen.add(key)
            out.append(item)
    return out


def lower_or_empty(value: Optional[str]) -> str:
    return (value or "").strip().lower()


def normalize_header_dict(headers: Dict[str, Any]) -> Dict[str, Any]:
    return {str(k).lower(): v for k, v in (headers or {}).items()}


def md5_hex(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


# ============================================================
# Evidence Classification
# ============================================================

def classify_reverse_dns(reverse_dns_value: Optional[str]) -> str:
    return "observed" if reverse_dns_value else "failed / unavailable"


def classify_server_banner(headers: Dict[str, Any]) -> str:
    if is_proxy_interference(headers):
        return "proxy-obscured"
    if headers.get("server"):
        return "observed"
    return "hidden"


def classify_framework_disclosure(headers: Dict[str, Any], stack_info: Dict[str, Any]) -> str:
    if (
        headers.get("x-powered-by")
        or headers.get("x-generator")
        or headers.get("x-aspnet-version")
        or headers.get("x-framework")
        or headers.get("x-technologies")
        or stack_info.get("framework")
        or stack_info.get("cms")
    ):
        return "observed"
    return "hidden"


def classify_waf_observation(waf_value: Optional[str]) -> str:
    if waf_value:
        return "observed"
    return "not directly observed"


def classify_email_provider(email_provider: Optional[str]) -> str:
    if not email_provider:
        return "unknown"
    if email_provider == "Custom / Unknown":
        return "custom/unknown"
    return "observed"


# ============================================================
# DNS Collection
# ============================================================

def get_dns_records(host: str) -> Dict[str, List[str]]:
    records = {
        "A": [],
        "AAAA": [],
        "CNAME": [],
        "MX": [],
        "NS": [],
        "TXT": []
    }

    for rtype in records.keys():
        try:
            answers = dns.resolver.resolve(host, rtype)
            for ans in answers:
                if rtype == "MX":
                    records[rtype].append(str(ans.exchange).rstrip("."))
                elif rtype == "TXT":
                    try:
                        txt_value = b"".join(ans.strings).decode("utf-8", errors="ignore")
                    except Exception:
                        txt_value = str(ans)
                    records[rtype].append(txt_value)
                else:
                    records[rtype].append(str(ans).rstrip("."))
        except Exception:
            pass

    for key in records:
        records[key] = unique_list(records[key])

    return records


def detect_dns_provider(ns_records: List[str]) -> Optional[str]:
    ns_blob = " ".join(ns_records).lower()

    rules = {
        "Route53": ["awsdns", "route53"],
        "Cloudflare DNS": ["cloudflare"],
        "Azure DNS": ["azure-dns", "azuredns"],
        "Google Cloud DNS": ["googledomains", "google"],
        "GoDaddy DNS": ["domaincontrol.com"],
        "Namecheap DNS": ["registrar-servers.com"],
        "DigitalOcean DNS": ["digitalocean"],
    }

    for provider, patterns in rules.items():
        if any(p in ns_blob for p in patterns):
            return provider

    return None


def detect_email_provider(mx_records: List[str]) -> Optional[str]:
    mx_blob = " ".join(mx_records).lower()

    if "mail.protection.outlook.com" in mx_blob:
        return "Microsoft 365"
    if "google.com" in mx_blob or "aspmx.l.google.com" in mx_blob:
        return "Google Workspace"
    if "zoho" in mx_blob:
        return "Zoho Mail"
    if "yahoodns.net" in mx_blob:
        return "Yahoo Mail"
    if "secureserver.net" in mx_blob:
        return "GoDaddy Mail"
    if mx_blob:
        return "Custom / Unknown"

    return None


# ============================================================
# HTTP Observation Collection
# ============================================================

def collect_http_observations(host: str) -> Dict[str, Any]:
    tests = [
        ("GET", "/"),
        ("HEAD", "/"),
        ("OPTIONS", "/"),
        ("GET", "/this-page-should-not-exist-404-test"),
        ("GET", "/favicon.ico"),
    ]

    observations = []
    merged_headers = {}
    html = ""
    allow_methods = []
    protocol_hints = []
    error_page_signatures = []

    for scheme in ["https", "http"]:
        for method, path in tests:
            url = f"{scheme}://{host}{path}"
            try:
                response = requests.request(
                    method=method,
                    url=url,
                    timeout=8,
                    verify=False,
                    allow_redirects=True,
                    headers={"User-Agent": "Mozilla/5.0"}
                )

                hdrs = normalize_header_dict(dict(response.headers or {}))

                for k, v in hdrs.items():
                    if k not in merged_headers and v:
                        merged_headers[k] = v

                body = response.text if method != "HEAD" else ""
                if body and len(body) > len(html):
                    html = body[:50000]

                if hdrs.get("allow"):
                    allow_methods.extend([x.strip() for x in str(hdrs["allow"]).split(",") if x.strip()])

                if hdrs.get("alt-svc"):
                    protocol_hints.append(f'alt-svc={hdrs.get("alt-svc")}')

                if path.endswith("404-test"):
                    snippet = (body or "")[:500].lower()
                    if snippet:
                        error_page_signatures.append(snippet)

                observations.append({
                    "url": url,
                    "method": method,
                    "status_code": response.status_code,
                    "headers": hdrs,
                    "content_length": len(response.content or b""),
                    "final_url": response.url
                })

            except Exception:
                continue

    return {
        "headers": merged_headers,
        "html": html,
        "observations": observations,
        "allow_methods": unique_list(allow_methods),
        "protocol_hints": unique_list(protocol_hints),
        "error_page_signatures": error_page_signatures,
    }


def fetch_favicon_hash(host: str) -> Dict[str, Any]:
    for scheme in ["https", "http"]:
        try:
            url = f"{scheme}://{host}/favicon.ico"
            response = requests.get(
                url,
                timeout=8,
                verify=False,
                allow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0"}
            )
            if response.status_code == 200 and response.content:
                icon_bytes = response.content
                return {
                    "url": response.url,
                    "status_code": response.status_code,
                    "md5": md5_hex(icon_bytes),
                    "mmh3": None,  # add mmh3 later if installed
                    "content_type": response.headers.get("Content-Type"),
                    "size": len(icon_bytes)
                }
        except Exception:
            continue

    return {
        "url": None,
        "status_code": None,
        "md5": None,
        "mmh3": None,
        "content_type": None,
        "size": None
    }


def is_proxy_interference(headers: Dict[str, Any]) -> bool:
    blob = " ".join([
        lower_or_empty(headers.get("server")),
        lower_or_empty(headers.get("via")),
        lower_or_empty(headers.get("x-cache")),
        lower_or_empty(headers.get("x-cache-lookup")),
        lower_or_empty(headers.get("x-squid-error")),
    ])

    proxy_markers = [
        "squid",
        "x-squid-error",
        "varnish",
        "bluecoat",
        "proxy",
        "cache"
    ]

    return any(marker in blob for marker in proxy_markers)

def is_proxy_generated_response(headers: Dict[str, Any]) -> bool:
    h = normalize_header_dict(headers or {})
    blob = " ".join([
        lower_or_empty(h.get("server")),
        lower_or_empty(h.get("via")),
        lower_or_empty(h.get("x-cache")),
        lower_or_empty(h.get("x-cache-lookup")),
        lower_or_empty(h.get("x-squid-error")),
    ])
    return any(x in blob for x in ["squid", "x-squid-error", "varnish", "bluecoat"])

# ============================================================
# HTML / Headers Tech Detection
# ============================================================

def detect_web_server(headers: Dict[str, Any]) -> Optional[str]:
    if is_proxy_interference(headers):
        return None

    server = lower_or_empty(headers.get("server"))

    if "apache" in server:
        return "Apache"
    if "nginx" in server:
        return "Nginx"
    if "microsoft-iis" in server or "iis" in server:
        return "Microsoft IIS"
    if "litespeed" in server:
        return "LiteSpeed"
    if "caddy" in server:
        return "Caddy"
    if "cloudflare" in server:
        return "Cloudflare Edge"
    if "envoy" in server:
        return "Envoy"
    if "gunicorn" in server:
        return "Gunicorn"

    return None

def detect_web_server_candidates(
    headers: Dict[str, Any],
    observations: List[Dict[str, Any]],
    html: str
) -> List[Dict[str, Any]]:
    candidates = []

    if is_proxy_interference(headers):
        return candidates

    html_l = (html or "").lower()
    header_blob = " ".join([f"{k}:{v}" for k, v in headers.items()]).lower()

    # Direct banner hints
    server = lower_or_empty(headers.get("server"))
    if "apache" in server:
        candidates.append({"product": "Apache", "confidence": 0.95, "source": "server_header"})
    if "nginx" in server:
        candidates.append({"product": "Nginx", "confidence": 0.95, "source": "server_header"})
    if "microsoft-iis" in server or "iis" in server:
        candidates.append({"product": "Microsoft IIS", "confidence": 0.95, "source": "server_header"})

    # Behavioral / header hints
    if "x-aspnet-version" in headers or "x-aspnetmvc-version" in headers:
        candidates.append({"product": "Microsoft IIS", "confidence": 0.72, "source": "aspnet_headers"})

    if "x-powered-by" in headers and "asp.net" in lower_or_empty(headers.get("x-powered-by")):
        candidates.append({"product": "Microsoft IIS", "confidence": 0.68, "source": "x_powered_by"})

    if "server-timing" in header_blob and "cf" not in header_blob:
        candidates.append({"product": "Nginx", "confidence": 0.25, "source": "timing_behavior"})

    if any(obs.get("status_code") == 405 for obs in observations):
        allow_header = ""
        for obs in observations:
            hdrs = {str(k).lower(): v for k, v in (obs.get("headers") or {}).items()}
            if "allow" in hdrs:
                allow_header = str(hdrs["allow"]).upper()
                break

        if "OPTIONS" in allow_header and "TRACE" not in allow_header:
            candidates.append({"product": "Microsoft IIS", "confidence": 0.35, "source": "method_behavior"})

    # HTML signatures
    if "asp.net" in html_l or "__viewstate" in html_l or "__eventvalidation" in html_l:
        candidates.append({"product": "Microsoft IIS", "confidence": 0.75, "source": "html_signature"})

    if "apache/" in html_l:
        candidates.append({"product": "Apache", "confidence": 0.40, "source": "html_signature"})

    if "nginx/" in html_l:
        candidates.append({"product": "Nginx", "confidence": 0.40, "source": "html_signature"})

    # merge by highest confidence
    merged = {}
    for c in candidates:
        product = c["product"]
        if product not in merged or c["confidence"] > merged[product]["confidence"]:
            merged[product] = c

    return sorted(merged.values(), key=lambda x: x["confidence"], reverse=True)


def detect_backend_stack(headers: Dict[str, Any], html: str) -> Dict[str, Optional[str]]:
    powered_by = lower_or_empty(headers.get("x-powered-by"))
    generator = lower_or_empty(headers.get("x-generator"))
    aspnet_version = lower_or_empty(headers.get("x-aspnet-version"))
    framework_header = lower_or_empty(headers.get("x-framework"))
    technologies_header = lower_or_empty(headers.get("x-technologies"))
    html_l = (html or "").lower()

    backend_stack = None
    framework = None
    cms = None

    if "asp.net" in framework_header or aspnet_version:
        backend_stack = ".NET / ASP.NET"
        framework = "ASP.NET"
    elif "django" in framework_header:
        backend_stack = "Python"
        framework = "Django"
    elif "flask" in framework_header:
        backend_stack = "Python"
        framework = "Flask"
    elif "laravel" in framework_header:
        backend_stack = "PHP"
        framework = "Laravel"
    elif "next.js" in framework_header:
        backend_stack = "Node.js"
        framework = "Next.js"
    elif "express" in framework_header:
        backend_stack = "Node.js"
        framework = "Express"

    if "asp.net" in powered_by:
        backend_stack = backend_stack or ".NET / ASP.NET"
        framework = framework or "ASP.NET"
    elif "php" in powered_by:
        backend_stack = backend_stack or "PHP"
    elif "express" in powered_by:
        backend_stack = backend_stack or "Node.js"
        framework = framework or "Express"
    elif "next.js" in powered_by:
        backend_stack = backend_stack or "Node.js"
        framework = framework or "Next.js"
    elif "django" in powered_by:
        backend_stack = backend_stack or "Python"
        framework = framework or "Django"
    elif "flask" in powered_by:
        backend_stack = backend_stack or "Python"
        framework = framework or "Flask"
    elif "laravel" in powered_by:
        backend_stack = backend_stack or "PHP"
        framework = framework or "Laravel"

    if "wp-content" in html_l or "wordpress" in generator or "wordpress" in technologies_header:
        backend_stack = backend_stack or "PHP"
        framework = framework or "WordPress"
        cms = "WordPress"

    if "csrfmiddlewaretoken" in html_l or "django" in html_l:
        backend_stack = backend_stack or "Python"
        framework = framework or "Django"

    if "__next_data__" in html_l or "/_next/" in html_l:
        backend_stack = backend_stack or "Node.js"
        framework = framework or "Next.js"

    if "react" in html_l and framework is None:
        framework = "React"

    if "angular" in html_l and framework is None:
        framework = "Angular"

    return {
        "backend_stack": backend_stack,
        "framework": framework,
        "cms": cms
    }


# ============================================================
# Behavioral Fingerprinting
# ============================================================

def score_behavioral_web_server(
    headers: Dict[str, Any],
    observations: List[Dict[str, Any]],
    html: str,
    error_page_signatures: List[str]
) -> List[Dict[str, Any]]:
    if is_proxy_interference(headers):
        return []

    scores = {
        "Microsoft IIS": 0.0,
        "Apache": 0.0,
        "Nginx": 0.0,
        "OpenResty": 0.0,
        "LiteSpeed": 0.0,
        "Caddy": 0.0,
    }

    server = lower_or_empty(headers.get("server"))
    powered_by = lower_or_empty(headers.get("x-powered-by"))
    aspnet_version = lower_or_empty(headers.get("x-aspnet-version"))
    html_l = (html or "").lower()
    error_blob = " ".join(error_page_signatures).lower()

    if "microsoft-iis" in server or "iis" in server:
        scores["Microsoft IIS"] += 0.95
    if "apache" in server:
        scores["Apache"] += 0.95
    if "nginx" in server:
        scores["Nginx"] += 0.95
    if "openresty" in server:
        scores["OpenResty"] += 0.95
    if "litespeed" in server:
        scores["LiteSpeed"] += 0.95
    if "caddy" in server:
        scores["Caddy"] += 0.95

    if aspnet_version or "asp.net" in powered_by:
        scores["Microsoft IIS"] += 0.35

    if "__viewstate" in html_l or "__eventvalidation" in html_l or "asp.net" in html_l:
        scores["Microsoft IIS"] += 0.30

    if "apache" in error_blob:
        scores["Apache"] += 0.25
    if "nginx" in error_blob:
        scores["Nginx"] += 0.25
    if "openresty" in error_blob:
        scores["OpenResty"] += 0.25
    if "iis" in error_blob or "asp.net" in error_blob:
        scores["Microsoft IIS"] += 0.25

    for obs in observations:
        hdrs = normalize_header_dict(obs.get("headers", {}) or {})
        allow = lower_or_empty(hdrs.get("allow"))
        x_aspnet = lower_or_empty(hdrs.get("x-aspnet-version"))

        if x_aspnet:
            scores["Microsoft IIS"] += 0.20

        if "trace" in allow and ("microsoft" in server or x_aspnet):
            scores["Microsoft IIS"] += 0.10

    candidates = []
    for product, score in scores.items():
        if score > 0:
            candidates.append({
                "product": product,
                "confidence": round(min(score, 0.99), 2),
                "source": "behavior_fingerprint"
            })

    candidates.sort(key=lambda x: x["confidence"], reverse=True)
    return candidates


# ============================================================
# Passive Enrichment Hook
# ============================================================

def get_passive_web_server_candidates(host: str, ip_address: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Placeholder hook.
    Later you can connect Shodan/Censys/Netlas/FOFA here.
    Keep result normalized.
    """
    return []


def merge_web_server_candidates(*candidate_lists: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    merged: Dict[str, Dict[str, Any]] = {}

    for candidates in candidate_lists:
        for c in candidates or []:
            product = c.get("product")
            if not product:
                continue

            if product not in merged:
                merged[product] = {
                    "product": product,
                    "confidence": float(c.get("confidence", 0.0)),
                    "source": c.get("source", "unknown")
                }
            else:
                merged[product]["confidence"] = round(
                    min(0.99, merged[product]["confidence"] + float(c.get("confidence", 0.0)) * 0.5),
                    2
                )
                if merged[product]["source"] != c.get("source"):
                    merged[product]["source"] = f'{merged[product]["source"]}+{c.get("source", "unknown")}'

    final_list = list(merged.values())
    final_list.sort(key=lambda x: x["confidence"], reverse=True)
    return final_list


# ============================================================
# Provider / Infra Inference
# ============================================================

def detect_cloud_provider(
    host: str,
    dns_records: Dict[str, List[str]],
    headers: Dict[str, Any],
    reverse_dns_name: Optional[str],
    asn_org: Optional[str],
    cert_info: Optional[Dict[str, Any]],
) -> Optional[str]:
    blob = " ".join([
        host,
        " ".join(dns_records.get("CNAME", [])),
        " ".join(dns_records.get("A", [])),
        " ".join(dns_records.get("NS", [])),
        reverse_dns_name or "",
        lower_or_empty(headers.get("server")),
        lower_or_empty(headers.get("via")),
        lower_or_empty(headers.get("x-served-by")),
        lower_or_empty(headers.get("cf-ray")),
        asn_org or "",
        (cert_info or {}).get("issuer", "") if cert_info else "",
        (cert_info or {}).get("subject", "") if cert_info else "",
    ]).lower()

    rules = [
        ("AWS", ["amazonaws.com", "cloudfront.net", "elb.amazonaws.com", "awsglobalaccelerator", "aws"]),
        ("Azure", ["azurewebsites.net", "cloudapp.azure.com", "azure", "microsoft corporation"]),
        ("GCP", ["googleusercontent.com", "appspot.com", "run.app", "google", "gcp"]),
        ("Cloudflare", ["cloudflare", "cf-ray"]),
        ("Akamai", ["akamai", "akamaiedge.net", "edgekey.net"]),
        ("Fastly", ["fastly", "fastly.net"]),
        ("Vercel", ["vercel.app", "vercel"]),
        ("Netlify", ["netlify.app", "netlify"]),
        ("Heroku", ["herokuapp.com", "heroku"]),
        ("DigitalOcean", ["digitalocean"]),
    ]

    for provider, patterns in rules:
        if any(p in blob for p in patterns):
            return provider

    return None


def detect_hosting_provider(
    cloud_provider: Optional[str],
    org_name: Optional[str],
    dns_provider: Optional[str],
    waf_cdn: Optional[str]
) -> Optional[str]:
    if cloud_provider:
        return cloud_provider

    org = lower_or_empty(org_name)
    if org:
        return org_name

    if dns_provider:
        return dns_provider

    if waf_cdn:
        return waf_cdn

    return None


def detect_waf_cdn_combined(host: str, headers: Dict[str, Any]) -> Optional[str]:
    waf = detect_waf(host)
    if waf:
        return waf

    blob = " ".join([
        lower_or_empty(headers.get("server")),
        lower_or_empty(headers.get("via")),
        lower_or_empty(headers.get("x-served-by")),
        lower_or_empty(headers.get("cf-cache-status")),
        lower_or_empty(headers.get("cf-ray")),
        lower_or_empty(headers.get("x-cache")),
    ])

    if "cloudflare" in blob or "cf-ray" in blob:
        return "Cloudflare"
    if "akamai" in blob:
        return "Akamai"
    if "fastly" in blob:
        return "Fastly"
    if "imperva" in blob:
        return "Imperva"
    if "sucuri" in blob:
        return "Sucuri"

    return None


def detect_load_balancer(
    dns_records: Dict[str, List[str]],
    headers: Dict[str, Any],
    reverse_dns_name: Optional[str]
) -> Optional[str]:
    blob = " ".join([
        " ".join(dns_records.get("CNAME", [])),
        lower_or_empty(headers.get("via")),
        lower_or_empty(headers.get("server")),
        reverse_dns_name or ""
    ]).lower()

    if "elb.amazonaws.com" in blob:
        return "AWS ELB / ALB"
    if "azure" in blob and "frontdoor" in blob:
        return "Azure Front Door"
    if "google" in blob and "lb" in blob:
        return "Google Cloud Load Balancer"
    if "cloudflare" in blob:
        return "Cloudflare Proxy"

    return None


def infer_deployment_type(
    cloud_provider: Optional[str],
    org_name: Optional[str],
    waf_cdn: Optional[str],
    framework: Optional[str],
    cms: Optional[str],
    dns_records: Dict[str, List[str]]
) -> str:
    cname_blob = " ".join(dns_records.get("CNAME", [])).lower()
    org_blob = lower_or_empty(org_name)

    if cms in ["Shopify", "Wix"]:
        return "SaaS Hosted Platform"

    if "vercel.app" in cname_blob or "netlify.app" in cname_blob:
        return "Static / Jamstack Hosting"

    if "azurewebsites.net" in cname_blob:
        return "PaaS App Service"

    if "run.app" in cname_blob or "appspot.com" in cname_blob:
        return "PaaS / Serverless"

    if cloud_provider and waf_cdn:
        return "Cloud Behind CDN/WAF"

    if cloud_provider:
        return f"Cloud Hosted ({cloud_provider})"

    if org_blob.startswith("as") or "bank" in org_blob:
        return "Organization-managed infrastructure"

    if framework in ["Next.js", "React", "Angular"]:
        return "Web Application"

    return "Unknown"


def calculate_confidence(result: Dict[str, Any]) -> float:
    score = 0.0

    if result.get("ip_address"):
        score += 0.10
    if result.get("asn"):
        score += 0.10
    if result.get("org_name"):
        score += 0.15
    if result.get("reverse_dns"):
        score += 0.10
    if result.get("web_server"):
        score += 0.10
    elif result.get("web_server_candidates"):
        score += 0.05
    if result.get("cloud_provider"):
        score += 0.15
    if result.get("hosting_provider"):
        score += 0.10
    if result.get("waf_cdn"):
        score += 0.05
    if result.get("dns_provider"):
        score += 0.05
    if result.get("email_provider"):
        score += 0.05
    if result.get("backend_stack"):
        score += 0.05
    if result.get("framework") or result.get("cms"):
        score += 0.05
    if result.get("tls_version"):
        score += 0.05

    return round(min(score, 0.99), 2)


# ============================================================
# Main Scanner
# ============================================================

def scan_infra_fingerprint(asset_identifier: str) -> Dict[str, Any]:
    host = normalize_host(asset_identifier)

    result: Dict[str, Any] = {
        "asset_identifier": asset_identifier,
        "host": host,
        "ip_address": None,
        "hosting_provider": None,
        "cloud_provider": None,
        "region": None,
        "web_server": None,
        "web_server_candidates": [],
        "web_server_detection_method": None,
        "passive_technology_matches": [],
        "backend_stack": None,
        "framework": None,
        "cms": None,
        "waf_cdn": None,
        "dns_provider": None,
        "email_provider": None,
        "load_balancer": None,
        "os_hint": None,
        "deployment_type": None,
        "deployment_observation": None,
        "reverse_dns": None,
        "reverse_dns_status": None,
        "server_banner_status": None,
        "framework_headers_status": None,
        "waf_cdn_status": None,
        "email_provider_status": None,
        "asn": None,
        "org_name": None,
        "tls_version": None,
        "supported_tls_versions": [],
        "cipher_suite": None,
        "key_exchange": None,
        "certificate_issuer": None,
        "certificate_subject": None,
        "certificate_expiry": None,
        "signature_algorithm": None,
        "key_size": None,
        "public_key_type": None,
        "quantum_security": None,
        "confidence_score": 0.0,
        "favicon_hash": {},
        "http_protocol_hints": [],
        "behavioral_fingerprint": {},
        "external_exposure_summary": {},
        "evidence_summary": {},
        "http_observations": [],
        "raw_headers": {},
        "raw_dns": {},
        "raw_tls": {},
        "raw_certificate": {},
    }

    if not host:
        logger.warning("Infra fingerprint skipped: invalid host")
        return result

    logger.info(f"Starting infrastructure fingerprint → {host}")

    dns_records = {}
    cert_info = None
    stack_info = {"backend_stack": None, "framework": None, "cms": None}

    try:
        ip = resolve_ip(host) or socket.gethostbyname(host)
        result["ip_address"] = ip
    except Exception as e:
        logger.warning(f"IP resolution failed → {host} | {e}")

    try:
        dns_records = get_dns_records(host)
        result["raw_dns"] = {"host": dns_records}

        dns_provider = detect_dns_provider(dns_records.get("NS", []))
        email_provider = detect_email_provider(dns_records.get("MX", []))

        if not dns_provider or not email_provider:
            for parent in get_parent_domains(host):
                parent_dns = get_dns_records(parent)
                result["raw_dns"][parent] = parent_dns

                if not dns_provider:
                    dns_provider = detect_dns_provider(parent_dns.get("NS", []))
                if not email_provider:
                    email_provider = detect_email_provider(parent_dns.get("MX", []))
                if dns_provider and email_provider:
                    break

        result["dns_provider"] = dns_provider
        result["email_provider"] = email_provider

    except Exception as e:
        logger.warning(f"DNS collection failed → {host} | {e}")

    try:
        reverse_name = reverse_dns_lookup(host)
        result["reverse_dns"] = reverse_name
    except Exception as e:
        logger.warning(f"Reverse DNS failed → {host} | {e}")

    try:
        http_fp = http_fingerprint(host) or {}
        observation_data = collect_http_observations(host)

        observations = observation_data.get("observations", []) or []
        html = observation_data.get("html", "") or ""

        trusted_headers = {}
        for obs in observations:
            hdrs = normalize_header_dict(obs.get("headers", {}) or {})
            status = obs.get("status_code")
            url = lower_or_empty(obs.get("url"))

            if is_proxy_generated_response(hdrs):
                continue

            # Prefer successful HTTPS observations
            if url.startswith("https://") and status and 200 <= int(status) < 400:
                for k, v in hdrs.items():
                    if k not in trusted_headers and v:
                        trusted_headers[k] = v

        # fallback only if nothing trusted found
        if not trusted_headers:
            trusted_headers = observation_data.get("headers", {}) or {}

        merged_headers = dict(trusted_headers)

        if http_fp.get("server") and not merged_headers.get("server"):
            merged_headers["server"] = http_fp.get("server")

        if http_fp.get("powered_by") and not merged_headers.get("x-powered-by"):
            merged_headers["x-powered-by"] = http_fp.get("powered_by")

        if http_fp.get("framework") and not merged_headers.get("x-framework"):
            merged_headers["x-framework"] = http_fp.get("framework")

        technologies = http_fp.get("technologies")
        if technologies and not merged_headers.get("x-technologies"):
            merged_headers["x-technologies"] = ", ".join(technologies) if isinstance(technologies, list) else str(technologies)
            
        result["raw_headers"] = merged_headers
        result["http_observations"] = observation_data.get("observations", [])
        result["http_protocol_hints"] = observation_data.get("protocol_hints", [])

        proxy_detected = is_proxy_interference(merged_headers)

        # direct detection first
        direct_web_server = detect_web_server(merged_headers)
        if direct_web_server:
            result["web_server"] = direct_web_server
            result["web_server_detection_method"] = "server_header"

        stack_info = detect_backend_stack(merged_headers, html)
        result["backend_stack"] = stack_info.get("backend_stack")
        result["framework"] = stack_info.get("framework")
        result["cms"] = stack_info.get("cms")
        result["waf_cdn"] = detect_waf_cdn_combined(host, merged_headers)

        direct_candidates = detect_web_server_candidates(
            headers=merged_headers,
            observations=result["http_observations"],
            html=html
        )

        behavior_candidates = score_behavioral_web_server(
            headers=merged_headers,
            observations=result["http_observations"],
            html=html,
            error_page_signatures=observation_data.get("error_page_signatures", [])
        )

        passive_candidates = get_passive_web_server_candidates(host, result.get("ip_address"))

        result["passive_technology_matches"] = passive_candidates
        result["web_server_candidates"] = merge_web_server_candidates(
            direct_candidates,
            behavior_candidates,
            passive_candidates
        )

        if not result["web_server"] and result["web_server_candidates"]:
            result["web_server_detection_method"] = "behavior_fingerprint"

        result["behavioral_fingerprint"] = {
            "proxy_interference_detected": proxy_detected,
            "allow_methods": observation_data.get("allow_methods", []),
            "protocol_hints": observation_data.get("protocol_hints", []),
            "observed_status_codes": unique_list([
                obs.get("status_code")
                for obs in result["http_observations"]
                if obs.get("status_code") is not None
            ]),
            "error_page_signatures_count": len(observation_data.get("error_page_signatures", [])),
            "candidate_count": len(result["web_server_candidates"])
        }

    except Exception as e:
        logger.warning(f"HTTP fingerprint failed → {host} | {e}")

    try:
        result["favicon_hash"] = fetch_favicon_hash(host)
    except Exception as e:
        logger.warning(f"Favicon fetch failed → {host} | {e}")

    try:
        cert_info = get_certificate_info(host) or {}
        result["raw_certificate"] = cert_info

        if cert_info:
            result["certificate_issuer"] = cert_info.get("issuer")
            result["certificate_subject"] = cert_info.get("subject")
            result["certificate_expiry"] = str(cert_info.get("expiry")) if cert_info.get("expiry") else None
            result["signature_algorithm"] = cert_info.get("signature_algorithm")
            result["key_size"] = cert_info.get("key_size")
            result["public_key_type"] = cert_info.get("public_key_type")
    except Exception as e:
        logger.warning(f"Certificate scan failed → {host} | {e}")

    try:
        tls_info = scan_tls(host) or {}
        result["raw_tls"] = tls_info

        if tls_info:
            result["tls_version"] = tls_info.get("tls_version")
            result["supported_tls_versions"] = tls_info.get("supported_tls_versions", [])
            result["cipher_suite"] = tls_info.get("cipher_suite")
            result["key_exchange"] = tls_info.get("key_exchange")
            result["certificate_issuer"] = result["certificate_issuer"] or tls_info.get("certificate_issuer")
            result["certificate_subject"] = result["certificate_subject"] or tls_info.get("certificate_subject")
            result["certificate_expiry"] = result["certificate_expiry"] or tls_info.get("expiry")
            result["signature_algorithm"] = result["signature_algorithm"] or tls_info.get("signature_algorithm")
            result["key_size"] = result["key_size"] or tls_info.get("key_size")
            result["public_key_type"] = result["public_key_type"] or tls_info.get("public_key_type")
            result["quantum_security"] = tls_info.get("quantum_security")
    except Exception as e:
        logger.warning(f"TLS scan failed → {host} | {e}")

    try:
        asn_info = enrich_asn(host)

        if asn_info.get("primary_asn"):
            result["asn"] = str(asn_info["primary_asn"])

        if asn_info.get("org"):
            result["org_name"] = asn_info["org"]

        if asn_info.get("asns"):
            result["asn"] = ", ".join([str(x) for x in asn_info["asns"]])
    except Exception as e:
        logger.warning(f"ASN scan failed → {host} | {e}")

    try:
        cloud_provider = detect_cloud_provider(
            host=host,
            dns_records=dns_records,
            headers=result.get("raw_headers", {}),
            reverse_dns_name=result.get("reverse_dns"),
            asn_org=result.get("org_name"),
            cert_info=cert_info,
        )
        result["cloud_provider"] = cloud_provider
        result["hosting_provider"] = detect_hosting_provider(
            cloud_provider=cloud_provider,
            org_name=result.get("org_name"),
            dns_provider=result.get("dns_provider"),
            waf_cdn=result.get("waf_cdn")
        )
    except Exception as e:
        logger.warning(f"Cloud provider detection failed → {host} | {e}")

    try:
        result["load_balancer"] = detect_load_balancer(
            dns_records=dns_records,
            headers=result.get("raw_headers", {}),
            reverse_dns_name=result.get("reverse_dns")
        )

        result["deployment_type"] = infer_deployment_type(
            cloud_provider=result.get("cloud_provider"),
            org_name=result.get("org_name"),
            waf_cdn=result.get("waf_cdn"),
            framework=result.get("framework"),
            cms=result.get("cms"),
            dns_records=dns_records
        )
    except Exception as e:
        logger.warning(f"Deployment type detection failed → {host} | {e}")

    try:
        web_server = lower_or_empty(result.get("web_server"))
        backend = lower_or_empty(result.get("backend_stack"))
        rdns = lower_or_empty(result.get("reverse_dns"))

        if "iis" in web_server or "asp.net" in backend:
            result["os_hint"] = "Windows"
        elif any(x in web_server for x in ["nginx", "apache", "gunicorn", "envoy"]) or "compute.amazonaws.com" in rdns:
            result["os_hint"] = "Linux"
    except Exception:
        pass

    result["reverse_dns_status"] = classify_reverse_dns(result.get("reverse_dns"))
    result["server_banner_status"] = classify_server_banner(result.get("raw_headers", {}))
    result["framework_headers_status"] = classify_framework_disclosure(
        result.get("raw_headers", {}),
        {"framework": result.get("framework"), "cms": result.get("cms")}
    )
    result["waf_cdn_status"] = classify_waf_observation(result.get("waf_cdn"))
    result["email_provider_status"] = classify_email_provider(result.get("email_provider"))
    result["deployment_observation"] = "inferred" if result.get("deployment_type") not in [None, "Unknown"] else "unknown"

    result["external_exposure_summary"] = {
        "reverse_dns": result.get("reverse_dns_status"),
        "http_server_banner": result.get("server_banner_status"),
        "framework_headers": result.get("framework_headers_status"),
        "waf_cdn": result.get("waf_cdn_status"),
        "email_provider": result.get("email_provider_status"),
        "deployment_type": result.get("deployment_type"),
        "quantum_security": result.get("quantum_security")
    }

    result["evidence_summary"] = {
        "server_header_present": bool(result.get("raw_headers", {}).get("server")),
        "proxy_interference_detected": is_proxy_interference(result.get("raw_headers", {})),
        "direct_web_server_detected": bool(result.get("web_server")),
        "candidate_web_servers": result.get("web_server_candidates", []),
        "passive_matches": result.get("passive_technology_matches", []),
        "reverse_dns_present": bool(result.get("reverse_dns")),
        "tls_present": bool(result.get("tls_version")),
        "favicon_hash": result.get("favicon_hash", {}),
        "tls_version": result.get("tls_version"),
        "cipher_suite": result.get("cipher_suite"),
        "certificate_subject": result.get("certificate_subject"),
    }

    result["confidence_score"] = calculate_confidence(result)

    logger.info(
        f"Infrastructure fingerprint completed → {host} | "
        f"hosting_provider={result.get('hosting_provider')} | "
        f"cloud_provider={result.get('cloud_provider')} | "
        f"server={result.get('web_server')} | "
        f"server_candidates={result.get('web_server_candidates')} | "
        f"framework={result.get('framework')} | "
        f"waf={result.get('waf_cdn')} | "
        f"asn={result.get('asn')} | "
        f"org={result.get('org_name')} | "
        f"deployment={result.get('deployment_type')} | "
        f"pqc={result.get('quantum_security')} | "
        f"confidence={result.get('confidence_score')}"
    )
    
    logger.info(
        f"HTTP header selection → host={host} | "
        f"trusted_server={merged_headers.get('server')} | "
        f"raw_server={(observation_data.get('headers', {}) or {}).get('server')} | "
        f"proxy_interference={is_proxy_interference(observation_data.get('headers', {}) or {})}"
    )

    return result