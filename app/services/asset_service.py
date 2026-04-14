import logging
import ipaddress
from datetime import datetime
from typing import Optional, List

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session
from tldextract import extract

from app.models.asset import Domain, Subdomain
from app.models.asset_registry import AssetRegistry
from app.models.tls import TLSScanResult
from app.models.cbom import CBOMInventory
from app.models.pqc import PQCAnalysis
from app.models.scan import PortScanResult

logger = logging.getLogger("AssetService")


# =========================================================
# HELPERS
# =========================================================

def normalize_asset_identifier(value: Optional[str]) -> str:
    if not value:
        return ""

    value = str(value).strip().lower()

    if value.startswith("https://"):
        value = value[len("https://"):]
    elif value.startswith("http://"):
        value = value[len("http://"):]

    value = value.strip().rstrip("/")
    value = value.split("/")[0]

    if ":" in value:
        host_part, port_part = value.rsplit(":", 1)
        if port_part.isdigit():
            value = host_part

    return value.strip()


def is_valid_ip(value: Optional[str]) -> bool:
    try:
        if not value:
            return False
        ipaddress.ip_address(str(value).strip())
        return True
    except Exception:
        return False


def extract_root_domain(hostname: str) -> str:
    hostname = normalize_asset_identifier(hostname)
    ext = extract(hostname)
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}"
    return hostname


def _safe_str(value, default="-") -> str:
    if value is None:
        return default
    value = str(value).strip()
    return value if value else default


def _get_asset_registry_row(
    db: Session,
    asset_identifier: str,
    asset_type: Optional[str] = None
):
    asset_identifier = normalize_asset_identifier(asset_identifier)

    query = db.query(AssetRegistry).filter(
        AssetRegistry.asset_identifier == asset_identifier
    )

    if asset_type:
        query = query.filter(AssetRegistry.asset_type == asset_type)

    return query.first()


def _get_latest_port_for_asset(db: Session, asset_id):
    return (
        db.query(PortScanResult)
        .filter(PortScanResult.asset_id == asset_id)
        .order_by(PortScanResult.scan_time.desc())
        .first()
    )


def _get_tls_for_asset(db: Session, asset_id):
    return (
        db.query(TLSScanResult)
        .filter(TLSScanResult.asset_id == asset_id)
        .order_by(TLSScanResult.scan_time.desc())
        .first()
    )


def _get_cbom_for_asset(db: Session, asset_id):
    return (
        db.query(CBOMInventory)
        .filter(CBOMInventory.asset_id == asset_id)
        .first()
    )


def _get_pqc_for_asset(db: Session, asset_id):
    return (
        db.query(PQCAnalysis)
        .filter(PQCAnalysis.asset_id == asset_id)
        .first()
    )


def _resolve_pqc_status(pqc_row, cbom_row) -> str:
    if pqc_row:
        if pqc_row.pqc_ready:
            return "PQC"
        if pqc_row.recommended_upgrade:
            return "Upgrade"
        return "Upgrade"

    if cbom_row and cbom_row.quantum_risk:
        risk = str(cbom_row.quantum_risk).strip().lower()
        if risk in ["low", "safe", "ready", "pqc"]:
            return "PQC"
        return "Upgrade"

    return "Upgrade"


# =========================================================
# CORE ASSET INVENTORY FUNCTIONS
# =========================================================

def get_or_create_asset(
    db: Session,
    organization_id: str,
    asset_identifier: str,
    asset_type: str = "subdomain",
    status: str = "active"
):
    asset_identifier = normalize_asset_identifier(asset_identifier)

    if not asset_identifier:
        logger.warning("Empty asset_identifier received in get_or_create_asset")
        return None

    try:
        asset = db.query(AssetRegistry).filter(
            AssetRegistry.asset_identifier == asset_identifier
        ).first()

        if asset:
            asset.last_seen = datetime.utcnow()

            if not asset.asset_type:
                asset.asset_type = asset_type

            if not asset.status:
                asset.status = status

            db.commit()
            db.refresh(asset)
            return asset

        asset = AssetRegistry(
            organization_id=organization_id,
            asset_identifier=asset_identifier,
            asset_type=asset_type,
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow(),
            status=status
        )

        db.add(asset)
        db.commit()
        db.refresh(asset)

        logger.info(f"Asset registry entry created → {asset_identifier}")
        return asset

    except SQLAlchemyError as e:
        db.rollback()
        logger.error(f"Failed to get/create asset → {asset_identifier}")
        logger.error(e)
        return None


def get_or_create_domain(
    db: Session,
    organization_id: str,
    domain_name: str
):
    domain_name = normalize_asset_identifier(domain_name)

    if not domain_name:
        logger.warning("Empty domain_name received in get_or_create_domain")
        return None

    try:
        domain = db.query(Domain).filter(
            Domain.domain_name == domain_name
        ).first()

        if domain:
            return domain

        domain = Domain(
            organization_id=organization_id,
            domain_name=domain_name
        )

        db.add(domain)
        db.commit()
        db.refresh(domain)

        logger.info(f"Domain created → {domain_name}")
        return domain

    except SQLAlchemyError as e:
        db.rollback()
        logger.error(f"Failed to get/create domain → {domain_name}")
        logger.error(e)
        return None


def store_subdomain(
    db: Session,
    organization_id: str,
    domain_name: str,
    subdomain: str,
    ip_address: str = None
):
    subdomain = normalize_asset_identifier(subdomain)
    domain_name = normalize_asset_identifier(domain_name)
    ip_address = str(ip_address).strip() if ip_address else None

    try:
        domain = get_or_create_domain(db, organization_id, domain_name)

        if not domain:
            logger.error(f"Failed to ensure domain exists → {domain_name}")
            return None

        existing_sub = db.query(Subdomain).filter(
            Subdomain.subdomain == subdomain
        ).first()

        if existing_sub:
            existing_sub.last_seen = datetime.utcnow()

            if ip_address:
                existing_sub.ip_address = ip_address

            db.commit()
            db.refresh(existing_sub)

            logger.info(f"Subdomain updated → {subdomain} | IP → {ip_address}")

            asset = get_or_create_asset(
                db=db,
                organization_id=organization_id,
                asset_identifier=subdomain,
                asset_type="subdomain",
                status="active"
            )

            if asset:
                asset.last_seen = datetime.utcnow()
                db.commit()

            # Keep IP assets in DB if you want IP tab support
            if ip_address and is_valid_ip(ip_address):
                ip_asset = get_or_create_asset(
                    db=db,
                    organization_id=organization_id,
                    asset_identifier=ip_address,
                    asset_type="ip",
                    status="active"
                )

                if ip_asset:
                    ip_asset.last_seen = datetime.utcnow()
                    db.commit()

            return existing_sub

        new_sub = Subdomain(
            domain_id=domain.id,
            subdomain=subdomain,
            ip_address=ip_address,
            last_seen=datetime.utcnow()
        )

        db.add(new_sub)
        db.commit()
        db.refresh(new_sub)

        logger.info(f"Subdomain stored → {subdomain} | IP → {ip_address}")

        get_or_create_asset(
            db=db,
            organization_id=organization_id,
            asset_identifier=subdomain,
            asset_type="subdomain",
            status="active"
        )

        # Keep IP assets in DB if you want IP tab support
        if ip_address and is_valid_ip(ip_address):
            get_or_create_asset(
                db=db,
                organization_id=organization_id,
                asset_identifier=ip_address,
                asset_type="ip",
                status="active"
            )

        return new_sub

    except SQLAlchemyError as e:
        db.rollback()
        logger.error(f"Failed to store subdomain → {subdomain}")
        logger.error(e)
        return None


# =========================================================
# UI ASSET VISIBILITY
# =========================================================

def _build_subdomain_asset_row(db: Session, sub: Subdomain, domain: Domain) -> dict:
    sub_asset = _get_asset_registry_row(
        db=db,
        asset_identifier=sub.subdomain,
        asset_type="subdomain"
    )

    port_value = "-"
    tls_value = "-"
    pqc_value = "Upgrade"

    if sub_asset:
        port_row = _get_latest_port_for_asset(db, sub_asset.id)
        tls_row = _get_tls_for_asset(db, sub_asset.id)
        cbom_row = _get_cbom_for_asset(db, sub_asset.id)
        pqc_row = _get_pqc_for_asset(db, sub_asset.id)

        port_value = str(port_row.port) if port_row and port_row.port is not None else "-"
        tls_value = tls_row.tls_version if tls_row and tls_row.tls_version else "-"
        pqc_value = _resolve_pqc_status(pqc_row, cbom_row)

        asset_id = str(sub_asset.id)
    else:
        asset_id = str(sub.id)

    return {
        "id": asset_id,
        "name": sub.subdomain,
        "type": "subdomain",
        "domain": domain.domain_name,
        "ip": _safe_str(sub.ip_address, "-"),
        "port": port_value,
        "tls": tls_value,
        "pqc": pqc_value
    }


def _build_domain_asset_row(db: Session, domain: Domain) -> dict:
    domain_asset = _get_asset_registry_row(
        db=db,
        asset_identifier=domain.domain_name,
        asset_type="domain"
    )

    return {
        "id": str(domain_asset.id) if domain_asset else str(domain.id),
        "name": domain.domain_name,
        "type": "domain",
        "domain": domain.domain_name,
        "ip": "-",
        "port": "-",
        "tls": "-",
        "pqc": "-"
    }


def _build_ip_asset_row(db: Session, asset: AssetRegistry) -> dict:
    port_row = _get_latest_port_for_asset(db, asset.id)
    tls_row = _get_tls_for_asset(db, asset.id)
    cbom_row = _get_cbom_for_asset(db, asset.id)
    pqc_row = _get_pqc_for_asset(db, asset.id)

    return {
        "id": str(asset.id),
        "name": asset.asset_identifier,
        "type": "ip",
        "domain": asset.asset_identifier,
        "ip": asset.asset_identifier,
        "port": str(port_row.port) if port_row and port_row.port is not None else "-",
        "tls": tls_row.tls_version if tls_row and tls_row.tls_version else "-",
        "pqc": _resolve_pqc_status(pqc_row, cbom_row)
    }


def get_assets_visibility(db: Session, asset_type: str = "all") -> List[dict]:
    asset_type = (asset_type or "all").strip().lower()
    result = []

    # -----------------------------
    # DOMAIN ROWS
    # -----------------------------
    if asset_type in ["all", "domain"]:
        domain_rows = db.query(Domain).order_by(Domain.domain_name.asc()).all()
        for domain in domain_rows:
            result.append(_build_domain_asset_row(db, domain))

    # -----------------------------
    # SUBDOMAIN ROWS
    # -----------------------------
    if asset_type in ["all", "subdomain", "ssl", "software"]:
        subdomain_rows = (
            db.query(Subdomain, Domain)
            .join(Domain, Subdomain.domain_id == Domain.id)
            .order_by(Subdomain.subdomain.asc())
            .all()
        )

        sub_rows = []
        for sub, domain in subdomain_rows:
            row = _build_subdomain_asset_row(db, sub, domain)
            sub_rows.append(row)

        if asset_type == "ssl":
            sub_rows = [row for row in sub_rows if row["tls"] != "-"]

        elif asset_type == "software":
            # No software table yet, so return empty
            sub_rows = []

        result.extend(sub_rows)

    # -----------------------------
    # IP ROWS
    # Only in IP tab, not in ALL tab
    # -----------------------------
    if asset_type == "ip":
        ip_assets = (
            db.query(AssetRegistry)
            .filter(AssetRegistry.asset_type == "ip")
            .order_by(AssetRegistry.asset_identifier.asc())
            .all()
        )

        for asset in ip_assets:
            result.append(_build_ip_asset_row(db, asset))

    return result


def get_assets_counts(db: Session) -> dict:
    try:
        domain_count = db.query(Domain).count()
        subdomain_count = db.query(Subdomain).count()

        # SAFE TLS query
        try:
            ssl_asset_ids = {
                str(row.asset_id)
                for row in db.query(TLSScanResult.asset_id).distinct().all()
                if row.asset_id is not None
            }
        except Exception:
            ssl_asset_ids = set()

        # SAFE IP count
        try:
            ip_count = db.query(AssetRegistry).filter(
                AssetRegistry.asset_type == "ip"
            ).count()
        except Exception:
            ip_count = 0

        return {
            "all": domain_count + subdomain_count,
            "domain": domain_count,
            "subdomain": subdomain_count,
            "ssl": len(ssl_asset_ids),
            "ip": ip_count,
            "software": 0
        }

    except Exception as e:
        logger.error(f"Error in get_assets_counts: {e}")
        return {
            "all": 0,
            "domain": 0,
            "subdomain": 0,
            "ssl": 0,
            "ip": 0,
            "software": 0
        }


def get_assets_summary_data(db: Session) -> List[dict]:
    try:
        counts = get_assets_counts(db)
        total_assets = counts.get("all", 0)

        return [
            {
                "label": "Total Assets",
                "value": str(total_assets),
                "change": "+0%",
                "icon": "Server",
                "positive": True
            },
            {
                "label": "New Issues",
                "value": "0",
                "change": "+0%",
                "icon": "AlertTriangle",
                "positive": False
            },
            {
                "label": "Resolved Issues",
                "value": "0",
                "change": "+0%",
                "icon": "CheckCircle",
                "positive": True
            },
            {
                "label": "Ignored Issues",
                "value": "0",
                "change": "+0%",
                "icon": "XCircle",
                "positive": False
            }
        ]
    except Exception as e:
        logger.error(f"Error in get_assets_summary_data: {e}")
        return []