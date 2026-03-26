import logging
import time
from datetime import datetime, date
from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError

from app.models.asset_registry import AssetRegistry
from app.models.scan import PortScanResult
from app.models.certificate import Certificate

logger = logging.getLogger("ScanService")


def normalize_asset_identifier(hostname: str) -> str:
    if not hostname:
        return ""

    return (
        str(hostname)
        .strip()
        .lower()
        .replace("https://", "")
        .replace("http://", "")
        .split(":")[0]
        .strip("/")
    )


def get_asset(db: Session, hostname: str):
    hostname = normalize_asset_identifier(hostname)
    asset = None

    for _ in range(5):
        asset = db.query(AssetRegistry).filter(
            AssetRegistry.asset_identifier == hostname
        ).first()

        if asset:
            return asset

        logger.warning(f"[Retry] Asset not found → {hostname}")
        time.sleep(1)

    logger.error(f"[Failed] Asset still missing → {hostname}")
    return None


def store_port_scan_result(
    db: Session,
    asset_hostname: str,
    port: int,
    protocol: str = "tcp",
    state: str = "open"
):
    try:
        asset_hostname = normalize_asset_identifier(asset_hostname)
        asset = get_asset(db, asset_hostname)

        if not asset:
            return

        existing = db.query(PortScanResult).filter(
            PortScanResult.asset_id == asset.id,
            PortScanResult.port == port
        ).first()

        if existing:
            logger.info(f"Port already exists → {asset_hostname}:{port}")
            return

        result = PortScanResult(
            asset_id=asset.id,
            port=port,
            protocol=protocol,
            state=state,
            scan_time=datetime.utcnow()
        )

        db.add(result)
        db.commit()

        logger.info(f"Port stored → {asset_hostname}:{port}")

    except SQLAlchemyError as e:
        db.rollback()
        logger.error(f"Failed to store port result → {asset_hostname}:{port}")
        logger.error(e)


def store_certificate_result(
    db: Session,
    asset_hostname: str,
    issuer: str,
    subject: str,
    expiry: date,
    signature_algorithm: str,
    key_size: int
):
    try:
        asset_hostname = normalize_asset_identifier(asset_hostname)
        asset = get_asset(db, asset_hostname)

        if not asset:
            return
        else:
            logger.info(f"✅ Asset found → {asset_hostname}")

        existing = db.query(Certificate).filter(
            Certificate.asset_id == asset.id,
            Certificate.signature_algorithm == signature_algorithm,
            Certificate.expiry_date == expiry
        ).first()

        if existing:
            logger.info(f"Certificate already exists → {asset_hostname}")
            return

        cert = Certificate(
            asset_id=asset.id,
            issuer=issuer,
            subject=subject,
            expiry_date=expiry,
            signature_algorithm=signature_algorithm,
            key_size=key_size
        )

        db.add(cert)
        db.commit()

        logger.info(f"💾 Certificate stored → {asset_hostname}")

    except SQLAlchemyError as e:
        db.rollback()
        logger.error(f"Failed to store certificate → {asset_hostname}")
        logger.error(e)