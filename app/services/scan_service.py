import logging
from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError
from datetime import datetime
from datetime import date

from app.models.asset_registry import AssetRegistry
from app.models.scan import PortScanResult
from app.models.certificate import Certificate

logger = logging.getLogger("ScanService")


def store_port_scan_result(
        db: Session,
        asset_hostname: str,
        port: int,
        protocol: str = "tcp",
        state: str = "open"
):

    try:

        asset = db.query(AssetRegistry).filter(
            AssetRegistry.asset_identifier == asset_hostname
        ).first()

        if not asset:
            logger.warning(f"Asset not found → {asset_hostname}")
            return
        
        existing = db.query(PortScanResult).filter(
            PortScanResult.asset_id == asset.id,
            PortScanResult.port == port
        ).first()

        if existing:
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
        logger.error("Failed to store port result")
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

        asset = db.query(AssetRegistry).filter(
            AssetRegistry.asset_identifier == asset_hostname
        ).first()

        if not asset:
            logger.warning(f"❌ Asset not found in DB → {asset_hostname}")
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
        logger.error("Failed to store certificate")
        logger.error(e)