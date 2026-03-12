import logging
from datetime import datetime
from sqlalchemy.orm import Session

from app.models.asset import Subdomain
from app.models.asset import Domain
from app.models.scan import PortScanResult
from app.models.tls import TLSScanResult
from app.models.asset_registry import AssetRegistry

logger = logging.getLogger("TLSService")


def store_tls_scan_result(
    db: Session,
    asset_hostname: str,
    tls_version: str,
    cipher_suite: str,
    key_exchange: str
):

    try:

        asset = db.query(AssetRegistry).filter(
            AssetRegistry.asset_identifier == asset_hostname
        ).first()

        if not asset:
            logger.warning(f"Asset not found → {asset_hostname}")
            return

        existing = db.query(TLSScanResult).filter(
            TLSScanResult.asset_id == asset.id,
            TLSScanResult.cipher_suite == cipher_suite
        ).first()

        if existing:

            existing.tls_version = tls_version
            existing.key_exchange = key_exchange
            existing.scan_time = datetime.utcnow()

            logger.info(f"TLS updated → {asset_hostname}")

        else:

            tls_result = TLSScanResult(
                asset_id=asset.id,
                tls_version=tls_version,
                cipher_suite=cipher_suite,
                key_exchange=key_exchange,
                forward_secrecy="DHE" in cipher_suite,
                scan_time=datetime.utcnow()
            )

            db.add(tls_result)

            logger.info(f"TLS stored → {asset_hostname}")

        db.commit()

    except Exception as e:

        db.rollback()
        logger.error("Failed TLS store")
        logger.error(e)