import logging
from sqlalchemy.orm import Session

from app.models.asset_registry import AssetRegistry
from app.models.certificate import Certificate
from app.models.cbom import CBOMInventory

logger = logging.getLogger("PQCService")


def store_cbom(
        db: Session,
        asset_hostname: str,
        tls_version: str,
        cipher_suite: str,
        key_exchange: str,
        certificate_id=None
):

    try:

        asset = db.query(AssetRegistry).filter(
            AssetRegistry.asset_identifier == asset_hostname
        ).first()

        if not asset:
            logger.warning(f"Asset not found → {asset_hostname}")
            return

        existing = db.query(CBOMInventory).filter(
            CBOMInventory.asset_id == asset.id
        ).first()

        if existing:

            existing.tls_version = tls_version
            existing.cipher_suite = cipher_suite
            existing.key_exchange = key_exchange
            existing.certificate_id = certificate_id
            existing.quantum_risk = "UNKNOWN"

            logger.info(f"CBOM updated → {asset_hostname}")

        else:

            cbom = CBOMInventory(
                asset_id=asset.id,
                tls_version=tls_version,
                cipher_suite=cipher_suite,
                key_exchange=key_exchange,
                certificate_id=certificate_id,
                quantum_risk="UNKNOWN"
            )

            db.add(cbom)

            logger.info(f"CBOM created → {asset_hostname}")

        db.commit()

    except Exception as e:

        db.rollback()
        logger.error("CBOM store failed")
        logger.error(e)