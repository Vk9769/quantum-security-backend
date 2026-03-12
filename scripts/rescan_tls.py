import logging
from datetime import datetime

from sqlalchemy.orm import Session

from app.db.postgres import SessionLocal
from app.models.asset_registry import AssetRegistry
from app.models.tls import TLSScanResult
from app.scanners.tls_scanner import scan_tls

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("TLSRescan")


db: Session = SessionLocal()

assets = db.query(AssetRegistry).all()

logger.info(f"Rescanning TLS for {len(assets)} assets")

for asset in assets:

    host = asset.asset_identifier

    logger.info(f"Scanning TLS → {host}")

    result = scan_tls(host, 443)

    if not result:
        continue

    existing = db.query(TLSScanResult).filter(
        TLSScanResult.asset_id == asset.id
    ).first()

    if existing:

        existing.tls_version = result["tls_version"]
        existing.cipher_suite = result["cipher_suite"]
        existing.key_exchange = result["key_exchange"]
        existing.scan_time = datetime.utcnow()

        logger.info(f"TLS updated → {host}")

    else:

        tls = TLSScanResult(
            asset_id=asset.id,
            tls_version=result["tls_version"],
            cipher_suite=result["cipher_suite"],
            key_exchange=result["key_exchange"],
            forward_secrecy="DHE" in result["cipher_suite"],
            scan_time=datetime.utcnow()
        )

        db.add(tls)

        logger.info(f"TLS stored → {host}")

    db.commit()

db.close()

logger.info("TLS rescan finished")