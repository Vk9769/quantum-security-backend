import logging
import ipaddress
from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError
from datetime import datetime

from app.models.asset import Domain, Subdomain
from app.models.asset_registry import AssetRegistry

logger = logging.getLogger("AssetService")


def is_valid_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except Exception:
        return False


def store_subdomain(
    db: Session,
    organization_id: str,
    domain_name: str,
    subdomain: str,
    ip_address: str = None
):
    try:
        # -------------------------
        # DOMAIN
        # -------------------------
        domain = db.query(Domain).filter(
            Domain.domain_name == domain_name
        ).first()

        if not domain:
            domain = Domain(
                organization_id=organization_id,
                domain_name=domain_name
            )
            db.add(domain)
            db.commit()
            db.refresh(domain)
            logger.info(f"Domain created → {domain_name}")

        # -------------------------
        # SUBDOMAIN
        # -------------------------
        existing_sub = db.query(Subdomain).filter(
            Subdomain.subdomain == subdomain
        ).first()

        if existing_sub:
            # update IP + last_seen if available
            existing_sub.last_seen = datetime.utcnow()

            if ip_address:
                existing_sub.ip_address = ip_address

            db.commit()
            db.refresh(existing_sub)

            # Ensure subdomain asset exists in registry
            asset = db.query(AssetRegistry).filter(
                AssetRegistry.asset_identifier == subdomain
            ).first()

            if not asset:
                asset = AssetRegistry(
                    organization_id=organization_id,
                    asset_identifier=subdomain,
                    asset_type="subdomain",
                    first_seen=datetime.utcnow(),
                    last_seen=datetime.utcnow(),
                    status="active"
                )
                db.add(asset)
                db.commit()
                logger.info(f"Asset registry entry created → {subdomain}")
            else:
                asset.last_seen = datetime.utcnow()
                db.commit()

            # Ensure IP asset also exists in registry
            if ip_address and is_valid_ip(ip_address):
                ip_asset = db.query(AssetRegistry).filter(
                    AssetRegistry.asset_identifier == ip_address
                ).first()

                if not ip_asset:
                    ip_asset = AssetRegistry(
                        organization_id=organization_id,
                        asset_identifier=ip_address,
                        asset_type="ip",
                        first_seen=datetime.utcnow(),
                        last_seen=datetime.utcnow(),
                        status="active"
                    )
                    db.add(ip_asset)
                    db.commit()
                    logger.info(f"IP asset registry entry created → {ip_address}")
                else:
                    ip_asset.last_seen = datetime.utcnow()
                    db.commit()

            return existing_sub

        # create new subdomain
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

        # -------------------------
        # ASSET REGISTRY: SUBDOMAIN
        # -------------------------
        asset = db.query(AssetRegistry).filter(
            AssetRegistry.asset_identifier == subdomain
        ).first()

        if not asset:
            asset = AssetRegistry(
                organization_id=organization_id,
                asset_identifier=subdomain,
                asset_type="subdomain",
                first_seen=datetime.utcnow(),
                last_seen=datetime.utcnow(),
                status="active"
            )
            db.add(asset)
            db.commit()
            logger.info(f"Asset registry entry created → {subdomain}")

        # -------------------------
        # ASSET REGISTRY: IP
        # -------------------------
        if ip_address and is_valid_ip(ip_address):
            ip_asset = db.query(AssetRegistry).filter(
                AssetRegistry.asset_identifier == ip_address
            ).first()

            if not ip_asset:
                ip_asset = AssetRegistry(
                    organization_id=organization_id,
                    asset_identifier=ip_address,
                    asset_type="ip",
                    first_seen=datetime.utcnow(),
                    last_seen=datetime.utcnow(),
                    status="active"
                )
                db.add(ip_asset)
                db.commit()
                logger.info(f"IP asset registry entry created → {ip_address}")
            else:
                ip_asset.last_seen = datetime.utcnow()
                db.commit()

        return new_sub

    except SQLAlchemyError as e:
        db.rollback()
        logger.error(f"Failed to store subdomain → {subdomain}")
        logger.error(e)
        return None