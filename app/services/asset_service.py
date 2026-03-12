import logging
from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError
from datetime import datetime

from app.models.asset import Domain, Subdomain
from app.models.asset_registry import AssetRegistry   # create if not exists

logger = logging.getLogger("AssetService")


def store_subdomain(
        db: Session,
        organization_id: str,
        domain_name: str,
        subdomain: str
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
            return existing_sub

        new_sub = Subdomain(
            domain_id=domain.id,
            subdomain=subdomain,
            last_seen=datetime.utcnow()
        )

        db.add(new_sub)
        db.commit()
        db.refresh(new_sub)

        logger.info(f"Subdomain stored → {subdomain}")

        # -------------------------
        # ASSET REGISTRY
        # -------------------------

        asset = AssetRegistry(
            id=new_sub.id,                 # SAME ID AS SUBDOMAIN
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

        return new_sub

    except SQLAlchemyError as e:

        db.rollback()

        logger.error(f"Failed to store subdomain → {subdomain}")
        logger.error(e)