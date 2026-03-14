import logging
from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError
from datetime import datetime

from app.models.alert import Alert
from app.models.asset_registry import AssetRegistry

logger = logging.getLogger("AlertService")


def create_alert(
        db: Session,
        asset_hostname: str,
        severity: str,
        alert_type: str,
        description: str
):

    try:

        asset = db.query(AssetRegistry).filter(
            AssetRegistry.asset_identifier == asset_hostname
        ).first()

        if not asset:

            logger.warning(f"Asset not found → {asset_hostname}")
            return None

        alert = Alert(
            asset_id=asset.id,
            severity=severity,
            alert_type=alert_type,
            description=description,
            created_at=datetime.utcnow()
        )

        db.add(alert)
        db.commit()
        db.refresh(alert)

        logger.info(f"Alert created → {asset_hostname} [{severity}]")

        return alert

    except SQLAlchemyError as e:

        db.rollback()

        logger.error("Failed to create alert")
        logger.error(e)

        return None


def get_asset_alerts(
        db: Session,
        asset_hostname: str
):

    asset = db.query(AssetRegistry).filter(
        AssetRegistry.asset_identifier == asset_hostname
    ).first()

    if not asset:
        return []

    alerts = db.query(Alert).filter(
        Alert.asset_id == asset.id
    ).order_by(
        Alert.created_at.desc()
    ).all()

    return alerts


def get_recent_alerts(
        db: Session,
        limit: int = 50
):

    return db.query(Alert).order_by(
        Alert.created_at.desc()
    ).limit(limit).all()