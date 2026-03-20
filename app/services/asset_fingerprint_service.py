import logging
from typing import Any, Dict, Optional, List
from uuid import UUID

from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError

from app.models.asset_registry import AssetRegistry
from app.models.asset_fingerprint import AssetFingerprint

logger = logging.getLogger("AssetFingerprintService")


def _clean_json_value(value: Any) -> Any:
    """
    Make values safer for JSONB storage.
    """
    if value is None:
        return None

    if isinstance(value, dict):
        return {str(k): _clean_json_value(v) for k, v in value.items()}

    if isinstance(value, list):
        return [_clean_json_value(v) for v in value]

    if isinstance(value, tuple):
        return [_clean_json_value(v) for v in value]

    # datetimes / dates / UUID / custom objects
    if not isinstance(value, (str, int, float, bool)):
        try:
            return str(value)
        except Exception:
            return None

    return value


def _normalize_fingerprint_payload(fingerprint_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Keep only fields supported by current AssetFingerprint model.
    """
    return {
        "hosting_provider": fingerprint_data.get("hosting_provider"),
        "cloud_provider": fingerprint_data.get("cloud_provider"),
        "region": fingerprint_data.get("region"),
        "web_server": fingerprint_data.get("web_server"),
        "web_server_detection_method": fingerprint_data.get("web_server_detection_method"),
        "web_server_candidates": _clean_json_value(fingerprint_data.get("web_server_candidates", [])),
        "passive_technology_matches": _clean_json_value(fingerprint_data.get("passive_technology_matches", [])),
        "backend_stack": fingerprint_data.get("backend_stack"),
        "framework": fingerprint_data.get("framework"),
        "cms": fingerprint_data.get("cms"),
        "waf_cdn": fingerprint_data.get("waf_cdn"),
        "dns_provider": fingerprint_data.get("dns_provider"),
        "email_provider": fingerprint_data.get("email_provider"),
        "load_balancer": fingerprint_data.get("load_balancer"),
        "os_hint": fingerprint_data.get("os_hint"),
        "deployment_type": fingerprint_data.get("deployment_type"),
        "reverse_dns": fingerprint_data.get("reverse_dns"),
        "asn": fingerprint_data.get("asn"),
        "org_name": fingerprint_data.get("org_name"),
        "confidence_score": fingerprint_data.get("confidence_score"),
        "raw_headers": _clean_json_value(fingerprint_data.get("raw_headers", {})),
        "raw_dns": _clean_json_value(fingerprint_data.get("raw_dns", {})),
        "raw_tls": _clean_json_value(fingerprint_data.get("raw_tls", {})),
        "raw_whois": _clean_json_value(
            fingerprint_data.get("raw_whois")
            or {
                "host": fingerprint_data.get("host"),
                "ip_address": fingerprint_data.get("ip_address"),
                "certificate_issuer": fingerprint_data.get("certificate_issuer"),
                "certificate_subject": fingerprint_data.get("certificate_subject"),
                "certificate_expiry": fingerprint_data.get("certificate_expiry"),
                "signature_algorithm": fingerprint_data.get("signature_algorithm"),
                "key_size": fingerprint_data.get("key_size"),
                "raw_certificate": fingerprint_data.get("raw_certificate", {}),
            }
        ),
        "http_observations": _clean_json_value(fingerprint_data.get("http_observations", [])),
        "favicon_hash": _clean_json_value(fingerprint_data.get("favicon_hash", {})),
        "behavioral_fingerprint": _clean_json_value(fingerprint_data.get("behavioral_fingerprint", {})),
        "evidence_summary": _clean_json_value(fingerprint_data.get("evidence_summary", {})),
        "external_exposure_summary": _clean_json_value(fingerprint_data.get("external_exposure_summary", {})),
    }


def get_asset_by_id(db: Session, asset_id: str | UUID) -> Optional[AssetRegistry]:
    try:
        return db.query(AssetRegistry).filter(AssetRegistry.id == asset_id).first()
    except SQLAlchemyError as e:
        logger.error(f"Failed to fetch asset by id {asset_id} | {e}")
        return None


def get_asset_by_identifier(db: Session, asset_identifier: str) -> Optional[AssetRegistry]:
    try:
        return (
            db.query(AssetRegistry)
            .filter(AssetRegistry.asset_identifier == asset_identifier)
            .first()
        )
    except SQLAlchemyError as e:
        logger.error(f"Failed to fetch asset by identifier {asset_identifier} | {e}")
        return None


def save_asset_fingerprint(
    db: Session,
    asset_id: str | UUID,
    fingerprint_data: Dict[str, Any]
) -> Optional[AssetFingerprint]:
    """
    Save a new fingerprint row for an asset.
    Keeps history by inserting a new record each time.
    """
    try:
        asset = get_asset_by_id(db, asset_id)
        if not asset:
            logger.warning(f"Asset not found, cannot save fingerprint | asset_id={asset_id}")
            return None

        payload = _normalize_fingerprint_payload(fingerprint_data)

        fingerprint = AssetFingerprint(
            asset_id=asset.id,
            **payload
        )

        db.add(fingerprint)
        db.commit()
        db.refresh(fingerprint)

        logger.info(
            f"Asset fingerprint saved | asset_id={asset.id} "
            f"provider={fingerprint.cloud_provider} "
            f"server={fingerprint.web_server} "
            f"method={fingerprint.web_server_detection_method} "
            f"candidates={len(fingerprint.web_server_candidates or [])}"
        )

        return fingerprint

    except SQLAlchemyError as e:
        db.rollback()
        logger.error(f"Failed to save fingerprint for asset_id={asset_id} | {e}")
        return None
    except Exception as e:
        db.rollback()
        logger.error(f"Unexpected error while saving fingerprint for asset_id={asset_id} | {e}")
        return None


def save_asset_fingerprint_by_identifier(
    db: Session,
    asset_identifier: str,
    fingerprint_data: Dict[str, Any]
) -> Optional[AssetFingerprint]:
    """
    Save fingerprint using asset identifier instead of asset_id.
    """
    try:
        asset = get_asset_by_identifier(db, asset_identifier)
        if not asset:
            logger.warning(
                f"Asset not found, cannot save fingerprint | asset_identifier={asset_identifier}"
            )
            return None

        return save_asset_fingerprint(db, asset.id, fingerprint_data)

    except Exception as e:
        logger.error(
            f"Unexpected error while saving fingerprint for asset_identifier={asset_identifier} | {e}"
        )
        return None


def get_latest_asset_fingerprint(
    db: Session,
    asset_id: str | UUID
) -> Optional[AssetFingerprint]:
    try:
        return (
            db.query(AssetFingerprint)
            .filter(AssetFingerprint.asset_id == asset_id)
            .order_by(AssetFingerprint.detected_at.desc())
            .first()
        )
    except SQLAlchemyError as e:
        logger.error(f"Failed to fetch latest fingerprint for asset_id={asset_id} | {e}")
        return None


def get_asset_fingerprint_history(
    db: Session,
    asset_id: str | UUID,
    limit: int = 20
) -> List[AssetFingerprint]:
    try:
        return (
            db.query(AssetFingerprint)
            .filter(AssetFingerprint.asset_id == asset_id)
            .order_by(AssetFingerprint.detected_at.desc())
            .limit(limit)
            .all()
        )
    except SQLAlchemyError as e:
        logger.error(f"Failed to fetch fingerprint history for asset_id={asset_id} | {e}")
        return []


def delete_asset_fingerprint(
    db: Session,
    fingerprint_id: str | UUID
) -> bool:
    try:
        fingerprint = (
            db.query(AssetFingerprint)
            .filter(AssetFingerprint.id == fingerprint_id)
            .first()
        )

        if not fingerprint:
            logger.warning(f"Fingerprint not found | fingerprint_id={fingerprint_id}")
            return False

        db.delete(fingerprint)
        db.commit()

        logger.info(f"Fingerprint deleted | fingerprint_id={fingerprint_id}")
        return True

    except SQLAlchemyError as e:
        db.rollback()
        logger.error(f"Failed to delete fingerprint_id={fingerprint_id} | {e}")
        return False


def serialize_asset_fingerprint(fingerprint: AssetFingerprint) -> Dict[str, Any]:
    if not fingerprint:
        return {}

    return {
        "id": str(fingerprint.id),
        "asset_id": str(fingerprint.asset_id),
        "hosting_provider": fingerprint.hosting_provider,
        "cloud_provider": fingerprint.cloud_provider,
        "region": fingerprint.region,
        "web_server": fingerprint.web_server,
        "web_server_detection_method": fingerprint.web_server_detection_method,
        "web_server_candidates": fingerprint.web_server_candidates,
        "passive_technology_matches": fingerprint.passive_technology_matches,
        "backend_stack": fingerprint.backend_stack,
        "framework": fingerprint.framework,
        "cms": fingerprint.cms,
        "waf_cdn": fingerprint.waf_cdn,
        "dns_provider": fingerprint.dns_provider,
        "email_provider": fingerprint.email_provider,
        "load_balancer": fingerprint.load_balancer,
        "os_hint": fingerprint.os_hint,
        "deployment_type": fingerprint.deployment_type,
        "reverse_dns": fingerprint.reverse_dns,
        "asn": fingerprint.asn,
        "org_name": fingerprint.org_name,
        "confidence_score": fingerprint.confidence_score,
        "raw_headers": fingerprint.raw_headers,
        "raw_dns": fingerprint.raw_dns,
        "raw_tls": fingerprint.raw_tls,
        "raw_whois": fingerprint.raw_whois,
        "http_observations": fingerprint.http_observations,
        "favicon_hash": fingerprint.favicon_hash,
        "behavioral_fingerprint": fingerprint.behavioral_fingerprint,
        "evidence_summary": fingerprint.evidence_summary,
        "external_exposure_summary": fingerprint.external_exposure_summary,
        "detected_at": fingerprint.detected_at.isoformat() if fingerprint.detected_at else None,
    }