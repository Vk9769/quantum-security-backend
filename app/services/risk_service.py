from datetime import date
from sqlalchemy import func

from app.models.risk import AssetRiskScore
from app.models.asset_registry import AssetRegistry
from app.models.tls import TLSScanResult
from app.models.certificate import Certificate
from app.models.scan_jobs import ScanJob
from app.models.cbom import CBOMInventory
from sqlalchemy import func
from sqlalchemy.orm import Session

def store_asset_risk(db, asset_id, score):

    existing = db.query(AssetRiskScore).filter(
        AssetRiskScore.asset_id == asset_id
    ).first()

    category = "LOW"
    if score >= 70:
        category = "CRITICAL"
    elif score >= 40:
        category = "HIGH"
    elif score >= 20:
        category = "MEDIUM"

    if existing:
        existing.score = score
        existing.risk_category = category
    else:
        db.add(AssetRiskScore(
            asset_id=asset_id,
            score=score,
            risk_category=category
        ))

    db.commit()  # ✅ MUST


def get_global_risk_score(db):

    rows = db.query(
        AssetRiskScore.score
    ).all()

    if not rows:
        return {
            "score": 0,
            "label": "No Risk",
            "change": 0
        }

    scores = [r[0] for r in rows if r[0] is not None]

    if not scores:
        return {
            "score": 0,
            "label": "No Risk",
            "change": 0
        }

    avg_score = sum(scores) / len(scores)

    risk_score = min(int(avg_score), 100)

    if risk_score >= 80:
        label = "High Risk"
    elif risk_score >= 60:
        label = "Moderate Risk"
    elif risk_score >= 30:
        label = "Low Risk"
    else:
        label = "No Risk"

    return {
        "score": risk_score,
        "label": label,
        "change": 0
    }


def get_risk_tiers(db):
    grouped_rows = (
        db.query(
            func.upper(AssetRiskScore.risk_category).label("risk_category"),
            func.count(AssetRiskScore.id).label("count")
        )
        .group_by(func.upper(AssetRiskScore.risk_category))
        .all()
    )

    counts_map = {row.risk_category: row.count for row in grouped_rows}

    tiers = [
        {
            "label": "Critical",
            "count": counts_map.get("CRITICAL", 0),
            "color": "bg-destructive",
            "textColor": "text-destructive"
        },
        {
            "label": "High",
            "count": counts_map.get("HIGH", 0),
            "color": "bg-warning",
            "textColor": "text-warning"
        },
        {
            "label": "Medium",
            "count": counts_map.get("MEDIUM", 0),
            "color": "bg-primary",
            "textColor": "text-primary"
        },
        {
            "label": "Low",
            "count": counts_map.get("LOW", 0),
            "color": "bg-success",
            "textColor": "text-success"
        }
    ]

    return tiers


def get_domain_risk_score(db, domain: str):

    assets = db.query(AssetRegistry.id).filter(
        AssetRegistry.asset_identifier.ilike(f"%{domain}%")
    ).all()

    asset_ids = [a[0] for a in assets]

    if not asset_ids:
        return {
            "domain": domain,
            "asset_id": None,
            "score": 0,
            "label": "No Data",
            "change": 0,
            "weak_tls": False,
            "tls_version": None,
            "expired_cert": False,
            "certificate_expiry": None
        }

    scores = db.query(AssetRiskScore.score).filter(
        AssetRiskScore.asset_id.in_(asset_ids)
    ).all()

    scores = [s[0] for s in scores if s[0] is not None]

    if not scores:
        return {
            "domain": domain,
            "asset_id": None,
            "score": 0,
            "label": "No Data",
            "change": 0,
            "weak_tls": False,
            "tls_version": None,
            "expired_cert": False,
            "certificate_expiry": None
        }

    avg = sum(scores) / len(scores)
    risk_score = min(int(avg), 100)

    # ✅ LABEL LOGIC
    if risk_score >= 80:
        label = "High Risk"
    elif risk_score >= 60:
        label = "Moderate Risk"
    elif risk_score >= 30:
        label = "Low Risk"
    else:
        label = "No Risk"

    return {
        "domain": domain,
        "asset_id": None,
        "score": risk_score,
        "label": label,
        "change": 0,
        "weak_tls": False,
        "tls_version": None,
        "expired_cert": False,
        "certificate_expiry": None
    }


def get_domain_risk_tiers(db, domain: str):
    asset = db.query(AssetRegistry).filter(
        AssetRegistry.asset_identifier == domain
    ).first()

    if not asset:
        return [
            {
                "label": "Critical",
                "count": 0,
                "color": "bg-destructive",
                "textColor": "text-destructive"
            },
            {
                "label": "High",
                "count": 0,
                "color": "bg-warning",
                "textColor": "text-warning"
            },
            {
                "label": "Medium",
                "count": 0,
                "color": "bg-primary",
                "textColor": "text-primary"
            },
            {
                "label": "Low",
                "count": 0,
                "color": "bg-success",
                "textColor": "text-success"
            }
        ]

    risk_row = db.query(AssetRiskScore).filter(
        AssetRiskScore.asset_id == asset.id
    ).first()

    counts_map = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0
    }

    if risk_row and risk_row.risk_category:
        counts_map[risk_row.risk_category.upper()] = 1

    tiers = [
        {
            "label": "Critical",
            "count": counts_map.get("CRITICAL", 0),
            "color": "bg-destructive",
            "textColor": "text-destructive"
        },
        {
            "label": "High",
            "count": counts_map.get("HIGH", 0),
            "color": "bg-warning",
            "textColor": "text-warning"
        },
        {
            "label": "Medium",
            "count": counts_map.get("MEDIUM", 0),
            "color": "bg-primary",
            "textColor": "text-primary"
        },
        {
            "label": "Low",
            "count": counts_map.get("LOW", 0),
            "color": "bg-success",
            "textColor": "text-success"
        }
    ]

    return tiers


def get_scan_risk_tiers(db: Session, scan_id: str):

    # -----------------------------
    # GET DOMAIN FROM SCAN
    # -----------------------------
    scan = db.query(ScanJob).filter(ScanJob.id == scan_id).first()

    if not scan or not scan.domain:
        return []

    # -----------------------------
    # GET ASSETS ONLY FOR DOMAIN
    # -----------------------------
    asset_ids = [
        row.id
        for row in db.query(AssetRegistry.id)
        .filter(AssetRegistry.asset_identifier.ilike(f"%{scan.domain}%"))
        .all()
    ]

    if not asset_ids:
        return []

    # -----------------------------
    # GET RISK FROM SAME ASSETS
    # -----------------------------
    results = (
        db.query(
            func.upper(AssetRiskScore.risk_category),
            func.count().label("count")
        )
        .filter(AssetRiskScore.asset_id.in_(asset_ids))
        .group_by(func.upper(AssetRiskScore.risk_category))
        .all()
    )

    counts_map = {r[0]: r[1] for r in results}

    return [
        {
            "label": "Critical",
            "count": counts_map.get("CRITICAL", 0),
            "color": "bg-destructive",
            "textColor": "text-destructive"
        },
        {
            "label": "High",
            "count": counts_map.get("HIGH", 0),
            "color": "bg-warning",
            "textColor": "text-warning"
        },
        {
            "label": "Medium",
            "count": counts_map.get("MEDIUM", 0),
            "color": "bg-primary",
            "textColor": "text-primary"
        },
        {
            "label": "Low",
            "count": counts_map.get("LOW", 0),
            "color": "bg-success",
            "textColor": "text-success"
        }
    ]