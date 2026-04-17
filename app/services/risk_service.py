from datetime import date
from sqlalchemy import func

from app.models.risk import AssetRiskScore
from app.models.asset_registry import AssetRegistry
from app.models.tls import TLSScanResult
from app.models.certificate import Certificate


def store_asset_risk(db, asset_id, score):
    category = "LOW"

    if score >= 70:
        category = "CRITICAL"
    elif score >= 40:
        category = "HIGH"
    elif score >= 20:
        category = "MEDIUM"

    record = AssetRiskScore(
        asset_id=asset_id,
        score=score,
        risk_category=category
    )

    db.add(record)


def get_global_risk_score(db):
    total_assets = db.query(AssetRegistry).count()

    if total_assets == 0:
        return {
            "score": 0,
            "label": "No Risk",
            "change": 0
        }

    weak_tls = db.query(TLSScanResult).filter(
        TLSScanResult.tls_version != "TLS 1.3"
    ).count()

    expired_certs = db.query(Certificate).filter(
        Certificate.expiry_date.isnot(None),
        Certificate.expiry_date < date.today()
    ).count()

    risk_score = (weak_tls * 2) + (expired_certs * 3)
    risk_score = min(risk_score, 100)

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
    asset = db.query(AssetRegistry).filter(
        AssetRegistry.asset_identifier == domain
    ).first()

    if not asset:
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

    tls = db.query(TLSScanResult).filter(
        TLSScanResult.asset_id == asset.id
    ).order_by(TLSScanResult.scan_time.desc()).first()

    cert = db.query(Certificate).filter(
        Certificate.asset_id == asset.id
    ).first()

    risk_score = 0
    weak_tls = False
    tls_version = None
    expired_cert = False
    certificate_expiry = None

    if tls:
        tls_version = tls.tls_version
        if tls.tls_version != "TLS 1.3":
            weak_tls = True
            risk_score += 40

    if cert and cert.expiry_date:
        certificate_expiry = str(cert.expiry_date)
        if cert.expiry_date < date.today():
            expired_cert = True
            risk_score += 60

    risk_score = min(risk_score, 100)

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
        "asset_id": str(asset.id),
        "score": risk_score,
        "label": label,
        "change": 0,
        "weak_tls": weak_tls,
        "tls_version": tls_version,
        "expired_cert": expired_cert,
        "certificate_expiry": certificate_expiry
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