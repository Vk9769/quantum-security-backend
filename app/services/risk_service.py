from app.models.risk import AssetRiskScore


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
    db.commit()