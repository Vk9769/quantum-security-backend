import logging
from typing import Optional
from sqlalchemy.orm import Session

from app.models.asset_registry import AssetRegistry
from app.models.certificate import Certificate
from app.models.cbom import CBOMInventory
from app.models.pqc import PQCAnalysis
from app.models.tls import TLSScanResult

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


def update_cbom_quantum_risk(db: Session, asset_id, quantum_risk: str):
    cbom = db.query(CBOMInventory).filter(
        CBOMInventory.asset_id == asset_id
    ).first()

    if cbom:
        cbom.quantum_risk = quantum_risk
        db.commit()


def store_pqc_analysis(db: Session, asset_id, algorithm: str, pqc_ready: bool):
    upgrade = None

    if not pqc_ready:
        upgrade = "CRYSTALS-Kyber / Dilithium"

    record = PQCAnalysis(
        asset_id=asset_id,
        algorithm=algorithm,
        pqc_ready=pqc_ready,
        recommended_upgrade=upgrade
    )

    db.add(record)
    db.commit()


def build_pqc_dashboard(db: Session, domain: Optional[str] = None):
    query = db.query(AssetRegistry)

    if domain:
        query = query.filter(
            AssetRegistry.asset_identifier.ilike(f"%{domain}%")
        )

    assets = query.all()

    pqc_assets = []
    elite_count = 0
    standard_count = 0
    legacy_count = 0
    critical_count = 0

    ready_count = 0
    standard_status_count = 0
    legacy_status_count = 0
    critical_status_count = 0

    recommendations_set = set()

    for asset in assets:
        tls = db.query(TLSScanResult).filter(
            TLSScanResult.asset_id == asset.id
        ).first()

        cbom = db.query(CBOMInventory).filter(
            CBOMInventory.asset_id == asset.id
        ).first()

        pqc = db.query(PQCAnalysis).filter(
            PQCAnalysis.asset_id == asset.id
        ).order_by(PQCAnalysis.id.desc()).first()

        cert = db.query(Certificate).filter(
            Certificate.asset_id == asset.id
        ).first()

        support = bool(pqc.pqc_ready) if pqc else False
        tls_version = tls.tls_version if tls else None
        key_exchange = tls.key_exchange if tls else None
        quantum_risk = cbom.quantum_risk if cbom else None

        asset_ip = None

        if support:
            elite_count += 1
            ready_count += 1
        else:
            if quantum_risk and quantum_risk.upper() == "CRITICAL":
                critical_count += 1
                critical_status_count += 1
                recommendations_set.add("Immediate migration from vulnerable cryptography")
                recommendations_set.add("Implement Kyber for key exchange")
            elif tls_version and tls_version.upper() in ["TLSV1.3", "TLS1.3"]:
                standard_count += 1
                standard_status_count += 1
                recommendations_set.add("Upgrade key exchange to PQC-hybrid mode")
            else:
                legacy_count += 1
                legacy_status_count += 1
                recommendations_set.add("Upgrade to TLS 1.3 with PQC")
                recommendations_set.add("Update cryptographic libraries")

        if cert and cert.signature_algorithm:
            algo = cert.signature_algorithm.lower()
            if "rsa" in algo or "ecdsa" in algo:
                recommendations_set.add("Develop PQC migration plan")

        pqc_assets.append({
            "asset_id": asset.id,
            "name": asset.asset_identifier,
            "ip": asset_ip,
            "support": support,
            "tls_version": tls_version,
            "key_exchange": key_exchange,
            "quantum_risk": quantum_risk
        })

    total_assets = len(assets)

    def pct(count: int) -> int:
        if total_assets == 0:
            return 0
        return round((count / total_assets) * 100)

    summary_stats = [
        {
            "label": "Elite-PQC Ready",
            "value": f"{pct(ready_count)}%",
            "color": "text-emerald-400"
        },
        {
            "label": "Standard",
            "value": f"{pct(standard_status_count)}%",
            "color": "text-cyan-400"
        },
        {
            "label": "Legacy",
            "value": f"{pct(legacy_status_count)}%",
            "color": "text-amber-400"
        },
        {
            "label": "Critical Apps",
            "value": str(critical_status_count),
            "color": "text-rose-400"
        },
    ]

    classification_data = [
        {
            "label": "Elite",
            "value": elite_count,
            "color": "bg-emerald-400"
        },
        {
            "label": "Critical",
            "value": critical_count,
            "color": "bg-red-500"
        },
        {
            "label": "Std",
            "value": standard_count,
            "color": "bg-violet-500"
        },
    ]

    application_status = [
        {
            "label": "Elite-PQC Ready",
            "value": pct(ready_count),
            "color": "#4ade80"
        },
        {
            "label": "Standard",
            "value": pct(standard_status_count),
            "color": "#22d3ee"
        },
        {
            "label": "Legacy",
            "value": pct(legacy_status_count),
            "color": "#f59e0b"
        },
        {
            "label": "Critical",
            "value": pct(critical_status_count),
            "color": "#ef4444"
        },
    ]

    app_details = None
    if pqc_assets:
        first_asset = pqc_assets[0]

        score = 900 if first_asset["support"] else 480
        status = "PQC Ready" if first_asset["support"] else "Legacy"
        risk_label = "Low" if first_asset["support"] else "Critical"
        tls_text = first_asset["key_exchange"] or first_asset["tls_version"] or "Unknown"

        app_details = {
            "name": first_asset["name"],
            "owner": "Security Team",
            "exposure": "Internet",
            "tls": tls_text,
            "score": score,
            "risk_label": risk_label,
            "status": status
        }

    recommendations = list(recommendations_set)
    if not recommendations:
        recommendations = [
            "Upgrade to TLS 1.3 with PQC",
            "Implement Kyber for key exchange",
            "Update cryptographic libraries",
            "Develop PQC migration plan",
        ]

    return {
        "summary_stats": summary_stats,
        "classification_data": classification_data,
        "application_status": application_status,
        "assets": pqc_assets,
        "recommendations": recommendations,
        "app_details": app_details
    }