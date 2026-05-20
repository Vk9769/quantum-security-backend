from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func
from app.models.tls import TLSScanResult
from app.models.risk import AssetRiskScore
from app.models.pqc import PQCAnalysis
import json

def parse_json_safe(value):
    try:
        return json.loads(value) if value else None
    except:
        return value

from app.db.postgres import get_db
from app.models.ai_agent_results import AIAgentResult
from app.models.asset_registry import AssetRegistry
from app.ai.llm.model_client import generate_ai_response
from pydantic import BaseModel

router = APIRouter()

# ============================================
# 1️⃣ AI SUMMARY
# ============================================
@router.get("/ai/summary")
def get_ai_summary(scan_id: str = None, domain: str = None, db: Session = Depends(get_db)):

    # ============================================
    # 1️⃣ FILTER ASSETS BY DOMAIN
    # ============================================
    asset_query = db.query(AssetRegistry)

    if domain:
        asset_query = asset_query.filter(
            AssetRegistry.asset_identifier.ilike(f"%{domain}%")
        )

    assets = asset_query.all()
    asset_ids = [a.id for a in assets]

    # ============================================
    # 2️⃣ FILTER AI RESULTS BY ASSET + SCAN
    # ============================================
    query = db.query(AIAgentResult)

    if scan_id:
        query = query.filter(AIAgentResult.scan_id == scan_id)

    if asset_ids:
        query = query.filter(AIAgentResult.asset_id.in_(asset_ids))
    else:
        # 👉 no assets found → return empty summary
        return {
            "success": True,
            "scan_id": scan_id,
            "source": "current",
            "data": {
                "total_assets": 0,
                "critical_findings": 0,
                "high_findings": 0,
                "recommendations_count": 0,
                "attack_paths_count": 0,
                "pqc_plan_count": 0,
                "crypto_issue_count": 0,
                "anomalies_count": 0,
                "average_risk_score": 0
            }
        }

    # ============================================
    # 3️⃣ CALCULATE METRICS
    # ============================================
    total_assets = len(asset_ids)

    critical = query.filter(AIAgentResult.severity == "CRITICAL").count()
    high = query.filter(AIAgentResult.severity == "HIGH").count()

    return {
        "success": True,
        "scan_id": scan_id,
        "source": "current",
        "data": {
            "total_assets": total_assets,
            "critical_findings": critical,
            "high_findings": high,
            "recommendations_count": query.filter(AIAgentResult.result_type == "recommendations").count(),
            "attack_paths_count": query.filter(AIAgentResult.result_type == "attack_paths").count(),
            "pqc_plan_count": query.filter(AIAgentResult.agent_name == "PQCRecommender").count(),
            "crypto_issue_count": query.filter(AIAgentResult.result_type == "crypto_issues").count(),
            "anomalies_count": query.filter(AIAgentResult.result_type == "anomalies").count(),
            "average_risk_score": 50
        }
    }


# ============================================
# 2️⃣ AI ASSETS TABLE
# ============================================
@router.get("/ai/assets")
def get_ai_assets(scan_id: str = None, domain: str = None, db: Session = Depends(get_db)):

    # ============================================
    # 1️⃣ Get ALL assets of domain
    # ============================================
    asset_query = db.query(AssetRegistry)

    if domain:
        asset_query = asset_query.filter(
            AssetRegistry.asset_identifier.ilike(f"%{domain}%")
        )

    assets = asset_query.all()

    # ============================================
    # 2️⃣ Fetch related data
    # ============================================
    from sqlalchemy import func

    subquery = (
        db.query(
            AIAgentResult.asset_id,
            AIAgentResult.result_type,
            func.max(AIAgentResult.created_at).label("latest_time")
        )
        .filter(AIAgentResult.scan_id == scan_id)
        .group_by(AIAgentResult.asset_id, AIAgentResult.result_type)
        .subquery()
    )

    ai_results = (
        db.query(AIAgentResult)
        .join(
            subquery,
            (AIAgentResult.asset_id == subquery.c.asset_id) &
            (AIAgentResult.result_type == subquery.c.result_type) &
            (AIAgentResult.created_at == subquery.c.latest_time)
        )
        .filter(AIAgentResult.scan_id == scan_id)
        .all()
    )

    tls_results = db.query(TLSScanResult).all()
    risk_scores = db.query(AssetRiskScore).all()
    pqc_results = db.query(PQCAnalysis).all()

    # ============================================
    # 3️⃣ Create maps (FAST lookup)
    # ============================================
    ai_map = {}
    for r in ai_results:
        ai_map.setdefault(r.asset_id, []).append(r)

    tls_map = {t.asset_id: t for t in tls_results}
    risk_map = {r.asset_id: r for r in risk_scores}
    pqc_map = {p.asset_id: p for p in pqc_results}

    # ============================================
    # 4️⃣ Build response
    # ============================================
    data = []

    for asset in assets:
        key = asset.id

        risk = risk_map.get(key)
        tls = tls_map.get(key)
        pqc = pqc_map.get(key)
        ai_list = ai_map.get(key, [])

        # ✅ calculate confidence (take max)
        confidence = None
        if ai_list:
            conf_values = [r.confidence for r in ai_list if r.confidence is not None]
            if conf_values:
                confidence = max(conf_values)

        row = {
            "asset_id": str(asset.id),
            "asset": asset.asset_identifier,
            "asset_type": asset.asset_type,
            "tls": tls.tls_version if tls else None,
            "risk_score": risk.score if risk else 0,
            "risk_level": (risk.risk_category.upper() if risk and risk.risk_category else "LOW"),
            "confidence": confidence,
            "pqc_ready": pqc.pqc_ready if pqc else None,
            "simulation_count": 0,
            "recommendations_count": 0,
            "crypto_issue_count": 0
        }

        # ============================================
        # 5️⃣ Count AI results
        # ============================================
        for r in ai_list:
            if r.result_type == "attack_simulation":
                row["simulation_count"] += 1

            elif r.result_type == "recommendations":
                row["recommendations_count"] += 1

            elif r.result_type == "crypto_issues":
                row["crypto_issue_count"] += 1

        data.append(row)

    # ============================================
    # 6️⃣ Return
    # ============================================
    return {
        "success": True,
        "scan_id": scan_id,
        "source": "current",
        "data": data
    }


# ============================================
# 3️⃣ AI ASSET DETAILS
# ============================================
@router.get("/ai/asset-details")
def get_ai_asset_details(scan_id: str, asset: str, db: Session = Depends(get_db)):

    from app.models.tls import TLSScanResult
    from app.models.risk import AssetRiskScore
    from app.models.pqc import PQCAnalysis
    from app.models.certificate import Certificate

    # ============================================
    # 1️⃣ Get asset
    # ============================================
    asset_obj = db.query(AssetRegistry).filter(
        AssetRegistry.asset_identifier == asset
    ).first()

    if not asset_obj:
        return {"success": False, "data": None}

    # ============================================
    # 2️⃣ Fetch related data
    # ============================================
    from sqlalchemy import func

    subquery = (
        db.query(
            AIAgentResult.asset_id,
            AIAgentResult.result_type,
            func.max(AIAgentResult.created_at).label("latest_time")
        )
        .filter(AIAgentResult.scan_id == scan_id)
        .group_by(AIAgentResult.asset_id, AIAgentResult.result_type)
        .subquery()
    )

    ai_results = (
        db.query(AIAgentResult)
        .join(
            subquery,
            (AIAgentResult.asset_id == subquery.c.asset_id) &
            (AIAgentResult.result_type == subquery.c.result_type) &
            (AIAgentResult.created_at == subquery.c.latest_time)
        )
        .filter(AIAgentResult.asset_id == asset_obj.id)
        .all()
    )

    tls = db.query(TLSScanResult).filter(
        TLSScanResult.asset_id == asset_obj.id
    ).first()

    risk = db.query(AssetRiskScore).filter(
        AssetRiskScore.asset_id == asset_obj.id
    ).first()

    pqc = db.query(PQCAnalysis).filter(
        PQCAnalysis.asset_id == asset_obj.id
    ).first()

    cert = db.query(Certificate).filter(
        Certificate.asset_id == asset_obj.id
    ).first()

    # ============================================
    # 3️⃣ Base response (IMPORTANT 🔥)
    # ============================================
    data = {
        "asset": asset,

        # ✅ FIXED FIELDS
        "asset_type": asset_obj.asset_type,
        "status": asset_obj.status,
        "criticality": asset_obj.criticality,

        "tls_version": tls.tls_version if tls else None,
        "cipher_suite": tls.cipher_suite if tls else None,
        "key_exchange": tls.key_exchange if tls else None,
        "forward_secrecy": tls.forward_secrecy if tls else None,

        "certificate_issuer": cert.issuer if cert else None,
        "certificate_subject": cert.subject if cert else None,
        "signature_algorithm": cert.signature_algorithm if cert else None,
        "key_size": cert.key_size if cert else None,
        "expiry": str(cert.expiry_date) if cert else None,

        "risk_score": risk.score if risk else 0,
        "quantum_risk": risk.risk_category if risk else "UNKNOWN",

        "pqc_ready": pqc.pqc_ready if pqc else None,

        # AI sections
        "attack_simulation": [],
        "recommendations": [],
        "attack_paths": [],
        "crypto_issues": [],
        "pqc_plan": [],
        "anomalies": [],
        "explanation": "",
        "report": {}
    }

    # ============================================
    # 4️⃣ Parse AI results
    # ============================================
    for r in ai_results:
        try:
            parsed = json.loads(r.result_data) if r.result_data else None
        except:
            parsed = r.result_data

        if r.result_type == "attack_simulation":
            if isinstance(parsed, list):
                seen = set()

                for item in parsed:
                    key = (item.get("name"), item.get("target"))

                    if key in seen:
                        continue
                    seen.add(key)

                    details = item.get("details", {}) or {}

                    data["attack_simulation"].append({
                        "title": item.get("name") or "Attack Simulation",

                        # ✅ severity mapping
                        "severity": (   
                            details.get("risk")
                            or item.get("risk")
                            or "LOW"
                        ).upper(),

                        # ✅ description mapping
                        "description": (
                            details.get("description")
                            or details.get("reason")
                            or item.get("type")
                            or "No description available"
                        ),

                        # ✅ technique
                        "technique": item.get("type") or "-",

                        # ✅ target
                        "target": item.get("target") or "-",

                        # ✅ impact mapping
                        "impact": (
                            details.get("quantum_impact")
                            or details.get("description")
                            or "-"
                        ),

                        "details": details
                    })

        elif r.result_type == "recommendations":

            # ============================================
            # ✅ HANDLE STRING CASE (FULL STRING RESPONSE)
            # ============================================
            if isinstance(parsed, str):
                parsed = [{"description": parsed}]

            if isinstance(parsed, list):

                seen = set()

                for raw_item in parsed:

                    # ============================================
                    # ✅ HANDLE STRING ITEM
                    # ============================================
                    if isinstance(raw_item, str):
                        item = {"description": raw_item}
                    else:
                        item = raw_item or {}

                    details = item.get("details", {}) or {}

                    key = (
                        item.get("title") or item.get("name") or item.get("description"),
                        details.get("description")
                    )

                    if key in seen:
                        continue
                    seen.add(key)

                    data["recommendations"].append({
                        "title": (
                            item.get("title")
                            or item.get("name")
                            or "Security Recommendation"
                        ),

                        "priority": (
                            details.get("priority")
                            or item.get("priority")
                            or "MEDIUM"
                        ).upper(),

                        "description": (
                            details.get("description")
                            or details.get("reason")
                            or item.get("description")
                            or "Improve cryptographic security posture"
                        ),

                        "owner": (
                            details.get("owner")
                            or item.get("owner")
                            or None
                        ),

                        "details": details
                    })

        elif r.result_type == "attack_paths":
            if isinstance(parsed, list):

                seen = set()

                def make_hashable(value):
                    if value is None:
                        return None

                    if isinstance(value, list):
                        return " → ".join(map(str, value))

                    if isinstance(value, dict):
                        return None

                    return str(value)

                for item in parsed:

                    details = item.get("details", {}) or {}

                    raw_source = item.get("source")
                    raw_target = item.get("target")
                    raw_path = item.get("path")

                    source_val = make_hashable(raw_source)
                    target_val = make_hashable(raw_target)
                    path_val = make_hashable(raw_path)

                    # ============================================
                    # ✅ CLEAN TARGET (optional improvement)
                    # ============================================
                    if isinstance(raw_target, str) and "|" in raw_target:
                        target_val = raw_target.split("|")[0].strip()

                    # ============================================
                    # ✅ FALLBACK LOGIC (🔥 MAIN FIX)
                    # ============================================
                    if not source_val:
                        source_val = asset or "Entry Point"

                    if not target_val:
                        target_val = (
                            raw_target
                            or details.get("component")
                            or "Target System"
                        )

                    if not path_val:
                        path_val = f"{source_val} → {target_val}"

                    # ============================================
                    # ✅ DEDUPLICATION (AFTER CLEANING)
                    # ============================================
                    key = (source_val, target_val, path_val)

                    if key in seen:
                        continue
                    seen.add(key)

                    # ============================================
                    # ✅ FINAL APPEND
                    # ============================================
                    data["attack_paths"].append({
                        "source": source_val,
                        "target": target_val,
                        "path": path_val,
                        "description": (
                            details.get("description")
                            or item.get("description")
                            or "Potential attack path identified"
                        ),
                        "risk": (
                            details.get("risk")
                            or item.get("risk")
                            or "MEDIUM"
                        ).upper(),
                        "details": details
                    })

        elif r.result_type == "crypto_issues":
            if isinstance(parsed, list):

                seen = set()  # ✅ remove duplicates

                for item in parsed:
                    key = (item.get("name"), item.get("component"))

                    if key in seen:
                        continue
                    seen.add(key)

                    details = item.get("details", {}) or {}

                    data["crypto_issues"].append({
                        "title": item.get("name") or "Crypto Issue",

                        # ✅ severity mapping
                        "severity": (
                            details.get("risk")
                            or item.get("severity")
                            or "LOW"
                        ).upper(),

                        # ✅ description
                        "description": (
                            details.get("description")
                            or details.get("reason")
                            or item.get("type")
                            or "No description available"
                        ),

                        # ✅ affected component
                        "affected_component": (
                            item.get("component")
                            or details.get("component")
                            or item.get("target")
                            or "-"
                        ),

                        # ✅ recommendation
                        "recommendation": (
                            details.get("recommendation")
                            or "Upgrade to quantum-safe algorithms (PQC)"
                        ),

                        "details": details
                    })
                    
        elif r.agent_name == "PQCRecommender" or r.result_type == "pqc_plan":
            if isinstance(parsed, list):

                seen = set()  # ✅ prevent duplicates

                for idx, item in enumerate(parsed):
                    key = item.get("step") or item.get("title") or str(idx)

                    if key in seen:
                        continue
                    seen.add(key)

                    details = item.get("details", {}) or {}

                    data["pqc_plan"].append({
                        # ✅ Step title
                        "step": (
                            item.get("step")
                            or item.get("title")
                            or f"Step {idx + 1}"
                        ),

                        # ✅ Priority
                        "priority": (
                            details.get("priority")
                            or item.get("priority")
                            or "MEDIUM"
                        ).upper(),

                        # ✅ Status
                        "status": (
                            details.get("status")
                            or item.get("status")
                            or "PENDING"
                        ).upper(),

                        # ✅ Description
                        "description": (
                            details.get("description")
                            or item.get("description")
                            or "Migrate to post-quantum cryptography"
                        ),

                        "details": details
                    })

        elif r.result_type == "anomalies":
            if isinstance(parsed, dict):
                data["anomalies"].extend(parsed.get("anomalies", []))

        elif r.result_type == "explanation":

            # ============================================
            # ✅ CASE 1: RAW STRING
            # ============================================
            if isinstance(parsed, str):
                data["explanation"] = parsed.strip()

            # ============================================
            # ✅ CASE 2: DICT RESPONSE (MOST COMMON)
            # ============================================
            elif isinstance(parsed, dict):

                explanation_parts = []

                # --------------------------------------------
                # 🔥 PRIORITY 1: HANDLE "value" (YOUR MAIN CASE)
                # --------------------------------------------
                if parsed.get("value"):
                    data["explanation"] = str(parsed.get("value")).strip()
                    continue  # ✅ skip further processing

                # --------------------------------------------
                # 🔥 PRIORITY 2: HANDLE "text"
                # --------------------------------------------
                if parsed.get("text"):
                    explanation_parts.append(str(parsed.get("text")).strip())

                # --------------------------------------------
                # 🔥 STRUCTURED FIELDS
                # --------------------------------------------
                if parsed.get("summary"):
                    explanation_parts.append(f"**Summary:**\n{parsed.get('summary')}")

                if parsed.get("risk_reason"):
                    explanation_parts.append(f"**Risk Reason:**\n{parsed.get('risk_reason')}")

                if parsed.get("impact"):
                    explanation_parts.append(f"**Impact:**\n{parsed.get('impact')}")

                if parsed.get("recommendation"):
                    explanation_parts.append(f"**Recommendation:**\n{parsed.get('recommendation')}")

                # --------------------------------------------
                # 🔥 HANDLE LIST VALUES (VERY IMPORTANT)
                # --------------------------------------------
                for key, value in parsed.items():
                    if isinstance(value, list) and value:

                        safe_items = []
                        for v in value:
                            if isinstance(v, dict):
                                safe_items.append(str(v))
                            else:
                                safe_items.append(str(v))

                        explanation_parts.append(
                            f"**{key.replace('_', ' ').title()}:**\n- " + "\n- ".join(safe_items)
                        )

                # --------------------------------------------
                # 🔥 FINAL FALLBACK
                # --------------------------------------------
                if not explanation_parts:
                    explanation_parts.append(str(parsed))

                data["explanation"] = "\n\n".join(explanation_parts)

            # ============================================
            # ✅ CASE 3: UNKNOWN FORMAT
            # ============================================
            else:
                data["explanation"] = str(parsed)
                
    # ============================================
    # AUTO PQC PLAN (if missing)
    # ============================================
    if not data["pqc_plan"]:
        if data.get("pqc_ready") is False:

            data["pqc_plan"] = [
                {
                    "step": "Upgrade TLS to 1.3",
                    "priority": "HIGH",
                    "status": "PENDING",
                    "description": "Older TLS versions are vulnerable to downgrade and quantum attacks"
                },
                {
                    "step": "Replace RSA/ECC with PQC algorithms",
                    "priority": "CRITICAL",
                    "status": "PENDING",
                    "description": "Current encryption is vulnerable to Shor’s algorithm"
                },
                {
                    "step": "Enable Forward Secrecy",
                    "priority": "HIGH",
                    "status": "IN_PROGRESS",
                    "description": "Protect session keys from future compromise"
                }
            ]
            
    # ============================================
    # AUTO ATTACK PATHS (if missing)
    # ============================================
    if not data["attack_paths"]:
        if data.get("pqc_ready") is False:

            data["attack_paths"] = [
                {
                    "source": "Client",
                    "target": "TLS Layer",
                    "path": "Client → TLS1.2 → Weak Cipher",
                    "description": "Weak TLS allows downgrade or interception",
                    "risk": "HIGH"
                },
                {
                    "source": "Attacker",
                    "target": "Encrypted Traffic",
                    "path": "Intercept → Store Now → Decrypt Later",
                    "description": "Harvest Now Decrypt Later (HNDL) quantum attack",
                    "risk": "CRITICAL"
                }
            ]

    # ============================================
    # 5️⃣ Return
    # ============================================
    return {
        "success": True,
        "scan_id": scan_id,
        "source": "current",
        "data": data
    }
    
# ============================================
# 4️⃣ AI AGENTS OVERVIEW
# ============================================
# ============================================
# 4️⃣ AI AGENTS OVERVIEW (FIXED FOR SINGLE ASSET)
# ============================================
@router.get("/ai/agents")
def get_ai_agents(
    scan_id: str,
    asset: str = None,   # ✅ NEW PARAM
    db: Session = Depends(get_db)
):

    # ============================================
    # 1️⃣ BASE QUERY
    # ============================================
    query = db.query(AIAgentResult).filter(
        AIAgentResult.scan_id == scan_id
    )

    # ============================================
    # 2️⃣ FILTER BY ASSET (🔥 MAIN FIX)
    # ============================================
    if asset:
        asset_obj = db.query(AssetRegistry).filter(
            AssetRegistry.asset_identifier == asset
        ).first()

        if asset_obj:
            query = query.filter(AIAgentResult.asset_id == asset_obj.id)
        else:
            return {
                "success": True,
                "scan_id": scan_id,
                "source": "current",
                "data": []
            }

    results = query.all()

    # ============================================
    # 3️⃣ BUILD AGENTS MAP
    # ============================================
    agents_map = {}

    for r in results:
        name = r.agent_name

        if name not in agents_map:
            agents_map[name] = {
                "name": name,
                "status": "COMPLETED",
                "description": f"{name} executed successfully"
            }

        # STATUS LOGIC
        if r.severity:
            if r.severity.upper() == "CRITICAL":
                agents_map[name]["status"] = "FAILED"
            elif r.severity.upper() == "HIGH":
                agents_map[name]["status"] = "WARNING"

    return {
        "success": True,
        "scan_id": scan_id,
        "source": "current",
        "data": list(agents_map.values())
    }
    
# ============================================
# 5️⃣ AI CHATBOT
# ============================================

class ChatRequest(BaseModel):
    message: str


@router.post("/ai/chat")
async def ai_chat(req: ChatRequest):

    response = await generate_ai_response(req.message)

    return {
        "success": True,
        "response": response
    }