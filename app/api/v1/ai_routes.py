from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func
import json

def parse_json_safe(value):
    try:
        return json.loads(value) if value else None
    except:
        return value

from app.db.postgres import get_db
from app.models.ai_agent_results import AIAgentResult
from app.models.asset_registry import AssetRegistry

router = APIRouter()

# ============================================
# 1️⃣ AI SUMMARY
# ============================================
@router.get("/ai/summary")
def get_ai_summary(scan_id: str = None, domain: str = None, db: Session = Depends(get_db)):

    query = db.query(AIAgentResult)

    if scan_id:
        query = query.filter(AIAgentResult.scan_id == scan_id)

    total_assets = db.query(AssetRegistry).count()

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

    results = db.query(AIAgentResult, AssetRegistry).join(
        AssetRegistry, AIAgentResult.asset_id == AssetRegistry.id
    ).filter(AIAgentResult.scan_id == scan_id).all()

    assets_map = {}

    for r, asset in results:
        key = asset.id

        if key not in assets_map:
            assets_map[key] = {
                "asset_id": str(asset.id),
                "asset": asset.asset_identifier,
                "risk_score": 0,
                "risk_level": "LOW",
                "pqc_ready": True,
                "simulation_count": 0,
                "recommendations_count": 0,
                "crypto_issue_count": 0
            }

        if r.result_type == "attack_simulation":
            assets_map[key]["simulation_count"] += 1

        if r.result_type == "recommendations":
            assets_map[key]["recommendations_count"] += 1

        if r.result_type == "crypto_issues":
            assets_map[key]["crypto_issue_count"] += 1

    return {
        "success": True,
        "scan_id": scan_id,
        "source": "current",
        "data": list(assets_map.values())
    }


# ============================================
# 3️⃣ AI ASSET DETAILS
# ============================================
@router.get("/ai/asset-details")
def get_ai_asset_details(scan_id: str, asset: str, db: Session = Depends(get_db)):

    asset_obj = db.query(AssetRegistry).filter(
        AssetRegistry.asset_identifier == asset
    ).first()

    if not asset_obj:
        return {"success": False, "data": None}

    results = db.query(AIAgentResult).filter(
        AIAgentResult.asset_id == asset_obj.id,
        AIAgentResult.scan_id == scan_id
    ).all()

    data = {
        "asset": asset,
        "attack_simulation": [],
        "recommendations": [],
        "attack_paths": [],
        "crypto_issues": [],
        "anomalies": [],
        "explanation": "",
        "report": {}
    }

    for r in results:
        try:
            parsed = json.loads(r.result_data) if r.result_data else None
        except:
            parsed = r.result_data

        if r.result_type == "attack_simulation":
            if isinstance(parsed, list):
                data["attack_simulation"].extend(parsed)

        elif r.result_type == "recommendations":
            if isinstance(parsed, list):
                data["recommendations"].extend([
                    {"title": item, "description": item, "priority": "MEDIUM"}
                    if isinstance(item, str) else item
                    for item in parsed
                ])

        elif r.result_type == "attack_paths":
            if isinstance(parsed, list):
                data["attack_paths"].extend(parsed)

        elif r.result_type == "crypto_issues":
            if isinstance(parsed, list):
                data["crypto_issues"].extend(parsed)

        elif r.result_type == "anomalies":
            if isinstance(parsed, dict):
                data["anomalies"].extend(parsed.get("anomalies", []))

        elif r.result_type == "explanation":
            if isinstance(parsed, dict):
                data["explanation"] = parsed.get("text", "")

    return {
        "success": True,
        "scan_id": scan_id,
        "source": "current",
        "data": data
    }
    
# ============================================
# 4️⃣ AI AGENTS OVERVIEW
# ============================================
@router.get("/ai/agents")
def get_ai_agents(scan_id: str, db: Session = Depends(get_db)):

    results = db.query(AIAgentResult).filter(
        AIAgentResult.scan_id == scan_id
    ).all()

    agents_map = {}

    for r in results:
        name = r.agent_name

        if name not in agents_map:
            agents_map[name] = {
                "name": name,
                "status": "COMPLETED",
                "description": f"{name} executed successfully"
            }

        # Improve status based on severity
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