from fastapi import APIRouter
from datetime import datetime
import os
from sqlalchemy import text

# ROUTES
from app.api.v1.auth_routes import router as auth_router
from app.api.v1.employee_routes import router as employee_router
from app.api.v1.asset_routes import router as asset_router
from app.api.v1.tls_routes import router as tls_router
from app.api.v1.risk_routes import router as risk_router
from app.api.v1.pqc_routes import router as pqc_router
from app.api.v1.topology_routes import router as topology_router
from app.api.v1.report_routes import router as report_router
from app.api.v1.scan_routes import router as scan_router
from app.api.v1.tls_analytics import router as tls_analytics_router
from app.api.v1.otp_routes import router as otp_router
from app.api.v1.drift_routes import router as drift_router
from app.api.v1.cbom_routes import router as cbom_router
from app.api.v1.certificate_map_routes import router as certificate_map_router
from app.api.v1.scan_history_routes import router as scan_history_router

# SERVICES
from app.db.postgres import engine
from app.db.redis import redis_client

router = APIRouter()

# ============================================
# HEALTH CHECK
# ============================================

@router.get("/health", tags=["System"])
def health():
    return {
        "status": "running",
        "service": "Quantum Security Scanner",
        "services": {
            "postgresql": "running",
            "redis": "running",
            "kafka": "running",
            "neo4j": "running"
        },
        "timestamp": datetime.utcnow().isoformat()
    }

# ============================================
# SYSTEM INFO
# ============================================

@router.get("/system/info", tags=["System"])
def system_info():
    return {
        "service_name": "Quantum Security Scanner",
        "version": "1.0",
        "environment": os.getenv("ENVIRONMENT", "development"),
        "timestamp": datetime.utcnow()
    }

# ============================================
# DATABASE STATUS
# ============================================

@router.get("/system/db-status", tags=["System"])
def db_status():
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))

        return {
            "database": "PostgreSQL",
            "status": "connected"
        }

    except Exception as e:
        return {
            "database": "PostgreSQL",
            "status": "error",
            "message": str(e)
        }

# ============================================
# REDIS STATUS
# ============================================

@router.get("/system/redis-status", tags=["System"])
def redis_status():
    try:
        redis_client.ping()
        return {"redis": "connected"}

    except Exception as e:
        return {
            "redis": "error",
            "message": str(e)
        }

# ============================================
# SERVICES STATUS
# ============================================

@router.get("/system/services", tags=["System"])
def services_status():
    return {
        "status": "running",
        "service": "Quantum Security Scanner",
        "services": {
            "postgresql": "running",
            "redis": "running",
            "kafka": "running",
            "neo4j": "running",
            "clickhouse": "running",
            "elasticsearch": "running"
        },
        "timestamp": datetime.utcnow().isoformat()
    }

# ============================================
# ROUTER REGISTRATION
# ============================================

router.include_router(auth_router, prefix="/auth", tags=["Authentication"])
router.include_router(employee_router, prefix="/employees", tags=["Employees"])
router.include_router(asset_router, tags=["Assets"])
router.include_router(tls_router, tags=["TLS Scanner"])
router.include_router(tls_analytics_router, tags=["TLS Analytics"])
router.include_router(risk_router, tags=["Risk Engine"])
router.include_router(pqc_router, tags=["PQC Compliance"])
router.include_router(topology_router, prefix="/topology", tags=["Topology"])
router.include_router(report_router, tags=["Reports"])
router.include_router(scan_router, prefix="/scan", tags=["Scanner"])
router.include_router(otp_router, prefix="/otp", tags=["OTP"])
router.include_router(drift_router, prefix="/drift", tags=["Drift"])
router.include_router(cbom_router, prefix="/cbom", tags=["CBOM"])
router.include_router(certificate_map_router, prefix="/map", tags=["Map"])
router.include_router(scan_history_router, tags=["Scan History"])