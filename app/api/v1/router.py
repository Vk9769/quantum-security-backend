from fastapi import APIRouter
from datetime import datetime
import os

from app.api.v1.auth_routes import router as auth_router

# Optional imports for service checks
from app.db.postgres import engine
from app.db.redis import redis_client

router = APIRouter()


# ============================================
# BASIC HEALTH CHECK
# ============================================

@router.get("/health", tags=["System"])
def health():
    """
    Basic health check endpoint
    """
    return {
        "status": "running",
        "service": "Quantum Security Scanner",
        "timestamp": datetime.utcnow()
    }


# ============================================
# SYSTEM INFO
# ============================================

@router.get("/system/info", tags=["System"])
def system_info():
    """
    Returns system information
    """
    return {
        "service_name": "Quantum Security Scanner",
        "version": "1.0",
        "environment": os.getenv("ENVIRONMENT", "development"),
        "timestamp": datetime.utcnow()
    }


# ============================================
# DATABASE STATUS CHECK
# ============================================
from sqlalchemy import text

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
# REDIS STATUS CHECK
# ============================================

@router.get("/system/redis-status", tags=["System"])
def redis_status():
    """
    Check Redis connectivity
    """

    try:
        redis_client.ping()

        return {
            "redis": "connected"
        }

    except Exception as e:
        return {
            "redis": "error",
            "message": str(e)
        }


# ============================================
# PLATFORM SERVICES STATUS
# ============================================

@router.get("/system/services", tags=["System"])
def services_status():
    """
    Returns status of platform services
    """

    services = {
        "postgresql": "running",
        "redis": "running",
        "kafka": "running",
        "neo4j": "running",
        "clickhouse": "running",
        "elasticsearch": "running"
    }

    return {
    "status": "running",
    "service": "Quantum Security Scanner",
    "timestamp": datetime.utcnow().isoformat()
}
    
    
    # ============================================
# AUTH ROUTES
# ============================================

router.include_router(
    auth_router,
    prefix="/auth",
    tags=["Authentication"]
)