from fastapi import APIRouter
from datetime import datetime

router = APIRouter()


@router.get("/reports")
def get_reports():

    return [
        {
            "name": "Weekly Security Posture",
            "date": "2026-03-04",
            "type": "PDF",
            "url": "/static/reports/security_posture.pdf"
        },
        {
            "name": "PQC Compliance Audit",
            "date": "2026-03-01",
            "type": "PDF",
            "url": "/static/reports/pqc_audit.pdf"
        },
        {
            "name": "TLS Configuration Report",
            "date": "2026-02-28",
            "type": "CSV",
            "url": "/static/reports/tls_report.csv"
        },
        {
            "name": "Asset Inventory Export",
            "date": "2026-02-25",
            "type": "CSV",
            "url": "/static/reports/assets.csv"
        }
    ]