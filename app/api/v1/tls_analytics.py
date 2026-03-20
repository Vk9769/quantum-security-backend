from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import text

from app.db.postgres import get_db

router = APIRouter()


def get_tls_color(version: str) -> str:
    version = (version or "").strip()

    if version == "TLS 1.3":
        return "bg-success"
    elif version == "TLS 1.2":
        return "bg-warning"
    elif version == "TLS 1.1":
        return "bg-destructive/70"
    else:
        return "bg-destructive"


@router.get("/tls-analytics")
def get_tls_analytics(db: Session = Depends(get_db)):
    # -----------------------------
    # Query TLS Version Distribution
    # -----------------------------
    tls_query = text("""
        SELECT 
            tls_version,
            COUNT(*) AS total
        FROM tls_scan_results
        WHERE tls_version IS NOT NULL
        GROUP BY tls_version
        ORDER BY total DESC
    """)

    # -----------------------------
    # Query Cipher Distribution
    # -----------------------------
    cipher_query = text("""
        SELECT 
            cipher_suite,
            COUNT(*) AS total
        FROM tls_scan_results
        WHERE cipher_suite IS NOT NULL
        GROUP BY cipher_suite
        ORDER BY total DESC
    """)

    tls_rows = db.execute(tls_query).fetchall()
    cipher_rows = db.execute(cipher_query).fetchall()

    # -----------------------------
    # Total counts for percentage
    # -----------------------------
    total_tls = sum(row.total for row in tls_rows) if tls_rows else 0
    total_cipher = sum(row.total for row in cipher_rows) if cipher_rows else 0

    # -----------------------------
    # Build TLS Data
    # -----------------------------
    tls_data = []
    for row in tls_rows:
        pct = round((row.total * 100.0 / total_tls), 2) if total_tls > 0 else 0
        tls_data.append({
            "version": row.tls_version,
            "pct": pct,
            "color": get_tls_color(row.tls_version)
        })

    # -----------------------------
    # Build Cipher Data
    # -----------------------------
    cipher_data = []
    for row in cipher_rows:
        pct = round((row.total * 100.0 / total_cipher), 2) if total_cipher > 0 else 0
        cipher_data.append({
            "cipher": row.cipher_suite,
            "pct": pct
        })

    return {
        "tlsData": tls_data,
        "cipherData": cipher_data
    }