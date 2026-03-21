from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import text

from app.db.postgres import get_db

router = APIRouter()


@router.get("/tls-analytics")
def get_tls_analytics(db: Session = Depends(get_db)):
    tls_query = text("""
        SELECT 
            tls_version,
            COUNT(*) AS total
        FROM tls_scan_results
        WHERE tls_version IS NOT NULL
        GROUP BY tls_version
        ORDER BY total DESC
    """)

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

    total_tls = sum(row.total for row in tls_rows) if tls_rows else 0
    total_cipher = sum(row.total for row in cipher_rows) if cipher_rows else 0

    tls_data = [
        {
            "version": row.tls_version,
            "pct": round((row.total * 100.0 / total_tls), 2) if total_tls > 0 else 0
        }
        for row in tls_rows
    ]

    cipher_data = [
        {
            "cipher": row.cipher_suite,
            "pct": round((row.total * 100.0 / total_cipher), 2) if total_cipher > 0 else 0
        }
        for row in cipher_rows
    ]

    return {
        "tlsData": tls_data,
        "cipherData": cipher_data
    }