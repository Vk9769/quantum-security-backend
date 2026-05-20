from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from app.db.postgres import get_db
from app.services.report_service import (
    get_reports,
    generate_csv_report
)

from app.models.scan_jobs import ScanJob

router = APIRouter()


# =========================================================
# GET REPORTS
# =========================================================
@router.get("/reports")
def reports(
    db: Session = Depends(get_db)
):

    return get_reports(db)


# =========================================================
# DOWNLOAD CSV REPORT
# =========================================================
@router.get("/reports/download/{scan_id}")
def download_report(
    scan_id: str,
    db: Session = Depends(get_db)
):

    # -----------------------------------------------------
    # GET SCAN
    # -----------------------------------------------------
    scan = db.query(ScanJob).filter(
        ScanJob.id == scan_id
    ).first()

    if not scan:
        raise HTTPException(
            status_code=404,
            detail="Scan not found"
        )

    # -----------------------------------------------------
    # GENERATE CSV
    # -----------------------------------------------------
    csv_file = generate_csv_report(
        db=db,
        scan_id=scan_id
    )

    if not csv_file:
        raise HTTPException(
            status_code=404,
            detail="Report not found"
        )

    # -----------------------------------------------------
    # CREATE VERSION NUMBER PER DOMAIN
    # -----------------------------------------------------
    scans = (
        db.query(ScanJob)
        .filter(ScanJob.domain == scan.domain)
        .order_by(ScanJob.started_at.asc())
        .all()
    )

    version = "v1"

    for index, s in enumerate(scans, start=1):

        if str(s.id) == str(scan.id):
            version = f"v{index}"
            break

    # -----------------------------------------------------
    # FILE NAME
    # -----------------------------------------------------
    filename = (
        f"{scan.domain}"
        f"({version})_assets_list.csv"
    )

    # -----------------------------------------------------
    # RETURN CSV RESPONSE
    # -----------------------------------------------------
    return StreamingResponse(
        iter([csv_file.getvalue()]),
        media_type="text/csv",
        headers={
            "Content-Disposition":
                f'attachment; filename="{filename}"'
        }
    )