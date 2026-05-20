import csv
import io

from sqlalchemy.orm import Session

from app.models.asset import Domain, Subdomain
from app.models.asset_registry import AssetRegistry
from app.models.scan import PortScanResult
from app.models.pqc import PQCAnalysis
from app.models.scan_jobs import ScanJob
from app.models.tls import TLSScanResult


# =========================================================
# GET REPORTS LIST
# =========================================================
def get_reports(db: Session):

    scans = (
        db.query(ScanJob)
        .order_by(ScanJob.started_at.asc())
        .all()
    )

    reports = []

    # -----------------------------------------------------
    # DOMAIN VERSION TRACKER
    # -----------------------------------------------------
    domain_versions = {}

    for scan in scans:

        domain = scan.domain or "unknown"

        # -------------------------------------------------
        # CREATE VERSION PER DOMAIN
        # -------------------------------------------------
        if domain not in domain_versions:
            domain_versions[domain] = 1
        else:
            domain_versions[domain] += 1

        version = f"v{domain_versions[domain]}"

        reports.append({
            "id": str(scan.id),
            "name": domain,
            "date": (
                scan.started_at.isoformat()
                if scan.started_at
                else ""
            ),
            "type": "CSV",
            "url": f"/reports/download/{scan.id}",
            "version": version,
            "file_name": f"{domain}({version})_assets_list.csv"
        })

    # -----------------------------------------------------
    # LATEST FIRST
    # -----------------------------------------------------
    reports.reverse()

    return reports


# =========================================================
# GENERATE CSV REPORT
# =========================================================
def generate_csv_report(
    db: Session,
    scan_id: str
):

    # -----------------------------------------------------
    # GET SCAN
    # -----------------------------------------------------
    scan = db.query(ScanJob).filter(
        ScanJob.id == scan_id
    ).first()

    if not scan:
        return None

    # -----------------------------------------------------
    # GET DOMAIN
    # -----------------------------------------------------
    domain = db.query(Domain).filter(
        Domain.domain_name == scan.domain
    ).first()

    if not domain:
        return None

    # -----------------------------------------------------
    # GET SUBDOMAINS
    # -----------------------------------------------------
    subdomains = db.query(Subdomain).filter(
        Subdomain.domain_id == domain.id
    ).all()

    # -----------------------------------------------------
    # CREATE CSV IN MEMORY
    # -----------------------------------------------------
    output = io.StringIO()

    writer = csv.writer(output)

    # -----------------------------------------------------
    # HEADER
    # -----------------------------------------------------
    writer.writerow([
        "Subdomain",
        "Domain",
        "Status",
        "Discovery Type",
        "IP Address",
        "Port",
        "TLS Version",
        "PQC Status"
    ])

    # -----------------------------------------------------
    # ADD ROWS
    # -----------------------------------------------------
    for sub in subdomains:

        asset = db.query(AssetRegistry).filter(
            AssetRegistry.asset_identifier == sub.subdomain
        ).first()

        port = "-"
        tls_version = "-"
        pqc_status = "PQC Not Ready"
        status = "Inactive"

        # ALWAYS AUTOMATIC
        discovery_type = "Automatic"

        if asset:

            # -------------------------------------------------
            # STATUS
            # -------------------------------------------------
            if asset.status:
                status = asset.status.capitalize()
            else:
                status = "Active"

            # -------------------------------------------------
            # GET PORT
            # -------------------------------------------------
            port_row = (
                db.query(PortScanResult)
                .filter(PortScanResult.asset_id == asset.id)
                .order_by(PortScanResult.scan_time.desc())
                .first()
            )

            if port_row and port_row.port:
                port = str(port_row.port)

            # -------------------------------------------------
            # GET TLS VERSION
            # -------------------------------------------------
            tls_row = (
                db.query(TLSScanResult)
                .filter(TLSScanResult.asset_id == asset.id)
                .order_by(TLSScanResult.scan_time.desc())
                .first()
            )

            if tls_row and tls_row.tls_version:
                tls_version = tls_row.tls_version

            # -------------------------------------------------
            # GET PQC
            # -------------------------------------------------
            pqc = (
                db.query(PQCAnalysis)
                .filter(PQCAnalysis.asset_id == asset.id)
                .order_by(PQCAnalysis.id.desc())
                .first()
            )

            if pqc:
                pqc_status = (
                    "PQC Ready"
                    if pqc.pqc_ready
                    else "PQC Not Ready"
                )

        # -----------------------------------------------------
        # WRITE ROW
        # -----------------------------------------------------
        writer.writerow([
            sub.subdomain,
            domain.domain_name,
            status,
            discovery_type,
            str(sub.ip_address) if sub.ip_address else "-",
            port,
            tls_version,
            pqc_status
        ])

    output.seek(0)

    return output