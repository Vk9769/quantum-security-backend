from app.db.postgres import SessionLocal
from app.models.scan_jobs import ScanJob

# ✅ NEW IMPORT (IN-MEMORY INSTANT CONTROL)
from app.utils.runtime_control import is_stopped, is_paused


def check_scan_control(scan_id):
    """
    NON-BLOCKING + INSTANT scan control:

    Priority:
    1. ⚡ In-memory flags (instant response)
    2. 🗄️ Database fallback (source of truth)

    Returns:
    - "running"  → continue processing
    - "paused"   → worker should wait
    - "stopped"  → terminate scan safely
    """

    # 🔥 Safety check
    if not scan_id or scan_id == "unknown":
        return "stopped"

    # =====================================================
    # ⚡ 1. IN-MEMORY CONTROL (INSTANT RESPONSE)
    # =====================================================
    try:
        if is_stopped(scan_id):
            return "stopped"

        if is_paused(scan_id):
            return "paused"

    except Exception as e:
        print(f"⚠ Runtime control error → {scan_id}: {e}")

    # =====================================================
    # 🗄️ 2. DATABASE FALLBACK
    # =====================================================
    db = SessionLocal()

    try:
        scan = db.query(ScanJob).filter(ScanJob.id == scan_id).first()

        # ❌ If scan not found → treat as stopped
        if not scan:
            return "stopped"

        # ✅ Normalize status
        status = (scan.status or "").lower()

        if status == "running":
            return "running"

        if status == "paused":
            return "paused"

        if status in ["stopped", "completed"]:
            return "stopped"

        # 🔥 Unknown state fallback
        return "stopped"

    except Exception as e:
        print(f"❌ Scan control error → {scan_id}: {e}")
        return "stopped"

    finally:
        db.close()
        
def is_scan_active(scan_id):
    """
    Backward compatibility for old workers.
    Returns:
    - True  → running
    - False → stopped
    - "paused" → paused
    """
    status = check_scan_control(scan_id)

    if status == "running":
        return True

    if status == "paused":
        return "paused"

    return False