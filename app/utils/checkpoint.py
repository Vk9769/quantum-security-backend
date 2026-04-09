from app.db.postgres import SessionLocal
from sqlalchemy.sql import text
from datetime import datetime
import json
import logging

logger = logging.getLogger("Checkpoint")


def save_checkpoint(scan_id, stage, last_asset=None, last_event=None, meta=None):
    db = SessionLocal()
    try:
        # ✅ Ensure meta is always JSON-safe
        if isinstance(meta, dict):
            try:
                meta = json.dumps(meta)
            except Exception:
                meta = "{}"

        db.execute(text("""
            INSERT INTO scan_checkpoints (scan_id, stage, last_asset, last_event, meta, updated_at)
            VALUES (:scan_id, :stage, :last_asset, :last_event, :meta, :updated_at)
            ON CONFLICT (scan_id)
            DO UPDATE SET
                stage = EXCLUDED.stage,
                last_asset = EXCLUDED.last_asset,
                last_event = EXCLUDED.last_event,
                meta = EXCLUDED.meta,
                updated_at = EXCLUDED.updated_at
        """), {
            "scan_id": scan_id,
            "stage": stage,
            "last_asset": last_asset,
            "last_event": last_event,
            "meta": meta,
            "updated_at": datetime.utcnow()
        })

        db.commit()

    except Exception as e:
        db.rollback()
        logger.error(f"❌ Failed to save checkpoint → {scan_id}")
        logger.error(e)

    finally:
        db.close()


def get_checkpoint(scan_id):
    db = SessionLocal()
    try:
        result = db.execute(text("""
            SELECT * FROM scan_checkpoints WHERE scan_id = :scan_id
        """), {"scan_id": scan_id}).fetchone()

        if not result:
            return None

        data = dict(result._mapping)

        # ✅ Ensure meta is always dict
        meta = data.get("meta")

        if meta:
            if isinstance(meta, str):
                try:
                    data["meta"] = json.loads(meta)
                except Exception:
                    data["meta"] = {}
        else:
            data["meta"] = {}

        return data

    except Exception as e:
        logger.error(f"❌ Failed to fetch checkpoint → {scan_id}")
        logger.error(e)
        return None

    finally:
        db.close()