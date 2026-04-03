import uuid
from sqlalchemy import Column, String, DateTime, ForeignKey
from sqlalchemy.dialects.postgresql import UUID

from app.db.postgres import Base
from app.models.organization import Organization   # ✅ ADD THIS


class ScanJob(Base):

    __tablename__ = "scan_jobs"

    id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4
    )

    organization_id = Column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id"),
        nullable=False
    )

    scan_type = Column(String)
    trigger = Column(String)

    # 🔥 UPDATED (only change)
    status = Column(String, default="running", index=True)
    
    domain = Column(String)

    started_at = Column(DateTime)
    finished_at = Column(DateTime)