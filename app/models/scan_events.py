import uuid
from sqlalchemy import Column, String, DateTime, ForeignKey
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.sql import func

from app.db.postgres import Base


class ScanEvent(Base):

    __tablename__ = "scan_events"

    id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4
    )

    scan_id = Column(
        UUID(as_uuid=True),
        ForeignKey("scan_jobs.id"),
        nullable=False
    )

    event_type = Column(String)

    event_data = Column(JSONB)

    timestamp = Column(
        DateTime,
        default=func.now()
    )