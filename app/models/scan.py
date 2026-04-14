import uuid
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey
from sqlalchemy.dialects.postgresql import UUID

from app.db.postgres import Base


class PortScanResult(Base):

    __tablename__ = "port_scan_results"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    asset_id = Column(
        UUID(as_uuid=True),
        ForeignKey("asset_registry.id"),
        nullable=False
    )

    port = Column(Integer)

    protocol = Column(String)

    state = Column(String)

    scan_time = Column(DateTime)


# ✅ ADDED THIS CLASS (no changes above)
class ScanSnapshot(Base):

    __tablename__ = "scan_snapshots"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    scan_id = Column(
        UUID(as_uuid=True),
        ForeignKey("scan_jobs.id"),
        nullable=False
    )

    asset_id = Column(
        UUID(as_uuid=True),
        ForeignKey("asset_registry.id"),
        nullable=False
    )

    snapshot_time = Column(DateTime)