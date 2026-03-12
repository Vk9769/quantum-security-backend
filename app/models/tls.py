import uuid
from sqlalchemy import Column, String, Boolean, DateTime, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from datetime import datetime

from app.db.postgres import Base


class TLSScanResult(Base):

    __tablename__ = "tls_scan_results"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    asset_id = Column(
        UUID(as_uuid=True),
        ForeignKey("asset_registry.id"),
        nullable=False
    )

    tls_version = Column(String)

    cipher_suite = Column(String)

    key_exchange = Column(String)

    forward_secrecy = Column(Boolean)

    scan_time = Column(DateTime, default=datetime.utcnow)