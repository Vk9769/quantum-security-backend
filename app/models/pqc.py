import uuid
from sqlalchemy import Column, String, Boolean, ForeignKey
from sqlalchemy.dialects.postgresql import UUID

from app.db.postgres import Base


class PQCAnalysis(Base):

    __tablename__ = "pqc_analysis"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    asset_id = Column(
        UUID(as_uuid=True),
        ForeignKey("asset_registry.id"),
        nullable=False
    )

    algorithm = Column(String)

    pqc_ready = Column(Boolean)

    recommended_upgrade = Column(String)