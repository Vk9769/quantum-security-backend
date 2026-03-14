import uuid
from sqlalchemy import Column, Integer, String, ForeignKey
from sqlalchemy.dialects.postgresql import UUID

from app.db.postgres import Base


class AssetRiskScore(Base):

    __tablename__ = "asset_risk_scores"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    asset_id = Column(
        UUID(as_uuid=True),
        ForeignKey("asset_registry.id"),
        nullable=False
    )

    score = Column(Integer)

    risk_category = Column(String)