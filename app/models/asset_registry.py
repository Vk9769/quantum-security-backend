import uuid
from sqlalchemy import Column, Text, DateTime, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func

from app.db.postgres import Base


class AssetRegistry(Base):
    __tablename__ = "asset_registry"

    __table_args__ = (
        UniqueConstraint("asset_identifier", name="uq_asset_registry_asset_identifier"),
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id = Column(UUID(as_uuid=True), nullable=False)

    asset_identifier = Column(Text, nullable=False)
    asset_type = Column(Text, nullable=True)

    first_seen = Column(DateTime, default=func.now())
    last_seen = Column(DateTime, default=func.now())

    status = Column(Text, nullable=True)
    criticality = Column(Text, nullable=True)