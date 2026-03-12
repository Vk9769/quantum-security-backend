import uuid
from sqlalchemy import Column, Text, DateTime
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func

from app.db.postgres import Base


class AssetRegistry(Base):

    __tablename__ = "asset_registry"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    organization_id = Column(UUID(as_uuid=True), nullable=False)

    asset_identifier = Column(Text)

    asset_type = Column(Text)

    first_seen = Column(DateTime, default=func.now())

    last_seen = Column(DateTime, default=func.now())

    status = Column(Text)

    criticality = Column(Text)