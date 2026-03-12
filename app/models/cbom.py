import uuid
from sqlalchemy import Column, String, ForeignKey
from sqlalchemy.dialects.postgresql import UUID

from app.db.postgres import Base


class CBOMInventory(Base):

    __tablename__ = "cbom_inventory"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    asset_id = Column(
        UUID(as_uuid=True),
        ForeignKey("asset_registry.id"),
        nullable=False
    )

    tls_version = Column(String)

    cipher_suite = Column(String)

    key_exchange = Column(String)

    certificate_id = Column(
        UUID(as_uuid=True),
        ForeignKey("certificates.id")
    )

    quantum_risk = Column(String)