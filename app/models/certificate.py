import uuid
from sqlalchemy import Column, String, Integer, Date, ForeignKey
from sqlalchemy.dialects.postgresql import UUID

from app.db.postgres import Base


class Certificate(Base):

    __tablename__ = "certificates"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    asset_id = Column(
        UUID(as_uuid=True),
        ForeignKey("asset_registry.id"),
        nullable=False
    )

    issuer = Column(String)

    subject = Column(String)

    signature_algorithm = Column(String)

    key_size = Column(Integer)

    expiry_date = Column(Date)