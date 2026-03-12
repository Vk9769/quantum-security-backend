from sqlalchemy import Column, String, Text, ForeignKey, DateTime
from sqlalchemy.dialects.postgresql import UUID, INET
from sqlalchemy.sql import func
import uuid

from app.db.postgres import Base


class Domain(Base):

    __tablename__ = "domains"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    organization_id = Column(UUID(as_uuid=True), nullable=True)

    domain_name = Column(Text, unique=True, nullable=False)


class Subdomain(Base):

    __tablename__ = "subdomains"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    domain_id = Column(
        UUID(as_uuid=True),
        ForeignKey("domains.id", ondelete="CASCADE"),
        nullable=False
    )

    subdomain = Column(Text, nullable=False)

    ip_address = Column(INET)

    last_seen = Column(DateTime, default=func.now())