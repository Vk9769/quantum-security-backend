import uuid
from sqlalchemy import Column, String, DateTime
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func

from app.db.postgres import Base


class Organization(Base):

    __tablename__ = "organizations"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    name = Column(String(255), nullable=False)

    industry = Column(String(100))

    country = Column(String(100))

    created_at = Column(DateTime, default=func.now())