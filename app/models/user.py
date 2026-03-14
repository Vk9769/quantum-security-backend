from sqlalchemy import Column, String, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
import uuid

from app.db.postgres import Base


class User(Base):

    __tablename__ = "users"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    organization_id = Column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id"),
        nullable=False
    )

    name = Column(String, nullable=False)

    email = Column(String, unique=True, nullable=False)

    role = Column(String, default="employee")

    password_hash = Column(String, nullable=False)