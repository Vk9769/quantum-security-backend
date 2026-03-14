from sqlalchemy import Column, String, Boolean, ForeignKey, TIMESTAMP
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func
import uuid

from app.db.postgres import Base


class Employee(Base):

    __tablename__ = "employees"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    organization_id = Column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id"),
        nullable=False
    )

    first_name = Column(String(100), nullable=False)

    last_name = Column(String(100), nullable=False)

    email = Column(String(150), nullable=False)

    password_hash = Column(String, nullable=False)

    role = Column(String(50), default="employee")

    department = Column(String(100))

    phone = Column(String(20))

    is_active = Column(Boolean, default=True)

    created_at = Column(TIMESTAMP, server_default=func.now())