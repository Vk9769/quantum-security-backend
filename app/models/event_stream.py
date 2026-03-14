import uuid
from sqlalchemy import Column, String, DateTime
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.sql import func

from app.db.postgres import Base


class EventStream(Base):

    __tablename__ = "event_stream"

    id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4
    )

    event_type = Column(String)

    payload = Column(JSONB)

    created_at = Column(
        DateTime,
        default=func.now()
    )