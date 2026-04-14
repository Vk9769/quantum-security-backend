import uuid
from sqlalchemy import Column, Text, Float, TIMESTAMP, ForeignKey
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.sql import func

from app.db.postgres import Base


class AIAgentResult(Base):
    __tablename__ = "ai_agent_results"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    scan_id = Column(UUID(as_uuid=True), ForeignKey("scan_jobs.id"))
    asset_id = Column(UUID(as_uuid=True), ForeignKey("asset_registry.id"), nullable=False)

    agent_name = Column(Text, nullable=False)
    result_type = Column(Text, nullable=False)

    severity = Column(Text)
    confidence = Column(Float)

    result_data = Column(JSONB, nullable=False)

    created_at = Column(TIMESTAMP, server_default=func.now())