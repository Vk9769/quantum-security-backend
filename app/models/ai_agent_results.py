from sqlalchemy import Column, String, Text, ForeignKey, DateTime
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func
import uuid

from app.db.postgres import Base


class AIAgentResult(Base):
    __tablename__ = "ai_agent_results"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    scan_id = Column(UUID(as_uuid=True), nullable=True)

    asset_id = Column(UUID(as_uuid=True), ForeignKey("asset_registry.id"))

    agent_name = Column(String, nullable=False)
    
    result_type = Column(String, nullable=False)

    result_data = Column(Text, nullable=True)

    severity = Column(String, nullable=True)

    confidence = Column(String, nullable=True)

    # ✅ ADD THIS (VERY IMPORTANT)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)