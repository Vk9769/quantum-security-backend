import uuid
from sqlalchemy import Column, String, ForeignKey, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from app.db.postgres import Base


class ScanDelta(Base):
    __tablename__ = "scan_deltas"

    # ----------------------------
    # PRIMARY KEY
    # ----------------------------
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    # ----------------------------
    # RELATIONS
    # ----------------------------
    asset_id = Column(
        UUID(as_uuid=True),
        ForeignKey("asset_registry.id", ondelete="CASCADE"),
        nullable=False
    )

    # ----------------------------
    # DRIFT DATA
    # ----------------------------
    change_type = Column(String, nullable=False)  
    # Example: "New Asset", "New Open Port", "TLS Change"

    change_description = Column(Text, nullable=True)  
    # Example: "api.bank.in → TLS1.2"

    # ----------------------------
    # OPTIONAL (FUTURE READY)
    # ----------------------------
    previous_snapshot = Column(UUID(as_uuid=True), nullable=True)
    current_snapshot = Column(UUID(as_uuid=True), nullable=True)

    # ----------------------------
    # RELATIONSHIP (OPTIONAL)
    # ----------------------------
    asset = relationship("AssetRegistry", backref="drifts")

    # ----------------------------
    # HELPER METHOD (OPTIONAL)
    # ----------------------------
    def to_dict(self):
        return {
            "id": str(self.id),
            "asset_id": str(self.asset_id) if self.asset_id else None,
            "type": self.change_type,
            "detail": self.change_description,
            "previous_snapshot": str(self.previous_snapshot) if self.previous_snapshot else None,
            "current_snapshot": str(self.current_snapshot) if self.current_snapshot else None,
        }