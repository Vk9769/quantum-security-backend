from sqlalchemy import Column, String, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
import uuid

from app.db.postgres import Base


# =====================================================
# TOPOLOGY NODE TABLE
# =====================================================

class TopologyNode(Base):
    __tablename__ = "topology_nodes"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    # domain / subdomain / ip / port / cert / email
    node_type = Column(String, nullable=False)

    # actual value like "tesla.com" or "api.tesla.com"
    value = Column(String, nullable=False, index=True)

    # relationships (optional, for ORM use)
    outgoing_edges = relationship(
        "TopologyEdge",
        foreign_keys="TopologyEdge.source_node",
        back_populates="source",
        cascade="all, delete"
    )

    incoming_edges = relationship(
        "TopologyEdge",
        foreign_keys="TopologyEdge.target_node",
        back_populates="target",
        cascade="all, delete"
    )

    def __repr__(self):
        return f"<TopologyNode(type={self.node_type}, value={self.value})>"


# =====================================================
# TOPOLOGY EDGE TABLE
# =====================================================

class TopologyEdge(Base):
    __tablename__ = "topology_edges"

    source_node = Column(
        UUID(as_uuid=True),
        ForeignKey("topology_nodes.id", ondelete="CASCADE"),
        primary_key=True
    )

    target_node = Column(
        UUID(as_uuid=True),
        ForeignKey("topology_nodes.id", ondelete="CASCADE"),
        primary_key=True
    )

    relation_type = Column(String, nullable=True)

    # relationships
    source = relationship(
        "TopologyNode",
        foreign_keys=[source_node],
        back_populates="outgoing_edges"
    )

    target = relationship(
        "TopologyNode",
        foreign_keys=[target_node],
        back_populates="incoming_edges"
    )

    def __repr__(self):
        return f"<Edge({self.source_node} -> {self.target_node})>"