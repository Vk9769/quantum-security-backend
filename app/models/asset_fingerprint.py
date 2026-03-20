import uuid
from sqlalchemy import Column, Text, DateTime, ForeignKey, Float, func
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship

from app.db.postgres import Base


class AssetFingerprint(Base):
    __tablename__ = "asset_fingerprints"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    asset_id = Column(
        UUID(as_uuid=True),
        ForeignKey("asset_registry.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )

    hosting_provider = Column(Text, nullable=True)
    cloud_provider = Column(Text, nullable=True)
    region = Column(Text, nullable=True)

    web_server = Column(Text, nullable=True)
    web_server_detection_method = Column(Text, nullable=True)
    backend_stack = Column(Text, nullable=True)
    framework = Column(Text, nullable=True)
    cms = Column(Text, nullable=True)

    waf_cdn = Column(Text, nullable=True)
    dns_provider = Column(Text, nullable=True)
    email_provider = Column(Text, nullable=True)
    load_balancer = Column(Text, nullable=True)

    os_hint = Column(Text, nullable=True)
    deployment_type = Column(Text, nullable=True)
    reverse_dns = Column(Text, nullable=True)

    asn = Column(Text, nullable=True)
    org_name = Column(Text, nullable=True)

    confidence_score = Column(Float, nullable=True)

    raw_headers = Column(JSONB, nullable=True)
    raw_dns = Column(JSONB, nullable=True)
    raw_tls = Column(JSONB, nullable=True)
    raw_whois = Column(JSONB, nullable=True)

    web_server_candidates = Column(JSONB, nullable=True)
    passive_technology_matches = Column(JSONB, nullable=True)
    http_observations = Column(JSONB, nullable=True)
    favicon_hash = Column(JSONB, nullable=True)
    behavioral_fingerprint = Column(JSONB, nullable=True)
    evidence_summary = Column(JSONB, nullable=True)
    external_exposure_summary = Column(JSONB, nullable=True)

    detected_at = Column(
        DateTime(timezone=False),
        nullable=False,
        server_default=func.current_timestamp()
    )

    asset = relationship(
        "AssetRegistry",
        back_populates="fingerprints"
    )