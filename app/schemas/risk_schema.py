from pydantic import BaseModel


class RiskScoreResponse(BaseModel):
    score: int
    label: str
    change: int


class RiskTierItem(BaseModel):
    label: str
    count: int
    color: str
    textColor: str


class DomainRiskResponse(BaseModel):
    domain: str
    asset_id: str | None
    score: int
    label: str
    change: int
    weak_tls: bool
    tls_version: str | None
    expired_cert: bool
    certificate_expiry: str | None


class DomainRiskTierItem(BaseModel):
    label: str
    count: int
    color: str
    textColor: str