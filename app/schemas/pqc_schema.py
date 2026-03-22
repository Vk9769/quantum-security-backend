from pydantic import BaseModel
from typing import List, Optional
from uuid import UUID


class PQCSummaryItem(BaseModel):
    label: str
    value: str
    color: str


class PQCClassificationItem(BaseModel):
    label: str
    value: int
    color: str


class PQCStatusItem(BaseModel):
    label: str
    value: int
    color: str


class PQCAssetItem(BaseModel):
    asset_id: UUID
    name: str
    ip: Optional[str] = None
    support: bool
    tls_version: Optional[str] = None
    key_exchange: Optional[str] = None
    quantum_risk: Optional[str] = None


class PQCAppDetails(BaseModel):
    asset_id: Optional[UUID] = None
    name: str
    owner: Optional[str] = None
    exposure: Optional[str] = None
    tls: Optional[str] = None
    score: Optional[int] = None
    risk_label: Optional[str] = None
    status: Optional[str] = None
    ip: Optional[str] = None
    pqc_support: Optional[bool] = None
    key_exchange: Optional[str] = None
    quantum_risk: Optional[str] = None
    criticality: Optional[str] = None
    environment: Optional[str] = None
    cloud_provider: Optional[str] = None
    region: Optional[str] = None
    algorithm: Optional[str] = None
    recommended_upgrade: Optional[str] = None


class PQCDashboardResponse(BaseModel):
    summary_stats: List[PQCSummaryItem]
    classification_data: List[PQCClassificationItem]
    application_status: List[PQCStatusItem]
    assets: List[PQCAssetItem]
    recommendations: List[str]
    app_details: Optional[PQCAppDetails] = None