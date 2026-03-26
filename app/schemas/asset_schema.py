from typing import Optional, List
from pydantic import BaseModel


class AssetResponse(BaseModel):
    id: str
    name: str
    type: str
    domain: str
    ip: str
    port: str
    tls: str
    pqc: str

    class Config:
        from_attributes = True


class AssetSummaryCard(BaseModel):
    label: str
    value: str
    change: str
    icon: str
    positive: bool


class AssetCountsResponse(BaseModel):
    all: int
    domain: int
    subdomain: int
    ssl: int
    ip: int
    software: int