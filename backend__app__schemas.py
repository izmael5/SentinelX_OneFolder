from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, HttpUrl


class TargetCreate(BaseModel):
    name: str = Field(min_length=2, max_length=160)
    kind: Literal['website', 'network'] = 'website'
    url: HttpUrl
    scope_notes: str = Field(min_length=10, max_length=4000)
    authorization_ref: str = Field(min_length=3, max_length=255)


class TargetOut(BaseModel):
    id: str
    name: str
    kind: str
    url: str
    scope_notes: str
    authorization_ref: str
    enabled: bool
    created_at: datetime
    updated_at: datetime

    model_config = {'from_attributes': True}


class ScanCreate(BaseModel):
    target_id: str
    check_family: Literal['safe_web_posture'] = 'safe_web_posture'


class ScanOut(BaseModel):
    id: str
    target_id: str
    status: str
    check_family: str
    summary: str | None
    started_at: datetime | None
    finished_at: datetime | None
    created_at: datetime

    model_config = {'from_attributes': True}


class FindingStatusUpdate(BaseModel):
    status: Literal['open', 'acknowledged', 'resolved']


class ResearchRequest(BaseModel):
    question: str = Field(min_length=8, max_length=4000)
    target_id: str | None = None
