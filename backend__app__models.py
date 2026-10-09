from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, Numeric, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from .db import Base


def now_utc() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def new_id() -> str:
    return str(uuid4())


class Target(Base):
    __tablename__ = 'targets'
    __table_args__ = (Index('idx_targets_enabled', 'enabled'),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(160))
    kind: Mapped[str] = mapped_column(String(32), default='website')
    url: Mapped[str] = mapped_column(String(2048))
    scope_notes: Mapped[str] = mapped_column(Text)
    authorization_ref: Mapped[str] = mapped_column(String(255))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now_utc)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=now_utc, onupdate=now_utc)


class ScanJob(Base):
    __tablename__ = 'scan_jobs'
    __table_args__ = (Index('idx_scan_created', 'created_at'), Index('idx_scan_target', 'target_id'))

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    target_id: Mapped[str] = mapped_column(ForeignKey('targets.id'))
    status: Mapped[str] = mapped_column(String(32), default='queued')
    check_family: Mapped[str] = mapped_column(String(64), default='safe_web_posture')
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now_utc)


class Finding(Base):
    __tablename__ = 'findings'
    __table_args__ = (Index('idx_finding_status', 'status'), Index('idx_finding_severity', 'severity'))

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    target_id: Mapped[str] = mapped_column(ForeignKey('targets.id'))
    scan_job_id: Mapped[str | None] = mapped_column(ForeignKey('scan_jobs.id'), nullable=True)
    title: Mapped[str] = mapped_column(String(255))
    severity: Mapped[str] = mapped_column(String(16))
    confidence: Mapped[str] = mapped_column(String(16))
    status: Mapped[str] = mapped_column(String(24), default='open')
    evidence: Mapped[str] = mapped_column(Text)
    remediation: Mapped[str] = mapped_column(Text)
    risk_score: Mapped[float] = mapped_column(Numeric(6, 2), default=0)
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=now_utc)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=now_utc)


class AuditEvent(Base):
    __tablename__ = 'audit_events'
    __table_args__ = (Index('idx_audit_created', 'created_at'), Index('idx_audit_target', 'target_id'))

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    event_type: Mapped[str] = mapped_column(String(64))
    actor: Mapped[str] = mapped_column(String(255))
    target_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    detail: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now_utc)
