import asyncio
import json
from collections import Counter
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request, WebSocket, WebSocketDisconnect
from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from .db import SessionLocal, get_db
from .ml import assess_risk
from .models import AuditEvent, Finding, ScanJob, Target, now_utc
from .research import build_brief
from .scanner import assess_url
from .schemas import FindingStatusUpdate, ResearchRequest, ScanCreate, ScanOut, TargetCreate, TargetOut
from .security import actor_for, audit, require_enabled_target, validate_target_url

router = APIRouter(prefix='/api')


class EventManager:
    def __init__(self) -> None:
        self.connections: set[WebSocket] = set()
        self.loop: asyncio.AbstractEventLoop | None = None

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        self.loop = asyncio.get_running_loop()
        self.connections.add(websocket)

    def disconnect(self, websocket: WebSocket) -> None:
        self.connections.discard(websocket)

    async def broadcast(self, payload: dict[str, Any]) -> None:
        stale: list[WebSocket] = []
        for connection in list(self.connections):
            try:
                await connection.send_json(payload)
            except Exception:
                stale.append(connection)
        for connection in stale:
            self.disconnect(connection)

    def publish_sync(self, payload: dict[str, Any]) -> None:
        if self.loop and not self.loop.is_closed():
            self.loop.call_soon_threadsafe(asyncio.create_task, self.broadcast(payload))


manager = EventManager()


def event_payload(event_type: str, detail: str, target_id: str | None = None) -> dict[str, Any]:
    return {'type': event_type, 'detail': detail, 'target_id': target_id, 'at': datetime.now(timezone.utc).isoformat()}


def run_scan(job_id: str, target_id: str) -> None:
    db = SessionLocal()
    try:
        job = db.get(ScanJob, job_id)
        target = db.get(Target, target_id)
        if not job or not target or not target.enabled:
            return
        job.status = 'running'
        job.started_at = now_utc()
        db.commit()
        manager.publish_sync(event_payload('scan_started', f'Safe posture assessment started for {target.name}.', target.id))

        observations = assess_url(target.url)
        for observation in observations:
            finding = Finding(
                target_id=target.id,
                scan_job_id=job.id,
                title=observation.title,
                severity=observation.severity,
                confidence=observation.confidence,
                evidence=observation.evidence,
                remediation=observation.remediation,
                risk_score=observation.risk.score,
                status='open',
            )
            db.add(finding)
        job.status = 'completed'
        job.summary = f'{len(observations)} evidence-backed observations recorded.'
        job.finished_at = now_utc()
        db.commit()
        audit(db, 'scan_completed', 'system-worker', job.summary, target.id)
        manager.publish_sync(event_payload('scan_completed', f'{target.name}: {job.summary}', target.id))
    except Exception as exc:
        db.rollback()
        job = db.get(ScanJob, job_id)
        if job:
            job.status = 'failed'
            job.summary = f'Assessment failed safely: {type(exc).__name__}'
            job.finished_at = now_utc()
            db.commit()
        manager.publish_sync(event_payload('scan_failed', f'Scan failed safely: {type(exc).__name__}', target_id))
    finally:
        db.close()


@router.get('/health')
def health() -> dict[str, str]:
    return {'status': 'ok', 'service': 'sentinelx-api'}


@router.get('/overview')
def overview(db: Session = Depends(get_db)) -> dict[str, Any]:
    targets = db.scalar(select(func.count(Target.id))) or 0
    enabled_targets = db.scalar(select(func.count(Target.id)).where(Target.enabled.is_(True))) or 0
    open_findings = db.scalar(select(func.count(Finding.id)).where(Finding.status != 'resolved')) or 0
    completed_scans = db.scalar(select(func.count(ScanJob.id)).where(ScanJob.status == 'completed')) or 0
    severity_rows = db.execute(select(Finding.severity, func.count(Finding.id)).where(Finding.status != 'resolved').group_by(Finding.severity)).all()
    severity = dict(severity_rows)
    latest = db.scalars(select(AuditEvent).order_by(desc(AuditEvent.created_at)).limit(12)).all()
    return {
        'targets': targets,
        'enabled_targets': enabled_targets,
        'open_findings': open_findings,
        'completed_scans': completed_scans,
        'severity': {key: severity.get(key, 0) for key in ('critical', 'high', 'medium', 'low', 'info')},
        'events': [serialize_event(event) for event in latest],
    }


def serialize_event(event: AuditEvent) -> dict[str, Any]:
    return {'id': event.id, 'type': event.event_type, 'actor': event.actor, 'detail': event.detail, 'target_id': event.target_id, 'at': event.created_at.isoformat()}


@router.get('/targets', response_model=list[TargetOut])
def list_targets(db: Session = Depends(get_db)) -> list[Target]:
    return list(db.scalars(select(Target).order_by(desc(Target.updated_at)).limit(100)).all())


@router.post('/targets', response_model=TargetOut, status_code=201)
def create_target(payload: TargetCreate, request: Request, db: Session = Depends(get_db)) -> Target:
    normalized = validate_target_url(str(payload.url))
    target = Target(name=payload.name.strip(), kind=payload.kind, url=normalized, scope_notes=payload.scope_notes.strip(), authorization_ref=payload.authorization_ref.strip())
    db.add(target)
    db.commit()
    db.refresh(target)
    audit(db, 'target_registered', actor_for(request), f'Registered {target.kind} target with explicit authorization reference.', target.id)
    manager.publish_sync(event_payload('target_registered', f'{target.name} is now in the authorized target registry.', target.id))
    return target


@router.patch('/targets/{target_id}/enabled')
def set_target_enabled(target_id: str, enabled: bool, request: Request, db: Session = Depends(get_db)) -> dict[str, Any]:
    target = db.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=404, detail='Target is not registered.')
    target.enabled = enabled
    target.updated_at = now_utc()
    db.commit()
    audit(db, 'target_scope_changed', actor_for(request), f'Target enabled state changed to {enabled}.', target.id)
    manager.publish_sync(event_payload('target_scope_changed', f'{target.name} scope is now {"enabled" if enabled else "disabled"}.', target.id))
    return {'id': target.id, 'enabled': target.enabled}


@router.post('/scan-jobs', response_model=ScanOut, status_code=202)
def create_scan(payload: ScanCreate, request: Request, background_tasks: BackgroundTasks, db: Session = Depends(get_db)) -> ScanJob:
    target = require_enabled_target(db, payload.target_id)
    if target.kind != 'website':
        raise HTTPException(status_code=422, detail='The first scanner supports registered website targets only.')
    job = ScanJob(target_id=target.id, check_family=payload.check_family, status='queued')
    db.add(job)
    db.commit()
    db.refresh(job)
    audit(db, 'scan_queued', actor_for(request), 'Queued a safe, non-destructive website posture assessment.', target.id)
    background_tasks.add_task(run_scan, job.id, target.id)
    manager.publish_sync(event_payload('scan_queued', f'Safe assessment queued for {target.name}.', target.id))
    return job


@router.get('/scan-jobs', response_model=list[ScanOut])
def list_scans(db: Session = Depends(get_db)) -> list[ScanJob]:
    return list(db.scalars(select(ScanJob).order_by(desc(ScanJob.created_at)).limit(50)).all())


@router.get('/findings')
def list_findings(status: str | None = None, db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    query = select(Finding, Target.name.label('target_name')).join(Target, Target.id == Finding.target_id).order_by(desc(Finding.last_seen)).limit(100)
    if status:
        query = query.where(Finding.status == status)
    return [serialize_finding(finding, target_name) for finding, target_name in db.execute(query).all()]


def serialize_finding(finding: Finding, target_name: str) -> dict[str, Any]:
    return {
        'id': finding.id, 'target_id': finding.target_id, 'target_name': target_name, 'title': finding.title,
        'severity': finding.severity, 'confidence': finding.confidence, 'status': finding.status,
        'evidence': finding.evidence, 'remediation': finding.remediation, 'risk_score': float(finding.risk_score),
        'first_seen': finding.first_seen.isoformat(), 'last_seen': finding.last_seen.isoformat(),
    }


@router.patch('/findings/{finding_id}/status')
def update_finding_status(finding_id: str, payload: FindingStatusUpdate, request: Request, db: Session = Depends(get_db)) -> dict[str, str]:
    finding = db.get(Finding, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail='Finding not found.')
    finding.status = payload.status
    finding.last_seen = now_utc()
    db.commit()
    audit(db, 'finding_status_changed', actor_for(request), f'Finding status changed to {payload.status}.', finding.target_id)
    manager.publish_sync(event_payload('finding_status_changed', f'Finding {finding.title} is now {payload.status}.', finding.target_id))
    return {'id': finding.id, 'status': finding.status}


@router.get('/events')
def list_events(db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    return [serialize_event(event) for event in db.scalars(select(AuditEvent).order_by(desc(AuditEvent.created_at)).limit(50)).all()]


@router.post('/research/brief')
def research_brief(payload: ResearchRequest, request: Request, db: Session = Depends(get_db)) -> dict[str, str]:
    context = None
    if payload.target_id:
        target = db.get(Target, payload.target_id)
        if not target:
            raise HTTPException(status_code=404, detail='Research target is not registered.')
        context = f'{target.name} ({target.kind}) with scope notes: {target.scope_notes}'
    brief = build_brief(payload.question, context)
    audit(db, 'research_requested', actor_for(request), 'Generated a defensive research brief; no action was triggered.', payload.target_id)
    manager.publish_sync(event_payload('research_ready', 'Defensive research brief is ready.', payload.target_id))
    return {'brief': brief}


@router.websocket('/ws/events')
async def events_socket(websocket: WebSocket) -> None:
    await manager.connect(websocket)
    try:
        await websocket.send_json(event_payload('connected', 'Live SentinelX event stream connected.'))
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception:
        manager.disconnect(websocket)
