from urllib.parse import urlparse

from fastapi import HTTPException, Request
from sqlalchemy.orm import Session

from .models import AuditEvent, Target


def validate_target_url(value: str) -> str:
    parsed = urlparse(value)
    if parsed.scheme not in {'http', 'https'}:
        raise HTTPException(status_code=422, detail='Only http and https targets are supported.')
    if not parsed.hostname or parsed.username or parsed.password:
        raise HTTPException(status_code=422, detail='Target must contain a hostname and no embedded credentials.')
    return value.rstrip('/')


def require_enabled_target(db: Session, target_id: str) -> Target:
    target = db.get(Target, target_id)
    if not target:
        raise HTTPException(status_code=404, detail='Target is not registered.')
    if not target.enabled:
        raise HTTPException(status_code=409, detail='Target is disabled and cannot be assessed.')
    return target


def actor_for(request: Request) -> str:
    # Do not trust a browser-supplied identity header. The managed project access gate
    # protects the preview; a later OAuth integration can replace this stable actor
    # label with the verified application identity.
    return 'platform-session'


def audit(db: Session, event_type: str, actor: str, detail: str, target_id: str | None = None) -> AuditEvent:
    event = AuditEvent(event_type=event_type, actor=actor, detail=detail, target_id=target_id)
    db.add(event)
    db.commit()
    db.refresh(event)
    return event
