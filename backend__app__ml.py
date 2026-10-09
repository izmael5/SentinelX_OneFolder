from dataclasses import dataclass


@dataclass(frozen=True)
class RiskAssessment:
    severity: str
    confidence: str
    score: float


SEVERITY_BASE = {'info': 10.0, 'low': 28.0, 'medium': 55.0, 'high': 78.0, 'critical': 95.0}


def assess_risk(severity: str, confidence: str, evidence_weight: float = 1.0) -> RiskAssessment:
    base = SEVERITY_BASE.get(severity, 10.0)
    confidence_factor = {'low': 0.75, 'medium': 0.9, 'high': 1.0}.get(confidence, 0.75)
    score = round(min(100.0, base * confidence_factor * max(0.6, min(1.2, evidence_weight))), 2)
    return RiskAssessment(severity=severity, confidence=confidence, score=score)
