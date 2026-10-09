from dataclasses import dataclass

import httpx

from .ml import RiskAssessment, assess_risk


@dataclass(frozen=True)
class Observation:
    title: str
    severity: str
    confidence: str
    evidence: str
    remediation: str
    risk: RiskAssessment


SAFE_HEADERS = {
    'strict-transport-security': ('Missing HSTS', 'medium', 'high', 'Add Strict-Transport-Security after confirming HTTPS coverage.'),
    'content-security-policy': ('Missing Content-Security-Policy', 'medium', 'medium', 'Define a restrictive Content-Security-Policy and iterate from report-only.'),
    'x-content-type-options': ('Missing X-Content-Type-Options', 'low', 'high', 'Set X-Content-Type-Options: nosniff.'),
    'x-frame-options': ('Missing clickjacking protection', 'low', 'medium', 'Use Content-Security-Policy frame-ancestors and/or X-Frame-Options.'),
}


def assess_url(url: str) -> list[Observation]:
    observations: list[Observation] = []
    headers = {'User-Agent': 'SentinelX-Defensive-Assessment/0.1', 'Accept': 'text/html,application/xhtml+xml'}
    try:
        with httpx.Client(timeout=8.0, follow_redirects=False, headers=headers) as client:
            response = client.get(url)
    except httpx.HTTPError as exc:
        risk = assess_risk('high', 'medium', 0.9)
        return [Observation('Target could not be reached', 'high', 'medium', f'Connection error: {type(exc).__name__}', 'Verify the target is in scope and reachable, then retry.', risk)]

    if response.status_code >= 500:
        risk = assess_risk('medium', 'high')
        observations.append(Observation('Server returned an error status', 'medium', 'high', f'HTTP {response.status_code} from the registered target.', 'Review server logs and error handling; avoid exposing diagnostic details.', risk))
    elif response.status_code >= 400:
        risk = assess_risk('low', 'high')
        observations.append(Observation('Target returned a client error', 'low', 'high', f'HTTP {response.status_code} from the registered target.', 'Confirm the assessment path is intended and review public error behavior.', risk))

    normalized = {key.lower(): value for key, value in response.headers.items()}
    for header, (title, severity, confidence, remediation) in SAFE_HEADERS.items():
        if header not in normalized:
            risk = assess_risk(severity, confidence)
            observations.append(Observation(title, severity, confidence, f'{header} was not present in the response headers.', remediation, risk))

    server = normalized.get('server')
    if server and any(token in server.lower() for token in ('apache/', 'nginx/', 'iis/')):
        risk = assess_risk('info', 'high')
        observations.append(Observation('Server banner is exposed', 'info', 'high', f'Server header: {server[:120]}', 'Consider minimizing version disclosure while retaining useful internal diagnostics.', risk))

    if response.status_code in {301, 302, 303, 307, 308} and response.headers.get('location'):
        risk = assess_risk('info', 'high')
        observations.append(Observation('Redirect observed', 'info', 'high', f'HTTP {response.status_code} redirects to {response.headers["location"][:240]}', 'Confirm the redirect destination is expected and remains within the authorized scope.', risk))

    if not observations:
        risk = assess_risk('info', 'high')
        observations.append(Observation('No posture gaps found in the selected checks', 'info', 'high', f'HTTP {response.status_code}; checked the configured safe header set.', 'Continue with authenticated review and application-specific controls.', risk))
    return observations
