import httpx

from .config import get_settings


def fallback_brief(question: str) -> str:
    return (
        'Defensive research brief\n\n'
        f'Question: {question}\n\n'
        'Recommended method: define the asset, collect reproducible evidence, map the observation to a known control or weakness category, '
        'prioritize by impact and confidence, and document a safe remediation. This workspace does not generate exploit steps or authorize actions.'
    )


def build_brief(question: str, target_context: str | None = None) -> str:
    settings = get_settings()
    if not settings.manus_api_url or not settings.manus_api_key:
        return fallback_brief(question)

    context = target_context or 'No target context was provided.'
    prompt = (
        'You are a defensive security research assistant. Provide concise, evidence-led analysis for systems the operator owns or is explicitly authorized to assess. '
        'Do not provide exploit code, persistence, credential theft, evasion, or instructions to attack arbitrary systems. Focus on risk, verification that is non-destructive, and remediation.\n\n'
        f'Target context: {context}\nQuestion: {question}'
    )
    try:
        response = httpx.post(
            f'{settings.manus_api_url.rstrip("/")}/v1/chat/completions',
            headers={'Authorization': f'Bearer {settings.manus_api_key}', 'Content-Type': 'application/json'},
            json={'messages': [{'role': 'user', 'content': prompt}], 'temperature': 0.1},
            timeout=20.0,
        )
        response.raise_for_status()
        body = response.json()
        content = body.get('choices', [{}])[0].get('message', {}).get('content')
        return content.strip() if content else fallback_brief(question)
    except (httpx.HTTPError, ValueError, IndexError, AttributeError):
        return fallback_brief(question)
