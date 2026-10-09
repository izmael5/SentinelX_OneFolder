const state = { view: 'overview', overview: null, targets: [], findings: [], ws: null };
const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => [...document.querySelectorAll(selector)];

async function api(path, options = {}) {
  const response = await fetch(`/api${path}`, { headers: { 'Content-Type': 'application/json', ...(options.headers || {}) }, ...options });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(body.detail || `Request failed (${response.status})`);
  return body;
}

function showToast(message) {
  const toast = $('#toast'); toast.textContent = message; toast.classList.add('show');
  window.clearTimeout(showToast.timer); showToast.timer = window.setTimeout(() => toast.classList.remove('show'), 3200);
}

function setView(view) {
  state.view = view;
  $$('.nav-item').forEach((item) => item.classList.toggle('active', item.dataset.view === view));
  $$('.view').forEach((section) => section.classList.toggle('active', section.id === `view-${view}`));
  $('#page-title').textContent = { overview: 'Overview', targets: 'Targets', findings: 'Findings', research: 'Research' }[view];
  if (view === 'targets') renderTargets();
  if (view === 'findings') renderFindings();
}

function formatTime(value) { if (!value) return '--'; return new Date(value).toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }); }
function esc(value) { return String(value ?? '').replace(/[&<>'"]/g, (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' }[char])); }

function renderOverview() {
  const data = state.overview || { targets: 0, enabled_targets: 0, open_findings: 0, completed_scans: 0, severity: {}, events: [] };
  $('#metric-targets').textContent = data.targets;
  $('#metric-targets-note').textContent = `${data.enabled_targets} enabled in scope`;
  $('#metric-findings').textContent = data.open_findings;
  $('#metric-scans').textContent = data.completed_scans;
  const total = Object.values(data.severity || {}).reduce((a, b) => a + b, 0);
  const weighted = total ? Math.round(((data.severity.critical || 0) * 95 + (data.severity.high || 0) * 78 + (data.severity.medium || 0) * 55 + (data.severity.low || 0) * 28 + (data.severity.info || 0) * 10) / total) : 0;
  $('#hero-risk').textContent = total ? weighted : '--';
  $('#event-list').innerHTML = (data.events || []).length ? data.events.map((event) => `<div class="event-row"><span class="event-marker"></span><span class="event-detail">${esc(event.detail)}</span><span class="event-time">${formatTime(event.at)}</span></div>`).join('') : '<div class="empty-state">No audit events yet. Register a target to begin.</div>';
  const levels = ['critical', 'high', 'medium', 'low', 'info'];
  $('#severity-chart').innerHTML = levels.map((level) => { const count = data.severity?.[level] || 0; const width = total ? Math.max(2, Math.round((count / total) * 100)) : 2; return `<div class="severity-row"><span>${level}</span><div class="bar-track"><div class="bar ${level}" style="width:${width}%"></div></div><strong>${count}</strong></div>`; }).join('');
}

function renderTargets() {
  $('#target-count').textContent = state.targets.length;
  $('#target-list').innerHTML = state.targets.length ? state.targets.map((target) => `<div class="target-row"><div><div class="target-name">${esc(target.name)} ${target.enabled ? '<span class="severity-pill">enabled</span>' : '<span class="severity-pill">paused</span>'}</div><div class="target-url">${esc(target.url)}</div><div class="target-meta">${esc(target.authorization_ref)} · ${esc(target.scope_notes)}</div></div><div class="target-actions"><button class="small-button scan-button" data-id="${target.id}" ${target.enabled ? '' : 'disabled'}>Run safe check</button><button class="small-button toggle-button" data-id="${target.id}" data-enabled="${target.enabled}">${target.enabled ? 'Disable' : 'Enable'}</button></div></div>`).join('') : '<div class="empty-state">No authorized targets registered.</div>';
  $('#research-target').innerHTML = '<option value="">No specific target</option>' + state.targets.map((target) => `<option value="${target.id}">${esc(target.name)}</option>`).join('');
  $$('.scan-button').forEach((button) => button.addEventListener('click', () => startScan(button.dataset.id)));
  $$('.toggle-button').forEach((button) => button.addEventListener('click', () => toggleTarget(button.dataset.id, button.dataset.enabled !== 'true')));
}

function renderFindings() {
  const list = state.findings;
  $('#finding-list').innerHTML = list.length ? list.map((finding) => `<article class="finding-card"><span class="finding-severity ${esc(finding.severity)}"></span><div><div class="finding-title">${esc(finding.title)}</div><div class="finding-sub">${esc(finding.target_name)} · ${esc(finding.confidence)} confidence · risk ${Math.round(finding.risk_score)}</div><div class="finding-evidence"><strong>Evidence:</strong> ${esc(finding.evidence)}</div><div class="finding-remediation"><strong>Remediation:</strong> ${esc(finding.remediation)}</div><div class="finding-actions"><button class="small-button status-button" data-id="${finding.id}" data-status="acknowledged">Acknowledge</button><button class="small-button status-button" data-id="${finding.id}" data-status="resolved">Resolve</button></div></div><div><span class="severity-pill ${esc(finding.severity)}">${esc(finding.severity)}</span></div></article>`).join('') : '<div class="panel empty-state">No findings match this filter.</div>';
  $$('.status-button').forEach((button) => button.addEventListener('click', () => updateFinding(button.dataset.id, button.dataset.status)));
}

async function loadAll() {
  try {
    [state.overview, state.targets, state.findings] = await Promise.all([api('/overview'), api('/targets'), api('/findings')]);
    renderOverview(); renderTargets(); renderFindings();
  } catch (error) { showToast(error.message); }
}

async function startScan(targetId) {
  try { await api('/scan-jobs', { method: 'POST', body: JSON.stringify({ target_id: targetId, check_family: 'safe_web_posture' }) }); showToast('Safe assessment queued.'); await loadAll(); } catch (error) { showToast(error.message); }
}

async function toggleTarget(targetId, enabled) {
  try { await api(`/targets/${targetId}/enabled?enabled=${enabled}`, { method: 'PATCH' }); showToast(`Target ${enabled ? 'enabled' : 'disabled'}.`); await loadAll(); } catch (error) { showToast(error.message); }
}

async function updateFinding(id, status) {
  try { await api(`/findings/${id}/status`, { method: 'PATCH', body: JSON.stringify({ status }) }); showToast(`Finding marked ${status}.`); await loadAll(); } catch (error) { showToast(error.message); }
}

function connectEvents() {
  const protocol = window.location.protocol === 'https:' ? 'wss' : 'ws';
  state.ws = new WebSocket(`${protocol}://${window.location.host}/api/ws/events`);
  state.ws.onopen = () => { $('#live-state').innerHTML = '<span class="status-dot"></span> live'; $('#metric-stream').textContent = 'LIVE'; state.ws.send('ready'); };
  state.ws.onclose = () => { $('#live-state').innerHTML = '<span class="status-dot" style="background:var(--amber)"></span> reconnecting'; $('#metric-stream').textContent = 'OFF'; window.setTimeout(connectEvents, 2200); };
  state.ws.onmessage = async (message) => { const event = JSON.parse(message.data); if (event.type !== 'connected') { showToast(event.detail); await loadAll(); } };
}

$('#refresh-btn').addEventListener('click', loadAll);
$$('.nav-item').forEach((item) => item.addEventListener('click', () => setView(item.dataset.view)));
$('#finding-filter').addEventListener('change', async (event) => { state.findings = await api(`/findings${event.target.value ? `?status=${event.target.value}` : ''}`); renderFindings(); });
$('#target-form').addEventListener('submit', async (event) => { event.preventDefault(); const form = new FormData(event.target); const status = $('#target-form-status'); status.textContent = 'Registering target…'; try { await api('/targets', { method: 'POST', body: JSON.stringify(Object.fromEntries(form.entries())) }); event.target.reset(); status.textContent = 'Target registered in the authorized scope.'; showToast('Target added to scope.'); await loadAll(); } catch (error) { status.textContent = error.message; } });
$('#research-form').addEventListener('submit', async (event) => { event.preventDefault(); const form = new FormData(event.target); const status = $('#research-status'); status.textContent = 'Preparing evidence-led brief…'; $('#research-output').textContent = 'Working…'; try { const result = await api('/research/brief', { method: 'POST', body: JSON.stringify(Object.fromEntries(form.entries())) }); $('#research-output').textContent = result.brief; status.textContent = 'Complete. No action was triggered.'; } catch (error) { status.textContent = error.message; $('#research-output').textContent = 'Unable to prepare a brief.'; } });

loadAll(); connectEvents();
