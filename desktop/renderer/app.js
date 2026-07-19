const api = window.firewallDesktop;
const ui = window.FirewallUi;

const state = {
  stats: null,
  events: [],
  pending: new Map(),
  config: null,
  socket: null,
  reconnectTimer: null,
  reconnectDelay: 1000,
  backendReady: false,
  filters: { agentId: '', sessionId: '' }
};

const $ = (selector) => document.querySelector(selector);

function setText(selector, value) {
  const element = $(selector);
  if (element) element.textContent = value;
}

function showToast(message, tone = 'neutral') {
  const toast = document.createElement('div');
  toast.className = `toast ${tone}`;
  toast.textContent = message;
  $('#toast-region').append(toast);
  setTimeout(() => toast.remove(), 4200);
}

function setConnection(status, label) {
  $('#connection-dot').className = status;
  setText('#connection-label', label);
  setText('#sidebar-status', label);
}

function showView(viewName) {
  const target = document.querySelector(`[data-view-panel="${viewName}"]`);
  if (!target) return;
  document.querySelectorAll('[data-view-panel]').forEach((panel) => {
    panel.hidden = panel !== target;
  });
  document.querySelectorAll('.nav-item[data-view]').forEach((button) => {
    const active = button.dataset.view === viewName;
    button.classList.toggle('active', active);
    if (active) button.setAttribute('aria-current', 'page');
    else button.removeAttribute('aria-current');
  });
  setText('#page-title', viewName === 'activity' ? 'Activity' : 'Firewall overview');
  window.scrollTo({ top: 0, behavior: 'auto' });
}

function renderStats(stats) {
  state.stats = stats;
  const total = stats.total_activity || 0;
  const chatCount = stats.chat?.total_events || 0;
  const toolCount = stats.total_events || 0;
  const safe = stats.posture_counts?.green || 0;
  const uncertain = stats.posture_counts?.yellow || 0;
  const dangerous = stats.posture_counts?.red || 0;
  const toolBlocks = ui.sumDecisionPrefix(stats.decision_counts, 'denied');
  const interventions = toolBlocks + (stats.chat?.interventions || 0);

  setText('#activity-count', total.toLocaleString());
  setText('#chat-count', chatCount.toLocaleString());
  setText('#tool-count', toolCount.toLocaleString());
  setText('#intervention-count', interventions.toLocaleString());
  setText('#total-events', `${total.toLocaleString()} total`);
  setText('#donut-total', total.toLocaleString());
  setText('#legend-safe', safe.toLocaleString());
  setText('#legend-yellow', uncertain.toLocaleString());
  setText('#legend-red', dangerous.toLocaleString());

  const safeEnd = ui.percent(safe, total);
  const yellowEnd = safeEnd + ui.percent(uncertain, total);
  $('#traffic-donut').style.background = total
    ? `conic-gradient(#4ee59a 0 ${safeEnd}%, #e6b94a ${safeEnd}% ${yellowEnd}%, #ff5b66 ${yellowEnd}% 100%)`
    : 'conic-gradient(#1b2a24 0 100%)';

  renderRiskBars(stats.combined_risk_level_counts || {});
}

function renderRiskBars(counts) {
  const levels = [
    ['LOW', '#4ee59a'], ['MEDIUM', '#e6b94a'], ['HIGH', '#ff8a52'], ['CRITICAL', '#ff5b66']
  ];
  const max = Math.max(1, ...levels.map(([level]) => counts[level] || 0));
  const container = $('#risk-bars');
  container.replaceChildren();
  levels.forEach(([level, color]) => {
    const count = counts[level] || 0;
    const row = document.createElement('div');
    row.className = 'risk-row';
    row.innerHTML = `<span>${level}</span><div><i></i></div><strong>${count}</strong>`;
    row.querySelector('i').style.width = `${(count / max) * 100}%`;
    row.querySelector('i').style.background = color;
    container.append(row);
  });
}

function badge(text, tone) {
  const span = document.createElement('span');
  span.className = `status-badge ${tone}`;
  span.textContent = text || 'unknown';
  return span;
}

function renderEvents(events) {
  state.events = events;
  const body = $('#events-body');
  body.replaceChildren();
  if (!events.length) {
    const row = body.insertRow();
    const cell = row.insertCell();
    cell.colSpan = 6;
    cell.className = 'empty-table';
    cell.textContent = 'No chat or tool activity matches these filters.';
    return;
  }
  events.forEach((event) => {
    const row = body.insertRow();
    const time = row.insertCell();
    time.textContent = ui.formatTime(event.created_at);

    const type = row.insertCell();
    type.append(badge(event.source, event.source === 'chat' ? 'yellow' : 'green'));

    const identity = row.insertCell();
    const agent = document.createElement('strong');
    agent.textContent = event.agent_id || 'unknown';
    const session = document.createElement('small');
    session.textContent = ui.shortId(event.session_id);
    identity.append(agent, session);
    row.insertCell().textContent = event.label;

    const risk = row.insertCell();
    risk.append(badge(`${event.risk_score ?? 0} / ${event.risk_level || 'LOW'}`, (event.risk_level || 'LOW').toLowerCase()));
    const safeOutcome = ['allow', 'allowed', 'recorded'].some((value) => String(event.outcome || '').startsWith(value));
    row.insertCell().append(badge(event.outcome, safeOutcome ? 'green' : 'red'));
  });
}

function updateAgentFilter(agentIds) {
  const select = $('#agent-filter');
  const selected = select.value;
  const known = new Set([...select.options].slice(1).map((option) => option.value));
  agentIds.forEach((agentId) => {
    if (!agentId || known.has(agentId)) return;
    const option = document.createElement('option');
    option.value = agentId;
    option.textContent = agentId;
    select.append(option);
  });
  select.value = selected;
}

function mergeActivity(toolEvents, codexEvents) {
  const tools = toolEvents.map((event) => ({
    source: 'tool',
    created_at: event.created_at,
    agent_id: event.agent_id,
    session_id: event.session_id,
    label: event.tool_name || 'Unknown tool',
    risk_score: event.risk_score,
    risk_level: event.risk_level,
    outcome: event.decision
  }));
  const chat = codexEvents
    .filter((event) => ['user_prompt', 'assistant_response'].includes(event.event_type))
    .map((event) => ({
      source: 'chat',
      created_at: event.created_at,
      agent_id: event.agent_id,
      session_id: event.session_id,
      label: event.event_type === 'user_prompt' ? 'User prompt' : 'Assistant response',
      risk_score: event.risk_score,
      risk_level: event.risk_level,
      outcome: event.action
    }));
  return [...tools, ...chat]
    .sort((left, right) => new Date(right.created_at) - new Date(left.created_at))
    .slice(0, 100);
}

function renderPending() {
  const container = $('#pending-list');
  const alerts = [...state.pending.values()];
  setText('#pending-count', alerts.length);
  container.replaceChildren();
  if (!alerts.length) {
    const empty = document.createElement('div');
    empty.className = 'empty-state';
    empty.textContent = 'No requests need your attention.';
    container.append(empty);
    return;
  }
  alerts.forEach((alert) => {
    const item = document.createElement('div');
    item.className = 'pending-item';
    const heading = document.createElement('div');
    const title = document.createElement('strong');
    title.textContent = alert.tool_name || 'Unknown tool';
    heading.append(title, badge(`${alert.risk_score ?? 0} risk`, 'red'));
    const explanation = document.createElement('p');
    explanation.textContent = alert.plain_explanation || 'This request requires a manual decision.';
    const meta = document.createElement('small');
    meta.textContent = `${alert.agent_id || 'unknown'} · ${ui.shortId(alert.session_id)}`;
    const actions = document.createElement('div');
    actions.className = 'inline-actions';
    const deny = document.createElement('button');
    deny.className = 'deny-button';
    deny.textContent = 'Reject';
    deny.onclick = () => decide(alert.request_id, 'deny');
    const allow = document.createElement('button');
    allow.className = 'allow-button';
    allow.textContent = 'Approve once';
    allow.onclick = () => decide(alert.request_id, 'allow');
    actions.append(deny, allow);
    item.append(heading, explanation, meta, actions);
    container.append(item);
  });
}

async function decide(requestId, decision) {
  try {
    await api.decide(requestId, decision);
    state.pending.delete(requestId);
    renderPending();
    showToast(`Request ${decision === 'allow' ? 'approved' : 'rejected'}.`, decision === 'allow' ? 'safe' : 'danger');
    setTimeout(refreshData, 350);
  } catch (error) {
    state.pending.delete(requestId);
    renderPending();
    showToast(error.message || 'The decision could not be submitted.', 'danger');
  }
}

function handleSocketEvent(event) {
  if (event.type === 'new_alert') {
    if (!event.auto_contained) state.pending.set(event.request_id, event);
    api.showAlert(event);
    renderPending();
    showToast(event.auto_contained ? 'A dangerous chain was contained.' : 'A request needs your approval.', 'danger');
  } else if (event.type === 'resolved') {
    state.pending.delete(event.request_id);
    api.alertResolved(event);
    renderPending();
    setTimeout(refreshData, 250);
  } else if (['containment_changed', 'backup_restored', 'codex_event', 'usage_reset'].includes(event.type)) {
    refreshData();
  }
}

function connectWebSocket() {
  clearTimeout(state.reconnectTimer);
  if (state.socket) state.socket.close();
  setConnection('connecting', 'Connecting');
  const socket = new WebSocket(state.config.wsUrl);
  state.socket = socket;
  socket.addEventListener('open', () => {
    state.reconnectDelay = 1000;
    setConnection('online', 'Live protection');
  });
  socket.addEventListener('message', (message) => {
    try { handleSocketEvent(JSON.parse(message.data)); } catch { /* Ignore malformed events. */ }
  });
  socket.addEventListener('close', () => {
    if (state.socket !== socket) return;
    setConnection('offline', 'Reconnecting');
    state.reconnectTimer = setTimeout(connectWebSocket, state.reconnectDelay);
    state.reconnectDelay = Math.min(state.reconnectDelay * 1.8, 15000);
  });
  socket.addEventListener('error', () => socket.close());
}

async function refreshData() {
  $('#refresh-button').classList.add('spinning');
  try {
    const [stats, toolHistory, chatHistory] = await Promise.all([
      api.getStats(state.filters),
      api.getEvents({ ...state.filters, limit: 100 }),
      api.getCodexEvents({ ...state.filters, limit: 100 })
    ]);
    const activity = mergeActivity(toolHistory.events || [], chatHistory.events || []);
    renderStats(stats);
    renderEvents(activity);
    updateAgentFilter([...new Set(activity.map((event) => event.agent_id))]);
    setText('#last-updated', `Updated ${new Intl.DateTimeFormat(undefined, { hour: 'numeric', minute: '2-digit', second: '2-digit' }).format(new Date())}`);
  } catch (error) {
    setConnection('offline', 'Backend unavailable');
    showToast(error.message || 'Could not load firewall data.', 'danger');
  } finally {
    $('#refresh-button').classList.remove('spinning');
  }
}

function bindEvents() {
  $('#refresh-button').addEventListener('click', async () => {
    if (state.backendReady) {
      refreshData();
      return;
    }
    setConnection('connecting', 'Starting backend');
    const result = await api.retryBackend();
    if (!result.ready && result.error) showToast(result.error, 'danger');
  });
  $('#apply-filters').addEventListener('click', () => {
    state.filters.agentId = $('#agent-filter').value;
    state.filters.sessionId = $('#session-filter').value.trim();
    refreshData();
  });
  $('#session-filter').addEventListener('keydown', (event) => {
    if (event.key === 'Enter') $('#apply-filters').click();
  });
  document.querySelectorAll('.nav-item[data-view]').forEach((button) => {
    button.addEventListener('click', () => showView(button.dataset.view));
  });
  api.onDecisionResolved(({ request_id }) => {
    state.pending.delete(request_id);
    renderPending();
    setTimeout(refreshData, 350);
  });
  api.onBackendReady(() => {
    state.backendReady = true;
    refreshData();
    if (!state.socket || state.socket.readyState > 1) connectWebSocket();
  });
  api.onBackendError((message) => {
    state.backendReady = false;
    setConnection('offline', 'Backend failed - click refresh');
    showToast(message, 'danger');
  });
}

async function init() {
  bindEvents();
  renderPending();
  state.config = await api.getConfig();
  state.backendReady = state.config.backendReady;
  if (state.backendReady) {
    await refreshData();
    connectWebSocket();
  } else if (state.config.backendError) {
    setConnection('offline', 'Backend failed - click refresh');
    showToast(state.config.backendError, 'danger');
  } else {
    setConnection('connecting', 'Starting backend');
  }
  setInterval(() => {
    if (state.backendReady) refreshData();
  }, 10000);
}

init();
