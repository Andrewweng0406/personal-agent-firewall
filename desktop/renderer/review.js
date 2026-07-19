const api = window.firewallDesktop;
let currentAlert = null;

function text(id, value) {
  document.getElementById(id).textContent = value ?? '—';
}

function setBusy(busy) {
  document.getElementById('allow-button').disabled = busy;
  document.getElementById('deny-button').disabled = busy;
}

async function decide(decision) {
  if (!currentAlert) return;
  setBusy(true);
  text('review-error', '');
  try {
    await api.decide(currentAlert.request_id, decision);
    window.close();
  } catch (error) {
    text('review-error', error.message || 'This request is no longer pending.');
    setBusy(false);
  }
}

api.onReviewAlert((alert) => {
  currentAlert = alert;
  text('review-risk-level', `${alert.risk_level || 'HIGH'} RISK`);
  text('review-score', `${alert.risk_score ?? '—'} / 100`);
  text('review-explanation', alert.plain_explanation || 'This action requires a manual decision.');
  text('review-agent', alert.agent_id);
  text('review-tool', alert.tool_name);
  text('review-intent', alert.user_intent || 'Not provided');
  text('review-args', JSON.stringify(alert.args_summary || {}, null, 2));
});

document.getElementById('allow-button').addEventListener('click', () => decide('allow'));
document.getElementById('deny-button').addEventListener('click', () => decide('deny'));
document.getElementById('open-dashboard').addEventListener('click', () => api.focusDashboard());
