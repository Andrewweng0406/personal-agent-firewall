const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('firewallDesktop', {
  getConfig: () => ipcRenderer.invoke('firewall:config'),
  retryBackend: () => ipcRenderer.invoke('firewall:retry-backend'),
  getStats: (filters) => ipcRenderer.invoke('firewall:stats', filters),
  getEvents: (filters) => ipcRenderer.invoke('firewall:events', filters),
  getCodexEvents: (filters) => ipcRenderer.invoke('firewall:codex-events', filters),
  getContainments: () => ipcRenderer.invoke('firewall:containments'),
  decide: (requestId, decision) => ipcRenderer.invoke('firewall:decision', requestId, decision),
  showAlert: (alert) => ipcRenderer.send('firewall:show-alert', alert),
  alertResolved: (event) => ipcRenderer.send('firewall:resolved', event),
  focusDashboard: () => ipcRenderer.send('firewall:focus-dashboard'),
  onReviewAlert: (callback) => ipcRenderer.on('review:set-alert', (_event, alert) => callback(alert)),
  onDecisionResolved: (callback) => ipcRenderer.on('firewall:decision-resolved', (_event, data) => callback(data)),
  onBackendReady: (callback) => ipcRenderer.on('firewall:backend-ready', callback),
  onBackendError: (callback) => ipcRenderer.on('firewall:backend-error', (_event, message) => callback(message))
});
