const { app, BrowserWindow, ipcMain, Menu, net } = require('electron');
const { spawn } = require('node:child_process');
const { existsSync } = require('node:fs');
const path = require('node:path');

const projectRoot = path.resolve(__dirname, '..', '..');
const desktopRoot = path.resolve(__dirname, '..');
const backendUrl = (process.env.AGENT_FIREWALL_URL || 'http://127.0.0.1:8000').replace(/\/$/, '');
const apiToken = process.env.AGENT_FIREWALL_TOKEN || '';
const wsToken = apiToken ? `?token=${encodeURIComponent(apiToken)}` : '';
const wsUrl = backendUrl.replace(/^http/, 'ws') + '/ws/alerts' + wsToken;
const smokeMode = process.argv.includes('--smoke-test');
const resetDataOnLaunch = !smokeMode && process.env.FIREWALL_RESET_ON_LAUNCH === '1';

let mainWindow = null;
let backendProcess = null;
let backendReady = false;
let backendError = null;
let backendStartPromise = null;
let backendLog = [];
let launchResetComplete = !resetDataOnLaunch;
const reviewWindows = new Map();

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1440,
    height: 920,
    minWidth: 1060,
    minHeight: 720,
    backgroundColor: '#08100d',
    title: 'Personal Agent Firewall',
    autoHideMenuBar: true,
    show: false,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      backgroundThrottling: false
    }
  });

  mainWindow.loadFile(path.join(desktopRoot, 'renderer', 'index.html'));
  mainWindow.once('ready-to-show', () => {
    if (!smokeMode) mainWindow.show();
  });
  mainWindow.on('closed', () => { mainWindow = null; });
}

function createReviewWindow(alert) {
  if (!alert?.request_id || alert.auto_contained || reviewWindows.has(alert.request_id)) return;

  const popup = new BrowserWindow({
    width: 430,
    height: 620,
    minWidth: 390,
    minHeight: 540,
    resizable: true,
    alwaysOnTop: true,
    title: 'Firewall approval required',
    backgroundColor: '#0b1511',
    autoHideMenuBar: true,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true
    }
  });

  reviewWindows.set(alert.request_id, popup);
  popup.loadFile(path.join(desktopRoot, 'renderer', 'review.html'));
  popup.webContents.once('did-finish-load', () => {
    popup.webContents.send('review:set-alert', alert);
  });
  popup.on('closed', () => reviewWindows.delete(alert.request_id));
}

function closeReviewWindow(requestId) {
  const popup = reviewWindows.get(requestId);
  if (popup && !popup.isDestroyed()) popup.close();
}

async function apiFetch(route, options = {}) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 8000);
  try {
    const headers = {};
    if (options.body) headers['Content-Type'] = 'application/json';
    if (apiToken) headers.Authorization = `Bearer ${apiToken}`;
    const response = await net.fetch(`${backendUrl}${route}`, {
      method: options.method || 'GET',
      headers,
      body: options.body ? JSON.stringify(options.body) : undefined,
      signal: controller.signal
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.detail || `Firewall returned HTTP ${response.status}`);
    return data;
  } catch (error) {
    if (error.name === 'AbortError') throw new Error('Firewall backend did not respond in time.');
    throw error;
  } finally {
    clearTimeout(timeout);
  }
}

function encodeFilters(filters = {}) {
  const params = new URLSearchParams();
  if (filters.agentId) params.set('agent_id', filters.agentId);
  if (filters.sessionId) params.set('session_id', filters.sessionId);
  if (filters.limit) params.set('limit', String(filters.limit));
  const query = params.toString();
  return query ? `?${query}` : '';
}

function isSafeRequestId(value) {
  return typeof value === 'string' && /^[A-Za-z0-9_-]{1,128}$/.test(value);
}

function registerIpc() {
  ipcMain.handle('firewall:config', () => ({
    backendUrl,
    wsUrl,
    backendReady,
    backendStarting: Boolean(backendStartPromise),
    backendError
  }));
  ipcMain.handle('firewall:retry-backend', async () => {
    const ready = await startBackend();
    return { ready, error: backendError };
  });
  ipcMain.handle('firewall:stats', (_event, filters) =>
    apiFetch(`/api/dashboard/stats${encodeFilters(filters)}`));
  ipcMain.handle('firewall:events', (_event, filters) =>
    apiFetch(`/api/events${encodeFilters({ ...filters, limit: filters?.limit || 100 })}`));
  ipcMain.handle('firewall:codex-events', (_event, filters) =>
    apiFetch(`/api/codex/events${encodeFilters({ ...filters, limit: filters?.limit || 100 })}`));
  ipcMain.handle('firewall:containments', () => apiFetch('/api/containment'));
  ipcMain.handle('firewall:decision', async (_event, requestId, decision) => {
    if (!isSafeRequestId(requestId) || !['allow', 'deny'].includes(decision)) {
      throw new Error('Invalid firewall decision.');
    }
    const result = await apiFetch(`/api/decision/${encodeURIComponent(requestId)}`, {
      method: 'POST',
      body: { decision, reviewer: 'desktop-app' }
    });
    mainWindow?.webContents.send('firewall:decision-resolved', { request_id: requestId, decision });
    // Let the invoking renderer receive its resolved promise before its popup
    // is destroyed. Dashboard-originated decisions still close the popup.
    setTimeout(() => closeReviewWindow(requestId), 75);
    return result;
  });
  ipcMain.on('firewall:show-alert', (_event, alert) => {
    if (alert?.type === 'new_alert') createReviewWindow(alert);
  });
  ipcMain.on('firewall:resolved', (_event, event) => {
    if (event?.request_id) closeReviewWindow(event.request_id);
  });
  ipcMain.on('firewall:focus-dashboard', () => {
    if (!mainWindow) createWindow();
    if (mainWindow.isMinimized()) mainWindow.restore();
    mainWindow.show();
    mainWindow.focus();
  });
}

async function backendIsReady() {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 750);
  try {
    const response = await net.fetch(`${backendUrl}/api/health`, {
      signal: controller.signal
    });
    return response.ok;
  } catch {
    return false;
  } finally {
    clearTimeout(timeout);
  }
}

function pythonCommand() {
  if (process.env.FIREWALL_PYTHON) return process.env.FIREWALL_PYTHON;
  const executable = process.platform === 'win32' ? 'python.exe' : 'python';
  const virtualenvPython = path.join(
    projectRoot, '.venv', process.platform === 'win32' ? 'Scripts' : 'bin', executable
  );
  return existsSync(virtualenvPython) ? virtualenvPython : executable;
}

async function ensureBackend() {
  if (await backendIsReady()) return true;

  const target = new URL(backendUrl);
  if (!['127.0.0.1', 'localhost', '::1'].includes(target.hostname)) {
    backendError = `Could not connect to ${backendUrl}.`;
    return false;
  }

  if (backendProcess && backendProcess.exitCode === null) backendProcess.kill();
  backendLog = [];
  let spawnError = null;

  backendProcess = spawn(
    pythonCommand(),
    ['-m', 'uvicorn', 'app.main:app', '--host', target.hostname === 'localhost' ? '127.0.0.1' : target.hostname, '--port', target.port || '8000'],
    { cwd: projectRoot, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] }
  );
  backendProcess.on('error', (error) => {
    spawnError = error.message;
  });
  for (const stream of [backendProcess.stdout, backendProcess.stderr]) {
    stream.on('data', (chunk) => {
      const lines = chunk.toString().split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
      backendLog.push(...lines);
      backendLog = backendLog.slice(-12);
      if (smokeMode) process.stdout.write(chunk);
    });
  }

  // Importing the optional local semantic-PII model can make a cold Python
  // start noticeably slower, especially on Windows. Keep the UI responsive
  // while allowing enough time for that first initialization to finish.
  for (let attempt = 0; attempt < 80; attempt += 1) {
    await new Promise((resolve) => setTimeout(resolve, 300));
    if (await backendIsReady()) return true;
    if (backendProcess.exitCode !== null) break;
  }
  const detail = spawnError || backendLog.at(-1);
  backendError = detail
    ? `Could not start the firewall backend: ${detail}`
    : 'Could not start the firewall backend. Click refresh to retry.';
  return false;
}

function startBackend() {
  if (backendStartPromise) return backendStartPromise;
  backendError = null;
  backendStartPromise = (async () => {
    backendReady = await ensureBackend();
    if (backendReady && !launchResetComplete) {
      try {
        await apiFetch('/api/dashboard/reset', { method: 'POST' });
        launchResetComplete = true;
      } catch (error) {
        backendReady = false;
        backendError = `Backend started, but usage data could not be reset: ${error.message}`;
      }
    }
    if (backendReady) {
      mainWindow?.webContents.send('firewall:backend-ready');
    } else {
      mainWindow?.webContents.send('firewall:backend-error', backendError);
    }
    return backendReady;
  })().finally(() => {
    backendStartPromise = null;
  });
  return backendStartPromise;
}

app.whenReady().then(async () => {
  Menu.setApplicationMenu(null);
  registerIpc();
  createWindow();
  await startBackend();

  if (smokeMode) {
    try {
      await new Promise((resolve) => setTimeout(resolve, 1200));
      const smokeAlert = {
        type: 'new_alert', request_id: 'desktop-smoke-alert', agent_id: 'smoke-agent',
        session_id: 'smoke-session', tool_name: 'write_file', risk_score: 92,
        risk_level: 'CRITICAL', plain_explanation: 'Smoke-test approval request.',
        args_summary: { path: '/protected/file' }, auto_contained: false
      };
      createReviewWindow(smokeAlert);
      await new Promise((resolve) => setTimeout(resolve, 500));
      const reviewWindow = reviewWindows.get(smokeAlert.request_id);
      const reviewActions = await reviewWindow?.webContents.executeJavaScript(`({
        allow: document.querySelector('#allow-button')?.textContent,
        deny: document.querySelector('#deny-button')?.textContent,
        tool: document.querySelector('#review-tool')?.textContent
      })`);
      const result = await mainWindow.webContents.executeJavaScript(`({
        title: document.title,
        brand: document.querySelector('.brand strong')?.textContent,
        activityCount: document.querySelector('#activity-count')?.textContent,
        connection: document.querySelector('#connection-label')?.textContent,
        hasTrafficChart: Boolean(document.querySelector('#traffic-donut')),
        hasPendingReview: Boolean(document.querySelector('#pending-list'))
      })`);
      result.activityNavigation = await mainWindow.webContents.executeJavaScript(`(() => {
        document.querySelector('[data-view="activity"]')?.click();
        return {
          title: document.querySelector('#page-title')?.textContent,
          activityVisible: !document.querySelector('#activity-view')?.hidden,
          overviewHidden: Boolean(document.querySelector('#overview-view')?.hidden),
          activeNav: document.querySelector('.nav-item.active')?.dataset.view
        };
      })()`);
      result.reviewActions = reviewActions;
      const valid = result.title === 'Personal Agent Firewall' && result.brand === 'FIREWORKS' &&
        result.hasTrafficChart &&
        result.hasPendingReview && result.connection === 'Live protection' &&
        result.activityNavigation?.title === 'Activity' &&
        result.activityNavigation?.activityVisible &&
        result.activityNavigation?.overviewHidden &&
        result.activityNavigation?.activeNav === 'activity' &&
        reviewActions?.allow === 'Approve once' &&
        reviewActions?.deny === 'Reject request' && reviewActions?.tool === 'write_file';
      console.log(`DESKTOP_SMOKE ${JSON.stringify(result)}`);
      if (!valid) process.exitCode = 1;
    } catch (error) {
      console.error(`DESKTOP_SMOKE_FAILED ${error.message}`);
      process.exitCode = 1;
    }
    app.quit();
    return;
  }

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});

app.on('before-quit', () => {
  if (backendProcess && backendProcess.exitCode === null) backendProcess.kill();
});
