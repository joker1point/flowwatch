/**
 * flowwatch-alert sidecar —— flowwatch 告警 → Catrace 小窗卡片
 *
 * 本机 HTTP 服务（默认 127.0.0.1:23457，被占用时自动 +1，最多试 3 个）:
 *   POST /alert   {title, body, level, sticky, autoHideMs, dedupeKey, source}
 *   GET  /health  → {ok, pluginId, port, publishCount, ...}
 *
 * 与宿主（Catrace）走 stdin/stdout JSONL（协议 v1）:
 *   出站: ready / log / publish / response
 *   入站: config / request(RPC) / resolved / shutdown
 */
import http from 'node:http';
import readline from 'node:readline';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const pluginId = process.env.CATRACE_PLUGIN_ID || 'flowwatch-alert';
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const STATE_PATH = path.join(__dirname, 'state.json');

const DEFAULT_CONFIG = {
  port: 23457,
  dedupeSec: 60,        // 相同标题在此窗口内只弹一次
  cardDurationSec: 0,   // 0 = 常驻（等用户点击），>0 = 自动关闭秒数
  enabled: true,
};

let config = { ...DEFAULT_CONFIG };
let server = null;
let actualPort = 0;
let seq = 0;
let publishCount = 0;
let lastPublishAt = 0;
let lastError = '';
const recentTitles = new Map(); // title -> ts

/* ---------- 协议输出 ---------- */
const send = (value) => process.stdout.write(JSON.stringify(value) + '\n');
const log = (message, data, level = 'info') => {
  const msg = { v: 1, op: 'log', level, message };
  if (data !== undefined) msg.data = data;
  send(msg);
};
function respond(requestId, ok, result, error) {
  const message = { v: 1, op: 'response', requestId, ok };
  if (ok) message.result = result ?? null;
  else message.error = error || 'request failed';
  send(message);
}

/* ---------- 工具 ---------- */
function clampInt(value, min, max, fallback) {
  const n = Number(value);
  if (!Number.isFinite(n)) return fallback;
  return Math.min(max, Math.max(min, Math.round(n)));
}
function normalizeLevel(raw) {
  const s = String(raw || '').toLowerCase();
  return ['info', 'warning', 'error', 'success'].includes(s) ? s : 'warning';
}
function normalizeConfig(input = {}) {
  return {
    port: clampInt(input.port, 1024, 65535, config.port),
    dedupeSec: clampInt(input.dedupeSec, 0, 3600, config.dedupeSec),
    cardDurationSec: clampInt(input.cardDurationSec, 0, 3600, config.cardDurationSec),
    enabled: input.enabled !== false,
  };
}
function loadState() {
  try {
    if (!fs.existsSync(STATE_PATH)) return;
    const raw = JSON.parse(fs.readFileSync(STATE_PATH, 'utf8'));
    if (typeof raw.publishCount === 'number') publishCount = raw.publishCount;
    if (typeof raw.lastPublishAt === 'number') lastPublishAt = raw.lastPublishAt;
  } catch (error) {
    log('load state failed', { error: String((error && error.message) || error) }, 'warn');
  }
}
function saveState() {
  try {
    fs.writeFileSync(
      STATE_PATH,
      JSON.stringify({ publishCount, lastPublishAt, savedAt: new Date().toISOString() }, null, 2),
      'utf8',
    );
  } catch (error) {
    log('save state failed', { error: String((error && error.message) || error) }, 'warn');
  }
}

/* ---------- 发布 ---------- */
function isDuplicate(title) {
  const win = config.dedupeSec * 1000;
  if (win <= 0) return false;
  const now = Date.now();
  const prev = recentTitles.get(title);
  if (prev && now - prev < win) return true;
  recentTitles.set(title, now);
  if (recentTitles.size > 200) {
    for (const [k, ts] of recentTitles) if (now - ts > win) recentTitles.delete(k);
  }
  return false;
}

function buildEvent(input = {}) {
  seq += 1;
  const title = String(input.title || '流量告警').slice(0, 200);
  const body = String(input.body || '').slice(0, 4000);
  const level = normalizeLevel(input.level);
  let cardSec = config.cardDurationSec;
  if (input.autoHideMs !== undefined) {
    cardSec = clampInt(Number(input.autoHideMs) / 1000, 0, 3600, cardSec);
  }
  const sticky = input.sticky === true || cardSec <= 0;
  return {
    eventType: 'flowwatch-alert.alert',
    kind: 'flowwatch-alert',
    title,
    body,
    level,
    sticky,
    actions: [{ id: 'dismiss', label: sticky ? '知道了' : '关闭' }],
    payload: {
      sequence: seq,
      source: String(input.source || 'flowwatch'),
      pluginId,
      publishedAt: new Date().toISOString(),
      auto_hide_ms: sticky ? 0 : cardSec * 1000,
    },
    dedupeKey: `flowwatch-alert:${seq}:${Date.now()}`,
  };
}

function publishAlert(input = {}) {
  const title = String(input.title || '流量告警').slice(0, 200);
  if (isDuplicate(title)) {
    log('alert deduped', { title });
    return { ok: true, deduped: true, sequence: seq };
  }
  const event = buildEvent(input);
  send({ v: 1, op: 'publish', event });
  publishCount += 1;
  lastPublishAt = Date.now();
  saveState();
  log('alert published', { title, level: event.level, sticky: event.sticky, sequence: seq });
  return { ok: true, sequence: seq, sticky: event.sticky };
}

/* ---------- HTTP ---------- */
function readBody(req, limit = 64 * 1024) {
  return new Promise((resolve, reject) => {
    let raw = '';
    req.on('data', (chunk) => {
      raw += chunk;
      if (raw.length > limit) {
        req.destroy();
        reject(new Error('body too large'));
      }
    });
    req.on('end', () => resolve(raw));
    req.on('error', reject);
  });
}

function statusPayload() {
  return {
    pluginId,
    pid: process.pid,
    port: actualPort,
    enabled: config.enabled !== false,
    dedupeSec: config.dedupeSec,
    cardDurationSec: config.cardDurationSec,
    publishCount,
    lastPublishAt,
    seq,
    lastError: lastError || null,
    alertUrl: `http://127.0.0.1:${actualPort}/alert`,
    healthUrl: `http://127.0.0.1:${actualPort}/health`,
  };
}

async function handleHttp(req, res) {
  const url = String(req.url || '/');
  const json = (code, obj) => {
    res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8' });
    res.end(JSON.stringify(obj));
  };
  if (req.method === 'GET' && (url === '/health' || url.startsWith('/health?'))) {
    json(200, { ok: true, ...statusPayload() });
    return;
  }
  if (req.method === 'POST' && (url === '/alert' || url.startsWith('/alert?'))) {
    if (config.enabled === false) {
      json(200, { ok: true, skipped: 'disabled' });
      return;
    }
    try {
      const raw = await readBody(req);
      const data = raw.trim() ? JSON.parse(raw) : {};
      if (typeof data !== 'object' || data === null || Array.isArray(data)) {
        json(400, { ok: false, error: 'body must be a JSON object' });
        return;
      }
      json(200, publishAlert(data));
    } catch (error) {
      const message = String((error && error.message) || error);
      lastError = message;
      json(400, { ok: false, error: message });
    }
    return;
  }
  json(404, { ok: false, error: 'not found', routes: ['POST /alert', 'GET /health'] });
}

function stopServer() {
  if (!server) return;
  try {
    server.close();
  } catch {
    /* ignore */
  }
  server = null;
  actualPort = 0;
}

function startServer(port, retriesLeft = 2) {
  stopServer();
  const srv = http.createServer((req, res) => {
    handleHttp(req, res).catch((error) => {
      try {
        res.writeHead(500);
        res.end('{"ok":false}');
      } catch {
        /* ignore */
      }
      log('http handler error', { error: String((error && error.message) || error) }, 'error');
    });
  });
  srv.on('error', (error) => {
    const code = error && error.code;
    try {
      srv.close();
    } catch {
      /* ignore */
    }
    if (code === 'EADDRINUSE' && retriesLeft > 0) {
      log(`port ${port} in use, trying ${port + 1}`, { code }, 'warn');
      startServer(port + 1, retriesLeft - 1);
      return;
    }
    lastError = `${code || 'error'}: ${(error && error.message) || ''}`;
    log('http server error', { code, message: lastError }, 'error');
  });
  srv.listen(port, '127.0.0.1', () => {
    server = srv;
    actualPort = srv.address().port;
    log(`listening on 127.0.0.1:${actualPort}`, { port: actualPort });
  });
}

/* ---------- 宿主指令 ---------- */
function applyHostConfig(input) {
  const next = normalizeConfig(input || {});
  const portChanged = next.port !== config.port;
  config = next;
  log('config applied', {
    port: config.port,
    dedupeSec: config.dedupeSec,
    cardDurationSec: config.cardDurationSec,
    enabled: config.enabled,
  });
  if (portChanged || !server) startServer(config.port);
}

function handleRequest(message) {
  const requestId = message.requestId || message.id;
  if (!requestId) return;
  const method = String(message.method || '');
  const params = message.params && typeof message.params === 'object' ? message.params : {};
  try {
    switch (method) {
      case 'getStatus':
        respond(requestId, true, statusPayload());
        break;
      case 'setConfig':
        applyHostConfig(params);
        respond(requestId, true, statusPayload());
        break;
      case 'testAlert': {
        // 手动测试必须可见：先清掉该标题的去重记录，再发布
        recentTitles.delete('流量哨兵测试');
        respond(
          requestId,
          true,
          publishAlert({
            title: '流量哨兵测试',
            body: 'Catrace 通道测试：这是一条测试告警。\n实际告警会在代理上行异常时自动弹出。',
            level: 'info',
            source: 'plugin-test',
          }),
        );
        break;
      }
      default:
        respond(requestId, false, null, `unknown method: ${method}`);
    }
  } catch (error) {
    respond(requestId, false, null, String((error && error.message) || error));
  }
}

function shutdown() {
  log('graceful shutdown', { publishCount, seq });
  stopServer();
  saveState();
  process.exit(0);
}

/* ---------- 启动 ---------- */
loadState();
send({ v: 1, op: 'ready' });
log('flowwatch-alert sidecar ready', {
  pluginId,
  pid: process.pid,
  protocol: process.env.CATRACE_PROTOCOL_VERSION,
  publishCount,
});
startServer(config.port);

readline.createInterface({ input: process.stdin }).on('line', (line) => {
  let message;
  try {
    message = JSON.parse(line);
  } catch {
    return;
  }
  if (!message || typeof message !== 'object') return;
  if (message.op === 'shutdown') {
    shutdown();
    return;
  }
  if (message.op === 'config' && message.config && typeof message.config === 'object') {
    applyHostConfig(message.config);
    return;
  }
  if (message.op === 'request') {
    handleRequest(message);
    return;
  }
  if (message.op === 'resolved') {
    log('toast resolved by host', {
      eventId: message.eventId,
      actionId: message.actionId,
      resolutionKind: message.resolutionKind,
    });
  }
});
