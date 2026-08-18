'use strict';

const crypto = require('crypto');
const fs = require('fs');
const http = require('http');
const net = require('net');
const path = require('path');

const PROTOCOL_VERSION = 1;
const ALLOWED_ACTIONS = new Set(['ping', 'echo', 'get_host_info', 'powershell']);

function parseArguments(argv) {
  const result = {};
  for (let index = 0; index < argv.length; index += 1) {
    const item = argv[index];
    if (!item.startsWith('--')) {
      throw new Error(`Unexpected argument: ${item}`);
    }
    const key = item.slice(2);
    const value = argv[index + 1];
    if (!value || value.startsWith('--')) {
      throw new Error(`Argument --${key} requires a value.`);
    }
    result[key] = value;
    index += 1;
  }
  return result;
}

function isLoopback(host) {
  return host === '127.0.0.1' || host === '::1' || host === 'localhost';
}

function readJsonFile(filePath) {
  return JSON.parse(fs.readFileSync(filePath, 'utf8').replace(/^\uFEFF/, ''));
}

function readConfig(configPath) {
  const absolutePath = path.resolve(configPath);
  const directory = path.dirname(absolutePath);
  const config = readJsonFile(absolutePath);
  config.agentListen = config.agentListen || { host: '127.0.0.1', port: 8765 };
  config.controlListen = config.controlListen || { host: '127.0.0.1', port: 8766 };
  config.heartbeatSeconds = Number(config.heartbeatSeconds || 15);
  config.sessionTimeoutSeconds = Number(config.sessionTimeoutSeconds || 45);
  config.maxMessageBytes = Number(config.maxMessageBytes || 262144);
  config.maxTaskTimeoutSeconds = Number(config.maxTaskTimeoutSeconds || 120);
  config.maxConcurrentTasksPerAgent = Number(config.maxConcurrentTasksPerAgent ?? 4);
  config.enableTestHooks = config.enableTestHooks === true;
  config.stateFile = path.resolve(directory, config.stateFile || 'state.json');
  config.controlToken = process.env.PS_TUNNEL_CONTROL_TOKEN || config.controlToken;

  if (!isLoopback(config.agentListen.host) || !isLoopback(config.controlListen.host)) {
    throw new Error('agentListen and controlListen must use loopback addresses.');
  }
  for (const listener of [config.agentListen, config.controlListen]) {
    listener.port = Number(listener.port);
    if (!Number.isInteger(listener.port) || listener.port < 1 || listener.port > 65535) {
      throw new Error('Listener ports must be integers from 1 through 65535.');
    }
  }
  if (!Number.isInteger(config.heartbeatSeconds) || config.heartbeatSeconds < 1) {
    throw new Error('heartbeatSeconds must be a positive integer.');
  }
  if (!Number.isInteger(config.sessionTimeoutSeconds) || config.sessionTimeoutSeconds <= config.heartbeatSeconds) {
    throw new Error('sessionTimeoutSeconds must exceed heartbeatSeconds.');
  }
  if (!Number.isInteger(config.maxMessageBytes) || config.maxMessageBytes < 1024 || config.maxMessageBytes > 1048576) {
    throw new Error('maxMessageBytes must be between 1024 and 1048576.');
  }
  if (!Number.isInteger(config.maxConcurrentTasksPerAgent) ||
      config.maxConcurrentTasksPerAgent < 1 || config.maxConcurrentTasksPerAgent > 64) {
    throw new Error('maxConcurrentTasksPerAgent must be between 1 and 64.');
  }
  if (!Number.isInteger(config.maxTaskTimeoutSeconds) || config.maxTaskTimeoutSeconds < 1 || config.maxTaskTimeoutSeconds > 3600) {
    throw new Error('maxTaskTimeoutSeconds must be between 1 and 3600.');
  }
  if (typeof config.controlToken !== 'string' || config.controlToken.length < 16) {
    throw new Error('controlToken must contain at least 16 characters.');
  }
  if (config.controlToken.startsWith('replace-with-')) {
    throw new Error('controlToken still contains the config.example.json placeholder.');
  }
  if (!config.agents || typeof config.agents !== 'object' || Array.isArray(config.agents)) {
    throw new Error('agents must be an object containing agent-id to secret mappings.');
  }
  for (const [agentId, secret] of Object.entries(config.agents)) {
    if (!/^[A-Za-z0-9._-]{1,64}$/.test(agentId)) {
      throw new Error(`Invalid agent id in config: ${agentId}`);
    }
    if (typeof secret !== 'string' || secret.length < 16) {
      throw new Error(`Secret for ${agentId} must contain at least 16 characters.`);
    }
    if (secret.startsWith('replace-with-')) {
      throw new Error(`Secret for ${agentId} still contains the config.example.json placeholder.`);
    }
  }
  return config;
}

function log(level, message, fields) {
  const suffix = fields ? ` ${JSON.stringify(fields)}` : '';
  process.stderr.write(`${new Date().toISOString()} [${level}] ${message}${suffix}\n`);
}

function hmacHex(secret, text) {
  return crypto.createHmac('sha256', Buffer.from(secret, 'utf8')).update(text, 'utf8').digest('hex');
}

function fixedTimeEqual(left, right) {
  if (typeof left !== 'string' || typeof right !== 'string') {
    return false;
  }
  const leftBuffer = Buffer.from(left, 'ascii');
  const rightBuffer = Buffer.from(right, 'ascii');
  if (leftBuffer.length !== rightBuffer.length) {
    return false;
  }
  return crypto.timingSafeEqual(leftBuffer, rightBuffer);
}

function jsonClone(value) {
  return JSON.parse(JSON.stringify(value));
}

const commandLine = parseArguments(process.argv.slice(2));
if (!commandLine.config) {
  throw new Error('Usage: node broker.js --config <config.json>');
}
const config = readConfig(commandLine.config);

function createEmptyState() {
  return { version: 1, queue: [], tasks: {} };
}

function loadState() {
  if (!fs.existsSync(config.stateFile)) {
    return createEmptyState();
  }
  const loaded = JSON.parse(fs.readFileSync(config.stateFile, 'utf8'));
  if (loaded.version !== 1 || !Array.isArray(loaded.queue) || !loaded.tasks || typeof loaded.tasks !== 'object') {
    throw new Error('State file format is invalid.');
  }
  for (const task of Object.values(loaded.tasks)) {
    if (task.status === 'running') {
      task.status = 'queued';
      task.sessionId = null;
      task.deadline = null;
      if (!loaded.queue.includes(task.id)) {
        loaded.queue.push(task.id);
      }
    }
  }
  return loaded;
}

const state = loadState();

function saveState() {
  fs.mkdirSync(path.dirname(config.stateFile), { recursive: true });
  const temporaryPath = `${config.stateFile}.tmp-${process.pid}`;
  fs.writeFileSync(temporaryPath, `${JSON.stringify(state, null, 2)}\n`, { encoding: 'utf8', mode: 0o600 });
  try {
    fs.renameSync(temporaryPath, config.stateFile);
  } catch (error) {
    if (fs.existsSync(config.stateFile)) {
      fs.rmSync(config.stateFile, { force: true });
      fs.renameSync(temporaryPath, config.stateFile);
    } else {
      throw error;
    }
  }
}

saveState();

const sessions = new Map();

function sendMessage(socket, message) {
  const serialized = JSON.stringify(message);
  if (Buffer.byteLength(serialized, 'utf8') > config.maxMessageBytes) {
    throw new Error('Outgoing protocol message exceeds maxMessageBytes.');
  }
  socket.write(`${serialized}\n`, 'utf8');
}

function requeueSessionTasks(sessionId) {
  let changed = false;
  for (const task of Object.values(state.tasks)) {
    if (task.status === 'running' && task.sessionId === sessionId) {
      task.status = 'queued';
      task.sessionId = null;
      task.deadline = null;
      task.updatedAt = new Date().toISOString();
      if (!state.queue.includes(task.id)) {
        state.queue.unshift(task.id);
      }
      changed = true;
    }
  }
  if (changed) {
    saveState();
  }
}

function dispatchNext(agentId) {
  const session = sessions.get(agentId);
  if (!session || session.socket.destroyed) {
    return;
  }

  let runningCount = Object.values(state.tasks).filter(
    (task) => task.agentId === agentId && task.status === 'running'
  ).length;
  while (runningCount < session.maxConcurrentTasks) {
    const queueIndex = state.queue.findIndex((taskId) => {
      const task = state.tasks[taskId];
      return task && task.agentId === agentId && task.status === 'queued';
    });
    if (queueIndex < 0) {
      return;
    }

    const [taskId] = state.queue.splice(queueIndex, 1);
    const task = state.tasks[taskId];
    task.status = 'running';
    task.sessionId = session.sessionId;
    task.attempts += 1;
    task.updatedAt = new Date().toISOString();
    task.deadline = new Date(Date.now() + task.timeoutSeconds * 1000).toISOString();
    saveState();

    try {
      sendMessage(session.socket, {
        type: 'task',
        protocol: PROTOCOL_VERSION,
        id: task.id,
        action: task.action,
        args: task.args,
        deadline: task.deadline,
      });
      runningCount += 1;
      log('INFO', 'Dispatched task.', {
        agentId,
        taskId: task.id,
        action: task.action,
        attempt: task.attempts,
        activeTasks: runningCount,
      });
    } catch (error) {
      log('WARN', 'Task dispatch failed; closing session.', { agentId, taskId: task.id, error: error.message });
      session.socket.destroy();
      return;
    }
  }
}

function handleResult(session, message) {
  if (typeof message.id !== 'string') {
    throw new Error('Result id is required.');
  }
  const task = state.tasks[message.id];
  if (!task || task.agentId !== session.agentId || task.status !== 'running' || task.sessionId !== session.sessionId) {
    throw new Error('Result does not match the active task.');
  }

  task.status = message.ok === true ? 'succeeded' : 'failed';
  task.updatedAt = new Date().toISOString();
  task.completedAt = task.updatedAt;
  task.result = {
    ok: message.ok === true,
    output: message.output === undefined ? null : jsonClone(message.output),
    error: message.error === undefined ? null : jsonClone(message.error),
    startedAt: typeof message.startedAt === 'string' ? message.startedAt : null,
    completedAt: typeof message.completedAt === 'string' ? message.completedAt : null,
    durationMs: Number.isFinite(message.durationMs) ? message.durationMs : null,
  };
  task.sessionId = null;
  task.deadline = null;
  saveState();
  log('INFO', 'Stored task result.', { agentId: session.agentId, taskId: task.id, ok: task.result.ok });
  dispatchNext(session.agentId);
}

function authenticateSession(session, message) {
  if (message.type !== 'authenticate' || message.protocol !== PROTOCOL_VERSION) {
    throw new Error('Expected authenticate message.');
  }
  if (typeof message.agentId !== 'string' || !Object.prototype.hasOwnProperty.call(config.agents, message.agentId)) {
    throw new Error('Agent identity is unknown.');
  }
  if (typeof message.nonce !== 'string' || !/^[a-f0-9]{64}$/.test(message.nonce)) {
    throw new Error('Client nonce is invalid.');
  }
  const requestedConcurrency = message.maxConcurrentTasks === undefined ? 1 : Number(message.maxConcurrentTasks);
  if (!Number.isInteger(requestedConcurrency) || requestedConcurrency < 1 || requestedConcurrency > 64) {
    throw new Error('Client task concurrency must be between 1 and 64.');
  }

  const secret = config.agents[message.agentId];
  const authText = `auth|${PROTOCOL_VERSION}|${message.agentId}|${session.serverNonce}|${message.nonce}`;
  const expectedProof = hmacHex(secret, authText);
  if (!fixedTimeEqual(expectedProof, message.proof)) {
    throw new Error('Agent authentication proof is invalid.');
  }

  const existing = sessions.get(message.agentId);
  if (existing) {
    requeueSessionTasks(existing.sessionId);
    existing.socket.destroy();
  }

  session.authenticated = true;
  session.agentId = message.agentId;
  session.clientNonce = message.nonce;
  session.sessionId = crypto.randomUUID();
  session.connectedAt = new Date().toISOString();
  session.lastSeen = Date.now();
  session.maxConcurrentTasks = Math.min(config.maxConcurrentTasksPerAgent, requestedConcurrency);
  clearTimeout(session.authTimer);
  sessions.set(session.agentId, session);

  const readyText = `ready|${PROTOCOL_VERSION}|${session.agentId}|${session.serverNonce}|${session.clientNonce}|${session.sessionId}`;
  sendMessage(session.socket, {
    type: 'ready',
    protocol: PROTOCOL_VERSION,
    sessionId: session.sessionId,
    proof: hmacHex(secret, readyText),
    allowedActions: Array.from(ALLOWED_ACTIONS),
    maxConcurrentTasks: session.maxConcurrentTasks,
    serverTime: new Date().toISOString(),
  });
  log('INFO', 'Agent authenticated.', { agentId: session.agentId, sessionId: session.sessionId });
  dispatchNext(session.agentId);
}

function closeForProtocolError(session, error) {
  log('WARN', 'Agent protocol error.', { agentId: session.agentId, error: error.message });
  try {
    sendMessage(session.socket, { type: 'error', protocol: PROTOCOL_VERSION, message: error.message });
  } catch (_) {
    // Connection cleanup below is authoritative.
  }
  session.socket.destroy();
}

const agentServer = net.createServer((socket) => {
  socket.setNoDelay(true);
  socket.setKeepAlive(true, 15000);
  socket.setEncoding('utf8');

  const session = {
    socket,
    authenticated: false,
    agentId: null,
    sessionId: null,
    serverNonce: crypto.randomBytes(32).toString('hex'),
    clientNonce: null,
    connectedAt: null,
    lastSeen: Date.now(),
    maxConcurrentTasks: 1,
    buffer: '',
    receivedProtocolLine: false,
    authTimer: null,
  };

  session.authTimer = setTimeout(() => closeForProtocolError(session, new Error('Authentication timed out.')), 10000);
  try {
    sendMessage(socket, {
      type: 'challenge',
      protocol: PROTOCOL_VERSION,
      nonce: session.serverNonce,
      serverTime: new Date().toISOString(),
    });
  } catch (error) {
    socket.destroy(error);
  }

  socket.on('data', (chunk) => {
    session.buffer += chunk;
    if (Buffer.byteLength(session.buffer, 'utf8') > config.maxMessageBytes * 2) {
      closeForProtocolError(session, new Error('Input buffer exceeds the protocol limit.'));
      return;
    }

    let newlineIndex;
    while ((newlineIndex = session.buffer.indexOf('\n')) >= 0) {
      let line = session.buffer.slice(0, newlineIndex).replace(/\r$/, '');
      session.buffer = session.buffer.slice(newlineIndex + 1);
      if (!session.receivedProtocolLine) {
        line = line.replace(/^\uFEFF/, '');
        session.receivedProtocolLine = true;
      }
      if (Buffer.byteLength(line, 'utf8') > config.maxMessageBytes) {
        closeForProtocolError(session, new Error('Protocol message exceeds maxMessageBytes.'));
        return;
      }

      let message;
      try {
        message = JSON.parse(line);
        session.lastSeen = Date.now();
        if (!session.authenticated) {
          authenticateSession(session, message);
        } else if (message.type === 'pong' && message.protocol === PROTOCOL_VERSION) {
          // lastSeen was updated above.
        } else if (message.type === 'result' && message.protocol === PROTOCOL_VERSION) {
          handleResult(session, message);
        } else {
          throw new Error('Unexpected message type from authenticated agent.');
        }
      } catch (error) {
        closeForProtocolError(session, error);
        return;
      }
    }
  });

  socket.on('error', (error) => {
    log('WARN', 'Agent socket error.', { agentId: session.agentId, error: error.message });
  });

  socket.on('close', () => {
    clearTimeout(session.authTimer);
    if (session.authenticated && sessions.get(session.agentId) === session) {
      sessions.delete(session.agentId);
      requeueSessionTasks(session.sessionId);
      log('INFO', 'Agent disconnected.', { agentId: session.agentId, sessionId: session.sessionId });
    }
  });
});

agentServer.on('error', (error) => {
  log('ERROR', 'Agent listener failed.', { error: error.message });
  process.exitCode = 1;
});

function isControlAuthorized(request) {
  const authorization = request.headers.authorization;
  if (typeof authorization !== 'string' || !authorization.startsWith('Bearer ')) {
    return false;
  }
  return fixedTimeEqual(config.controlToken, authorization.slice('Bearer '.length));
}

function writeJson(response, statusCode, body) {
  const payload = `${JSON.stringify(body)}\n`;
  response.writeHead(statusCode, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(payload),
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
  });
  response.end(payload);
}

function readJsonBody(request) {
  return new Promise((resolve, reject) => {
    let body = '';
    request.setEncoding('utf8');
    request.on('data', (chunk) => {
      body += chunk;
      if (Buffer.byteLength(body, 'utf8') > 65536) {
        reject(new Error('Request body exceeds 65536 bytes.'));
        request.destroy();
      }
    });
    request.on('end', () => {
      try {
        resolve(body.length === 0 ? {} : JSON.parse(body));
      } catch (error) {
        reject(new Error(`Request body is invalid JSON: ${error.message}`));
      }
    });
    request.on('error', reject);
  });
}

function getStatus() {
  const agents = Object.keys(config.agents).sort().map((agentId) => {
    const session = sessions.get(agentId);
    const activeTasks = Object.values(state.tasks).filter(
      task => task.agentId === agentId && task.status === 'running'
    ).length;
    return {
      agentId,
      connected: Boolean(session && !session.socket.destroyed),
      sessionId: session ? session.sessionId : null,
      connectedAt: session ? session.connectedAt : null,
      lastSeen: session ? new Date(session.lastSeen).toISOString() : null,
      activeTasks,
      maxConcurrentTasks: session ? session.maxConcurrentTasks : config.maxConcurrentTasksPerAgent,
    };
  });
  const taskCounts = {};
  for (const task of Object.values(state.tasks)) {
    taskCounts[task.status] = (taskCounts[task.status] || 0) + 1;
  }
  return { ok: true, uptimeSeconds: Math.round(process.uptime()), agents, taskCounts };
}

const controlServer = http.createServer(async (request, response) => {
  if (!isControlAuthorized(request)) {
    writeJson(response, 401, { error: 'UNAUTHORIZED', message: 'A valid bearer token is required.' });
    return;
  }

  const requestUrl = new URL(request.url, 'http://localhost');
  try {
    if (request.method === 'GET' && requestUrl.pathname === '/health') {
      writeJson(response, 200, { ok: true, protocol: PROTOCOL_VERSION });
      return;
    }
    if (request.method === 'GET' && requestUrl.pathname === '/v1/status') {
      writeJson(response, 200, getStatus());
      return;
    }
    if (request.method === 'POST' && requestUrl.pathname === '/v1/tasks') {
      const body = await readJsonBody(request);
      if (typeof body.agentId !== 'string' || !Object.prototype.hasOwnProperty.call(config.agents, body.agentId)) {
        writeJson(response, 400, { error: 'INVALID_AGENT', message: 'agentId must name a configured agent.' });
        return;
      }
      if (typeof body.action !== 'string' || !ALLOWED_ACTIONS.has(body.action)) {
        writeJson(response, 400, { error: 'INVALID_ACTION', message: 'action is outside the server allowlist.' });
        return;
      }
      const args = body.args === undefined ? {} : body.args;
      if (args === null || typeof args !== 'object' || Array.isArray(args)) {
        writeJson(response, 400, { error: 'INVALID_ARGS', message: 'args must be a JSON object.' });
        return;
      }
      if (body.action === 'powershell' && typeof args.script !== 'string') {
        writeJson(response, 400, { error: 'INVALID_ARGS', message: 'powershell requires args.script as a string.' });
        return;
      }
      const timeoutSeconds = body.timeoutSeconds === undefined ? 30 : Number(body.timeoutSeconds);
      if (!Number.isInteger(timeoutSeconds) || timeoutSeconds < 1 || timeoutSeconds > config.maxTaskTimeoutSeconds) {
        writeJson(response, 400, { error: 'INVALID_TIMEOUT', message: 'timeoutSeconds is outside the configured range.' });
        return;
      }

      const now = new Date().toISOString();
      const task = {
        id: crypto.randomUUID(),
        agentId: body.agentId,
        action: body.action,
        args: jsonClone(args),
        timeoutSeconds,
        status: 'queued',
        attempts: 0,
        createdAt: now,
        updatedAt: now,
        completedAt: null,
        sessionId: null,
        deadline: null,
        result: null,
      };
      state.tasks[task.id] = task;
      state.queue.push(task.id);
      saveState();
      log('INFO', 'Queued task.', { agentId: task.agentId, taskId: task.id, action: task.action });
      dispatchNext(task.agentId);
      writeJson(response, 202, task);
      return;
    }

    const taskMatch = requestUrl.pathname.match(/^\/v1\/tasks\/([A-Za-z0-9-]{8,64})$/);
    if (request.method === 'GET' && taskMatch) {
      const task = state.tasks[taskMatch[1]];
      if (!task) {
        writeJson(response, 404, { error: 'TASK_NOT_FOUND', message: 'Task id was not found.' });
        return;
      }
      writeJson(response, 200, task);
      return;
    }

    if (request.method === 'POST' && requestUrl.pathname === '/v1/test/disconnect' && config.enableTestHooks) {
      const body = await readJsonBody(request);
      const session = sessions.get(body.agentId);
      if (!session) {
        writeJson(response, 404, { error: 'AGENT_OFFLINE', message: 'Agent has no active session.' });
        return;
      }
      const oldSessionId = session.sessionId;
      writeJson(response, 202, { ok: true, agentId: body.agentId, sessionId: oldSessionId });
      setImmediate(() => session.socket.destroy());
      return;
    }

    writeJson(response, 404, { error: 'NOT_FOUND', message: 'Route was not found.' });
  } catch (error) {
    log('WARN', 'Control request failed.', { method: request.method, path: requestUrl.pathname, error: error.message });
    if (!response.headersSent) {
      writeJson(response, 400, { error: 'BAD_REQUEST', message: error.message });
    } else {
      response.destroy();
    }
  }
});

controlServer.on('error', (error) => {
  log('ERROR', 'Control listener failed.', { error: error.message });
  process.exitCode = 1;
});

const heartbeatTimer = setInterval(() => {
  const now = Date.now();
  for (const session of sessions.values()) {
    if (now - session.lastSeen > config.sessionTimeoutSeconds * 1000) {
      log('WARN', 'Agent heartbeat timed out.', { agentId: session.agentId, sessionId: session.sessionId });
      session.socket.destroy();
      continue;
    }
    try {
      sendMessage(session.socket, { type: 'ping', protocol: PROTOCOL_VERSION, at: new Date(now).toISOString() });
    } catch (error) {
      session.socket.destroy();
    }
  }
}, config.heartbeatSeconds * 1000);
heartbeatTimer.unref();

agentServer.listen(config.agentListen.port, config.agentListen.host, () => {
  log('INFO', 'Agent bridge listener ready.', config.agentListen);
});
controlServer.listen(config.controlListen.port, config.controlListen.host, () => {
  log('INFO', 'Control API ready.', config.controlListen);
});

let stopping = false;
function stop(signal) {
  if (stopping) {
    return;
  }
  stopping = true;
  log('INFO', 'Stopping broker.', { signal });
  clearInterval(heartbeatTimer);
  for (const session of sessions.values()) {
    session.socket.destroy();
  }
  saveState();
  agentServer.close();
  controlServer.close(() => process.exit(0));
  setTimeout(() => process.exit(0), 2000).unref();
}

process.on('SIGINT', () => stop('SIGINT'));
process.on('SIGTERM', () => stop('SIGTERM'));
