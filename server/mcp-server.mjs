import { McpServer } from '@modelcontextprotocol/server';
import { serveStdio } from '@modelcontextprotocol/server/stdio';
import * as z from 'zod/v4';

const SERVER_VERSION = '1.1.0';
const DEFAULT_CONTROL_BASE_URI = 'http://127.0.0.1:8766';
const CONTROL_REQUEST_TIMEOUT_MS = 10000;
const TASK_POLL_INTERVAL_MS = 200;
const TERMINAL_TASK_STATUSES = new Set(['succeeded', 'failed']);

function readConfiguration() {
  const controlToken = process.env.PS_TUNNEL_CONTROL_TOKEN;
  if (typeof controlToken !== 'string' || controlToken.length < 16) {
    throw new Error('PS_TUNNEL_CONTROL_TOKEN must contain at least 16 characters.');
  }

  const configuredBaseUri = process.env.PS_TUNNEL_CONTROL_BASE_URI;
  const controlBaseUri = (configuredBaseUri && configuredBaseUri.trim()) || DEFAULT_CONTROL_BASE_URI;
  const parsedBaseUri = new URL(controlBaseUri);
  if (parsedBaseUri.protocol !== 'http:' && parsedBaseUri.protocol !== 'https:') {
    throw new Error('PS_TUNNEL_CONTROL_BASE_URI must use http or https.');
  }

  return {
    controlToken,
    controlBaseUri: parsedBaseUri.href.replace(/\/$/, ''),
  };
}

function createRequestSignal(parentSignal, timeoutMilliseconds) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(new Error('Control API request timed out.')), timeoutMilliseconds);
  const abortFromParent = () => controller.abort(parentSignal.reason);

  if (parentSignal) {
    if (parentSignal.aborted) {
      abortFromParent();
    } else {
      parentSignal.addEventListener('abort', abortFromParent, { once: true });
    }
  }

  return {
    signal: controller.signal,
    dispose() {
      clearTimeout(timeout);
      parentSignal?.removeEventListener('abort', abortFromParent);
    },
  };
}

async function requestJson(configuration, method, path, body, parentSignal) {
  const requestSignal = createRequestSignal(parentSignal, CONTROL_REQUEST_TIMEOUT_MS);
  try {
    const response = await fetch(`${configuration.controlBaseUri}${path}`, {
      method,
      headers: {
        Authorization: `Bearer ${configuration.controlToken}`,
        Accept: 'application/json',
        ...(body === undefined ? {} : { 'Content-Type': 'application/json; charset=utf-8' }),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: requestSignal.signal,
    });

    const responseText = await response.text();
    let responseBody = null;
    if (responseText.length > 0) {
      try {
        responseBody = JSON.parse(responseText);
      } catch (error) {
        throw new Error(`Control API returned invalid JSON: ${error.message}`);
      }
    }

    if (!response.ok) {
      const code = responseBody && typeof responseBody.error === 'string' ? responseBody.error : `HTTP_${response.status}`;
      const message = responseBody && typeof responseBody.message === 'string'
        ? responseBody.message
        : response.statusText;
      throw new Error(`Control API ${code}: ${message}`);
    }
    return responseBody;
  } finally {
    requestSignal.dispose();
  }
}

function normalizeAgent(agent) {
  return {
    agentId: String(agent.agentId),
    connected: agent.connected === true,
    sessionId: agent.sessionId === null || agent.sessionId === undefined ? null : String(agent.sessionId),
    connectedAt: agent.connectedAt === null || agent.connectedAt === undefined ? null : String(agent.connectedAt),
    lastSeen: agent.lastSeen === null || agent.lastSeen === undefined ? null : String(agent.lastSeen),
  };
}

function normalizeTask(task) {
  const result = task.result === null || task.result === undefined
    ? null
    : {
        ok: task.result.ok === true,
        output: task.result.output === undefined ? null : task.result.output,
        error: task.result.error === undefined ? null : task.result.error,
        startedAt: task.result.startedAt === null || task.result.startedAt === undefined
          ? null
          : String(task.result.startedAt),
        completedAt: task.result.completedAt === null || task.result.completedAt === undefined
          ? null
          : String(task.result.completedAt),
        durationMs: Number.isFinite(task.result.durationMs) ? Number(task.result.durationMs) : null,
      };

  return {
    id: String(task.id),
    agentId: String(task.agentId),
    action: String(task.action),
    status: String(task.status),
    attempts: Number(task.attempts),
    timeoutSeconds: Number(task.timeoutSeconds),
    createdAt: String(task.createdAt),
    updatedAt: String(task.updatedAt),
    completedAt: task.completedAt === null || task.completedAt === undefined ? null : String(task.completedAt),
    deadline: task.deadline === null || task.deadline === undefined ? null : String(task.deadline),
    result,
  };
}

function toolResult(value, isError = false) {
  return {
    content: [{ type: 'text', text: JSON.stringify(value) }],
    structuredContent: value,
    ...(isError ? { isError: true } : {}),
  };
}

function wait(milliseconds, signal) {
  if (signal?.aborted) {
    return Promise.reject(signal.reason || new Error('MCP tool call was cancelled.'));
  }
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      signal?.removeEventListener('abort', onAbort);
      resolve();
    }, milliseconds);
    const onAbort = () => {
      clearTimeout(timer);
      reject(signal.reason || new Error('MCP tool call was cancelled.'));
    };
    signal?.addEventListener('abort', onAbort, { once: true });
  });
}

async function getTask(configuration, taskId, signal) {
  const task = await requestJson(configuration, 'GET', `/v1/tasks/${encodeURIComponent(taskId)}`, undefined, signal);
  return normalizeTask(task);
}

async function submitPowerShell(configuration, agentId, script, timeoutSeconds, signal) {
  const task = await requestJson(configuration, 'POST', '/v1/tasks', {
    agentId,
    action: 'powershell',
    args: { script },
    timeoutSeconds,
  }, signal);
  return normalizeTask(task);
}

async function waitForTask(configuration, initialTask, waitTimeoutSeconds, signal) {
  const deadline = Date.now() + (waitTimeoutSeconds * 1000);
  let task = initialTask;
  while (!TERMINAL_TASK_STATUSES.has(task.status) && Date.now() < deadline) {
    await wait(TASK_POLL_INTERVAL_MS, signal);
    task = await getTask(configuration, task.id, signal);
  }
  return task;
}

const agentSchema = z.object({
  agentId: z.string(),
  connected: z.boolean(),
  sessionId: z.string().nullable(),
  connectedAt: z.string().nullable(),
  lastSeen: z.string().nullable(),
});

const taskResultSchema = z.object({
  ok: z.boolean(),
  output: z.json(),
  error: z.json(),
  startedAt: z.string().nullable(),
  completedAt: z.string().nullable(),
  durationMs: z.number().nullable(),
});

const taskSchema = z.object({
  id: z.string(),
  agentId: z.string(),
  action: z.string(),
  status: z.enum(['queued', 'running', 'succeeded', 'failed']),
  attempts: z.number().int().nonnegative(),
  timeoutSeconds: z.number().int().positive(),
  createdAt: z.string(),
  updatedAt: z.string(),
  completedAt: z.string().nullable(),
  deadline: z.string().nullable(),
  result: taskResultSchema.nullable(),
});

const agentIdSchema = z.string()
  .regex(/^[A-Za-z0-9._-]{1,64}$/)
  .describe('Configured PS Tunnel agent ID. Call list_agents to discover available IDs.');
const taskIdSchema = z.string()
  .regex(/^[A-Za-z0-9-]{8,64}$/)
  .describe('Task ID returned by submit_powershell or run_powershell.');
const scriptSchema = z.string().describe('Complete PowerShell script to execute on the managed Windows agent.');
const timeoutSchema = z.number().int().min(1).max(3600).default(30)
  .describe('Client-side PowerShell execution timeout in seconds.');

function createServer() {
  const configuration = readConfiguration();
  const server = new McpServer(
    { name: 'ps-tunnel', version: SERVER_VERSION },
    {
      instructions: 'Use list_agents before targeting an agent. Use run_powershell for one-step execution and submit_powershell plus get_task for longer asynchronous work. PowerShell tools execute the supplied script on the selected managed Windows agent. Return task IDs when work remains queued or running.',
    },
  );

  server.registerTool(
    'list_agents',
    {
      title: 'List PS Tunnel agents',
      description: 'List configured PS Tunnel agents, connection state, session IDs, and task counts.',
      outputSchema: z.object({
        ok: z.boolean(),
        uptimeSeconds: z.number().nonnegative(),
        agents: z.array(agentSchema),
        taskCounts: z.record(z.string(), z.number().int().nonnegative()),
      }),
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
      },
    },
    async context => {
      const status = await requestJson(configuration, 'GET', '/v1/status', undefined, context.signal);
      const output = {
        ok: status.ok === true,
        uptimeSeconds: Number(status.uptimeSeconds),
        agents: Array.isArray(status.agents) ? status.agents.map(normalizeAgent) : [],
        taskCounts: status.taskCounts && typeof status.taskCounts === 'object' ? status.taskCounts : {},
      };
      return toolResult(output);
    },
  );

  server.registerTool(
    'submit_powershell',
    {
      title: 'Submit PowerShell',
      description: 'Submit an arbitrary PowerShell script to a managed agent and return immediately with its task ID.',
      inputSchema: z.object({
        agentId: agentIdSchema,
        script: scriptSchema,
        timeoutSeconds: timeoutSchema,
      }).strict(),
      outputSchema: taskSchema,
      annotations: {
        readOnlyHint: false,
        destructiveHint: true,
        idempotentHint: false,
        openWorldHint: true,
      },
    },
    async ({ agentId, script, timeoutSeconds }, context) => {
      const task = await submitPowerShell(configuration, agentId, script, timeoutSeconds, context.signal);
      return toolResult(task);
    },
  );

  server.registerTool(
    'get_task',
    {
      title: 'Get PS Tunnel task',
      description: 'Get the current state and full result of one PS Tunnel task.',
      inputSchema: z.object({ taskId: taskIdSchema }).strict(),
      outputSchema: taskSchema,
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
      },
    },
    async ({ taskId }, context) => toolResult(await getTask(configuration, taskId, context.signal)),
  );

  server.registerTool(
    'run_powershell',
    {
      title: 'Run PowerShell',
      description: 'Execute an arbitrary PowerShell script on a connected managed agent and wait for its full result.',
      inputSchema: z.object({
        agentId: agentIdSchema,
        script: scriptSchema,
        timeoutSeconds: timeoutSchema,
        waitTimeoutSeconds: z.number().int().min(1).max(3600).optional()
          .describe('Maximum time to wait for a terminal task state. Defaults to timeoutSeconds plus 15 seconds.'),
      }).strict(),
      outputSchema: taskSchema.extend({ waitTimedOut: z.boolean() }),
      annotations: {
        readOnlyHint: false,
        destructiveHint: true,
        idempotentHint: false,
        openWorldHint: true,
      },
    },
    async ({ agentId, script, timeoutSeconds, waitTimeoutSeconds }, context) => {
      const submitted = await submitPowerShell(configuration, agentId, script, timeoutSeconds, context.signal);
      const task = await waitForTask(
        configuration,
        submitted,
        waitTimeoutSeconds ?? Math.min(3600, timeoutSeconds + 15),
        context.signal,
      );
      const output = { ...task, waitTimedOut: !TERMINAL_TASK_STATUSES.has(task.status) };
      return toolResult(output, output.waitTimedOut || output.status === 'failed');
    },
  );

  return server;
}

try {
  serveStdio(createServer, {
    onerror(error) {
      console.error(`PS Tunnel MCP transport error: ${error.message}`);
    },
  });
  console.error(`PS Tunnel MCP ${SERVER_VERSION} running on stdio.`);
} catch (error) {
  console.error(`PS Tunnel MCP failed to start: ${error.message}`);
  process.exitCode = 1;
}
