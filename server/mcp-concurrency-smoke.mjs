import assert from 'node:assert/strict';
import path from 'node:path';
import process from 'node:process';
import { Client } from '@modelcontextprotocol/client';
import { StdioClientTransport } from '@modelcontextprotocol/client/stdio';

function parseArguments(argv) {
  const result = {};
  for (let index = 0; index < argv.length; index += 2) {
    const name = argv[index];
    const value = argv[index + 1];
    if (!name?.startsWith('--') || value === undefined) {
      throw new Error('Usage: node mcp-concurrency-smoke.mjs --server <path> --agent <id> --marker <value> [--cwd <path>]');
    }
    result[name.slice(2)] = value;
  }
  return result;
}

function inheritedEnvironment() {
  return Object.fromEntries(
    Object.entries(process.env).filter(entry => typeof entry[1] === 'string'),
  );
}

function resultValue(result) {
  if (result.structuredContent !== undefined) {
    return result.structuredContent;
  }
  const textBlock = result.content?.find(block => block.type === 'text');
  if (!textBlock) {
    throw new Error('MCP tool result contains neither structuredContent nor text content.');
  }
  return JSON.parse(textBlock.text);
}

function escapePowerShellSingleQuoted(value) {
  return value.replaceAll("'", "''");
}

function createConnection(serverPath, workingDirectory, suffix) {
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [serverPath],
    cwd: workingDirectory,
    env: inheritedEnvironment(),
    stderr: 'pipe',
  });
  let standardError = '';
  transport.stderr?.on('data', chunk => {
    standardError += chunk.toString('utf8');
  });
  const client = new Client({ name: `ps-tunnel-concurrency-${suffix}`, version: '1.0.0' });
  return { client, transport, standardError: () => standardError };
}

async function main() {
  const options = parseArguments(process.argv.slice(2));
  if (!options.server || !options.agent || !options.marker) {
    throw new Error('Usage: node mcp-concurrency-smoke.mjs --server <path> --agent <id> --marker <value> [--cwd <path>]');
  }

  const serverPath = path.resolve(options.server);
  const workingDirectory = options.cwd ? path.resolve(options.cwd) : path.dirname(serverPath);
  const connections = [
    createConnection(serverPath, workingDirectory, 'a'),
    createConnection(serverPath, workingDirectory, 'b'),
  ];

  try {
    await Promise.all(connections.map(({ client, transport }) => client.connect(transport)));
    const agentResults = await Promise.all(connections.map(({ client }) => client.callTool({
      name: 'list_agents',
      arguments: {},
    })));
    for (const result of agentResults) {
      assert.equal(result.isError, undefined);
      const agent = resultValue(result).agents.find(item => item.agentId === options.agent);
      assert.equal(agent?.connected, true);
      assert.ok(agent.maxConcurrentTasks >= 2);
    }

    const markers = [`${options.marker}-a`, `${options.marker}-b`];
    const startedAt = Date.now();
    const taskResults = await Promise.all(connections.map(({ client }, index) => client.callTool({
      name: 'run_powershell',
      arguments: {
        agentId: options.agent,
        script: `Start-Sleep -Seconds 7; [pscustomobject]@{ marker = '${escapePowerShellSingleQuoted(markers[index])}'; instance = '${index + 1}' }`,
        timeoutSeconds: 10,
        waitTimeoutSeconds: 15,
      },
    })));
    const elapsedMs = Date.now() - startedAt;

    const tasks = taskResults.map((result, index) => {
      assert.equal(result.isError, undefined);
      const task = resultValue(result);
      assert.equal(task.status, 'succeeded');
      assert.equal(task.waitTimedOut, false);
      assert.equal(task.result.output.marker, markers[index]);
      assert.equal(task.result.output.instance, String(index + 1));
      return task;
    });
    assert.ok(elapsedMs < 12000, `Parallel MCP calls took ${elapsedMs} ms.`);

    process.stdout.write(`${JSON.stringify({
      ok: true,
      elapsedMs,
      taskIds: tasks.map(task => task.id),
      markers,
    })}\n`);
  } catch (error) {
    for (const connection of connections) {
      const standardError = connection.standardError();
      if (standardError.trim().length > 0) {
        process.stderr.write(standardError);
      }
    }
    throw error;
  } finally {
    await Promise.allSettled(connections.map(({ client }) => client.close()));
  }
}

main().catch(error => {
  process.stderr.write(`MCP concurrency smoke test failed: ${error.stack || error.message}\n`);
  process.exitCode = 1;
});
