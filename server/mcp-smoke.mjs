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
      throw new Error('Usage: node mcp-smoke.mjs --server <path> --agent <id> --marker <value> [--cwd <path>]');
    }
    result[name.slice(2)] = value;
  }
  return result;
}

function inheritedEnvironment() {
  return Object.fromEntries(
    Object.entries(process.env).filter((entry) => typeof entry[1] === 'string'),
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

async function delay(milliseconds) {
  await new Promise(resolve => setTimeout(resolve, milliseconds));
}

async function main() {
  const options = parseArguments(process.argv.slice(2));
  if (!options.server || !options.agent || !options.marker) {
    throw new Error('Usage: node mcp-smoke.mjs --server <path> --agent <id> --marker <value> [--cwd <path>]');
  }

  const serverPath = path.resolve(options.server);
  const workingDirectory = options.cwd ? path.resolve(options.cwd) : path.dirname(serverPath);
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [serverPath],
    cwd: workingDirectory,
    env: inheritedEnvironment(),
    stderr: 'pipe',
  });
  let serverStandardError = '';
  transport.stderr?.on('data', chunk => {
    serverStandardError += chunk.toString('utf8');
  });
  const client = new Client({ name: 'ps-tunnel-mcp-smoke', version: '1.0.0' });

  try {
    await client.connect(transport);
    const listed = await client.listTools();
    const toolNames = listed.tools.map(tool => tool.name).sort();
    assert.deepEqual(toolNames, ['get_task', 'list_agents', 'run_powershell', 'submit_powershell']);

    let selectedAgent = null;
    const agentDeadline = Date.now() + 15000;
    while ((!selectedAgent || !selectedAgent.connected) && Date.now() < agentDeadline) {
      const agentsResult = await client.callTool({ name: 'list_agents', arguments: {} });
      assert.equal(agentsResult.isError, undefined);
      const agents = resultValue(agentsResult);
      selectedAgent = agents.agents.find(agent => agent.agentId === options.agent);
      if (!selectedAgent?.connected) {
        await delay(200);
      }
    }
    assert.ok(selectedAgent, `Agent ${options.agent} was not returned by list_agents.`);
    assert.equal(selectedAgent.connected, true);

    const escapedMarker = escapePowerShellSingleQuoted(options.marker);
    const runResult = await client.callTool({
      name: 'run_powershell',
      arguments: {
        agentId: options.agent,
        script: `[pscustomobject]@{ marker = '${escapedMarker}'; total = ((1..5 | Measure-Object -Sum).Sum); mode = 'run' }`,
        timeoutSeconds: 10,
        waitTimeoutSeconds: 15,
      },
    });
    assert.equal(runResult.isError, undefined);
    const runTask = resultValue(runResult);
    assert.equal(runTask.status, 'succeeded');
    assert.equal(runTask.waitTimedOut, false);
    assert.equal(runTask.result.output.marker, options.marker);
    assert.equal(runTask.result.output.total, 15);
    assert.equal(runTask.result.output.mode, 'run');

    const submittedMarker = `${options.marker}-submitted`;
    const submitResult = await client.callTool({
      name: 'submit_powershell',
      arguments: {
        agentId: options.agent,
        script: `[pscustomobject]@{ marker = '${escapePowerShellSingleQuoted(submittedMarker)}'; mode = 'submit' }`,
        timeoutSeconds: 10,
      },
    });
    assert.equal(submitResult.isError, undefined);
    let submittedTask = resultValue(submitResult);
    const deadline = Date.now() + 15000;
    while (!['succeeded', 'failed'].includes(submittedTask.status) && Date.now() < deadline) {
      await delay(200);
      const taskResult = await client.callTool({
        name: 'get_task',
        arguments: { taskId: submittedTask.id },
      });
      assert.equal(taskResult.isError, undefined);
      submittedTask = resultValue(taskResult);
    }
    assert.equal(submittedTask.status, 'succeeded');
    assert.equal(submittedTask.result.output.marker, submittedMarker);
    assert.equal(submittedTask.result.output.mode, 'submit');

    process.stdout.write(`${JSON.stringify({
      ok: true,
      agentId: options.agent,
      marker: options.marker,
      tools: toolNames,
      runTaskId: runTask.id,
      submittedTaskId: submittedTask.id,
    })}\n`);
  } catch (error) {
    if (serverStandardError.trim().length > 0) {
      process.stderr.write(serverStandardError);
    }
    throw error;
  } finally {
    await client.close();
  }
}

main().catch(error => {
  process.stderr.write(`MCP smoke test failed: ${error.stack || error.message}\n`);
  process.exitCode = 1;
});
