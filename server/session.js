'use strict';

const net = require('net');

function parseArguments(argv) {
  const result = { host: '127.0.0.1', port: 8765 };
  for (let index = 0; index < argv.length; index += 1) {
    const item = argv[index];
    const value = argv[index + 1];
    if (item === '--host' && value) {
      result.host = value;
      index += 1;
    } else if (item === '--port' && value) {
      result.port = Number(value);
      index += 1;
    } else {
      throw new Error(`Unexpected argument: ${item}`);
    }
  }
  if (!Number.isInteger(result.port) || result.port < 1 || result.port > 65535) {
    throw new Error('Port must be an integer from 1 through 65535.');
  }
  if (!['127.0.0.1', '::1', 'localhost'].includes(result.host)) {
    throw new Error('Session bridge target must be a loopback address.');
  }
  return result;
}

const options = parseArguments(process.argv.slice(2));
const socket = net.createConnection({ host: options.host, port: options.port });
socket.setNoDelay(true);
socket.setKeepAlive(true, 15000);

let connected = false;
socket.on('connect', () => {
  connected = true;
  process.stdin.pipe(socket);
  socket.pipe(process.stdout);
  process.stdin.resume();
});

socket.on('error', (error) => {
  process.stderr.write(`${new Date().toISOString()} session bridge: ${error.message}\n`);
  process.exitCode = 1;
});

socket.on('close', () => {
  if (connected) {
    process.stdin.unpipe(socket);
    socket.unpipe(process.stdout);
  }
  process.exit();
});

process.stdin.on('end', () => socket.end());
process.stdin.on('error', () => socket.destroy());
