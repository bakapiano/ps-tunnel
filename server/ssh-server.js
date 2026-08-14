'use strict';

const { createHash, timingSafeEqual } = require('crypto');
const fs = require('fs');
const net = require('net');
const path = require('path');
const { Server, utils } = require('ssh2');

function parseArguments(argv) {
  const result = {};
  for (let index = 0; index < argv.length; index += 1) {
    if (argv[index] !== '--config' || !argv[index + 1]) {
      throw new Error('Usage: node ssh-server.js --config <config.json>');
    }
    result.config = argv[index + 1];
    index += 1;
  }
  return result;
}

function log(level, message, fields) {
  const suffix = fields ? ` ${JSON.stringify(fields)}` : '';
  process.stderr.write(`${new Date().toISOString()} [${level}] ${message}${suffix}\n`);
}

function checkValue(input, allowed) {
  let expected = allowed;
  const lengthMismatch = input.length !== expected.length;
  if (lengthMismatch) {
    expected = input;
  }
  const matches = timingSafeEqual(input, expected);
  return !lengthMismatch && matches;
}

function keyFingerprint(data) {
  if (!Buffer.isBuffer(data)) {
    return null;
  }
  return `SHA256:${createHash('sha256').update(data).digest('base64').replace(/=+$/, '')}`;
}

const args = parseArguments(process.argv.slice(2));
if (!args.config) {
  throw new Error('Usage: node ssh-server.js --config <config.json>');
}

const configPath = path.resolve(args.config);
const configDirectory = path.dirname(configPath);
const config = JSON.parse(fs.readFileSync(configPath, 'utf8').replace(/^\uFEFF/, ''));
const ssh = config.ssh || {};
ssh.host = ssh.host || '0.0.0.0';
ssh.port = Number(ssh.port || 2222);
ssh.user = ssh.user || 'agent-a';
ssh.hostKeyFile = path.resolve(configDirectory, ssh.hostKeyFile || 'ssh-host-ed25519');
ssh.authorizedKeyFile = path.resolve(configDirectory, ssh.authorizedKeyFile || 'agent-a-ed25519.pub');
ssh.brokerHost = ssh.brokerHost || '127.0.0.1';
ssh.brokerPort = Number(ssh.brokerPort || 8765);

if (!Number.isInteger(ssh.port) || ssh.port < 1024 || ssh.port > 65535) {
  throw new Error('SSH port must be an integer from 1024 through 65535.');
}
if (!Number.isInteger(ssh.brokerPort) || ssh.brokerPort < 1 || ssh.brokerPort > 65535) {
  throw new Error('Broker port is invalid.');
}
if (!['127.0.0.1', '::1', 'localhost'].includes(ssh.brokerHost)) {
  throw new Error('Broker target must use a loopback address.');
}
if (!/^[A-Za-z0-9._-]{1,64}$/.test(ssh.user)) {
  throw new Error('SSH user is invalid.');
}

const hostKey = fs.readFileSync(ssh.hostKeyFile);
const parsedAuthorizedKey = utils.parseKey(fs.readFileSync(ssh.authorizedKeyFile));
if (parsedAuthorizedKey instanceof Error || Array.isArray(parsedAuthorizedKey)) {
  throw new Error('authorizedKeyFile must contain one valid OpenSSH public key.');
}
const allowedUser = Buffer.from(ssh.user, 'utf8');

const server = new Server({
  hostKeys: [hostKey],
  ident: 'PS-Tunnel',
  banner: 'Restricted PS Tunnel agent transport',
}, (client) => {
  const remoteAddress = client._sock && client._sock.remoteAddress ? client._sock.remoteAddress : 'unknown';
  let authenticationAttempts = 0;
  let authenticated = false;
  let sessionAccepted = false;
  let brokerSocket = null;

  client.on('authentication', (context) => {
    authenticationAttempts += 1;
    if (authenticationAttempts > 3) {
      log('WARN', 'SSH authentication attempt limit reached.', {
        remoteAddress,
        username: context.username,
        method: context.method,
      });
      context.reject();
      client.end();
      return;
    }

    const publicKeyMethod = context.method === 'publickey';
    const usernameMatches = checkValue(Buffer.from(context.username, 'utf8'), allowedUser);
    const keyTypeMatches = publicKeyMethod && context.key.algo === parsedAuthorizedKey.type;
    const keyDataMatches = publicKeyMethod
      && checkValue(context.key.data, parsedAuthorizedKey.getPublicSSH());
    const signatureMatches = !publicKeyMethod
      || !context.signature
      || parsedAuthorizedKey.verify(context.blob, context.signature, context.hashAlgo) === true;

    if (!publicKeyMethod || !usernameMatches || !keyTypeMatches || !keyDataMatches || !signatureMatches) {
      log('WARN', 'SSH authentication rejected.', {
        remoteAddress,
        attempt: authenticationAttempts,
        username: context.username,
        method: context.method,
        keyType: publicKeyMethod ? context.key.algo : null,
        keyFingerprint: publicKeyMethod ? keyFingerprint(context.key.data) : null,
        usernameMatches,
        keyTypeMatches,
        keyDataMatches,
        signaturePresented: Boolean(context.signature),
        signatureMatches,
      });
      context.reject(['publickey']);
      return;
    }
    context.accept();
  });

  client.on('ready', () => {
    authenticated = true;
    log('INFO', 'SSH agent authenticated.', { remoteAddress, user: ssh.user });

    client.on('session', (acceptSession, rejectSession) => {
      if (sessionAccepted) {
        rejectSession();
        return;
      }
      sessionAccepted = true;
      const session = acceptSession();
      let channelOpened = false;

      session.on('pty', (accept, reject) => reject());
      session.on('env', (accept, reject) => reject());
      session.on('x11', (accept, reject) => reject());

      function openBrokerChannel(accept, reject) {
        if (channelOpened) {
          reject();
          return;
        }
        channelOpened = true;
        const stream = accept();
        stream.pause();
        brokerSocket = net.createConnection({ host: ssh.brokerHost, port: ssh.brokerPort });
        brokerSocket.setNoDelay(true);
        brokerSocket.setKeepAlive(true, 15000);

        brokerSocket.once('connect', () => {
          stream.pipe(brokerSocket);
          brokerSocket.pipe(stream);
          stream.resume();
          log('INFO', 'SSH channel attached to broker.', { remoteAddress });
        });
        brokerSocket.on('error', (error) => {
          log('WARN', 'Broker connection failed.', { remoteAddress, error: error.message });
          if (stream.stderr) {
            stream.stderr.write('Broker is unavailable.\n');
          }
          stream.exit(1);
          stream.end();
        });
        brokerSocket.on('close', () => {
          stream.exit(0);
          stream.end();
        });
        stream.on('close', () => {
          if (brokerSocket) {
            brokerSocket.destroy();
          }
        });
        stream.on('error', () => {
          if (brokerSocket) {
            brokerSocket.destroy();
          }
        });
      }

      session.once('shell', openBrokerChannel);
      session.once('exec', (accept, reject) => openBrokerChannel(accept, reject));
    });
  });

  client.on('error', (error) => {
    log('WARN', 'SSH client error.', { remoteAddress, authenticated, error: error.message });
  });
  client.on('close', () => {
    if (brokerSocket) {
      brokerSocket.destroy();
    }
    log('INFO', 'SSH client disconnected.', { remoteAddress, authenticated });
  });
});

server.on('error', (error) => {
  log('ERROR', 'SSH listener failed.', { error: error.message });
  process.exitCode = 1;
});

server.listen(ssh.port, ssh.host, () => {
  log('INFO', 'Restricted SSH listener ready.', { host: ssh.host, port: ssh.port, user: ssh.user });
});

let stopping = false;
function stop(signal) {
  if (stopping) {
    return;
  }
  stopping = true;
  log('INFO', 'Stopping SSH listener.', { signal });
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(0), 2000).unref();
}

process.on('SIGINT', () => stop('SIGINT'));
process.on('SIGTERM', () => stop('SIGTERM'));
