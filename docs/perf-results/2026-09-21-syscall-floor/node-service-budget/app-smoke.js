'use strict';

const assert = require('assert');
const childProcess = require('child_process');
const crypto = require('crypto');
const fs = require('fs');
const net = require('net');
const os = require('os');
const path = require('path');
const { Worker } = require('worker_threads');

async function main() {
  process.title = 'carrick-nodejs-app-smoke';
  process.stdout.write('');

  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'nodejs-app-smoke-'));
  const file = path.join(dir, 'data.txt');
  fs.writeFileSync(file, 'hello');
  assert.strictEqual(fs.readFileSync(file, 'utf8'), 'hello');
  assert.strictEqual(crypto.randomBytes(16).length, 16);

  const child = childProcess.execFileSync(process.execPath, [
    '-e',
    'process.stdout.write(process.argv[1])',
    'child-ok'
  ], { encoding: 'utf8' });
  assert.strictEqual(child, 'child-ok');

  const server = net.createServer((socket) => {
    socket.once('data', (buf) => {
      socket.end(Buffer.from(buf.toString().toUpperCase()));
    });
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  const tcpReply = await new Promise((resolve, reject) => {
    const client = net.createConnection({ host: '127.0.0.1', port }, () => {
      client.write('tcp-ok');
    });
    client.once('data', (buf) => resolve(buf.toString()));
    client.once('error', reject);
  });
  server.close();
  assert.strictEqual(tcpReply, 'TCP-OK');

  const worker = new Worker(`
    const { parentPort } = require('worker_threads');
    parentPort.postMessage(42);
  `, { eval: true });
  const answer = await new Promise((resolve, reject) => {
    worker.once('message', resolve);
    worker.once('error', reject);
  });
  assert.strictEqual(answer, 42);

  await new Promise((resolve) => setTimeout(resolve, 1));
  console.log('app-smoke ok');
}

main().catch((err) => {
  console.error(err && err.stack ? err.stack : err);
  process.exit(1);
});
