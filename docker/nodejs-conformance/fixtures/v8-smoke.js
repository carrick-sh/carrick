'use strict';

const assert = require('assert');
const { Worker } = require('worker_threads');

assert.strictEqual(process.versions.v8.length > 0, true);
assert.strictEqual(/(?<=node)js/u.test('nodejs'), true);

const wasm = new Uint8Array([
  0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
  0x01, 0x07, 0x01, 0x60, 0x02, 0x7f, 0x7f, 0x01, 0x7f,
  0x03, 0x02, 0x01, 0x00,
  0x07, 0x07, 0x01, 0x03, 0x61, 0x64, 0x64, 0x00, 0x00,
  0x0a, 0x09, 0x01, 0x07, 0x00, 0x20, 0x00, 0x20, 0x01, 0x6a, 0x0b
]);

(async () => {
  const mod = await WebAssembly.compile(wasm);
  const instance = await WebAssembly.instantiate(mod);
  assert.strictEqual(instance.exports.add(20, 22), 42);

  const sab = new SharedArrayBuffer(4);
  const ia = new Int32Array(sab);
  assert.strictEqual(Atomics.add(ia, 0, 3), 0);
  assert.strictEqual(Atomics.load(ia, 0), 3);

  const collator = new Intl.Collator('en');
  assert.strictEqual(collator.compare('a', 'b') < 0, true);
  if (globalThis.Temporal) {
    assert.strictEqual(typeof Temporal.Now.instant().epochNanoseconds, 'bigint');
  }

  const worker = new Worker(`
    const { parentPort } = require('worker_threads');
    parentPort.postMessage(JSON.stringify({ ok: true, v8: process.versions.v8 }));
  `, { eval: true });
  const msg = await new Promise((resolve, reject) => {
    worker.once('message', resolve);
    worker.once('error', reject);
  });
  assert.strictEqual(JSON.parse(msg).ok, true);

  const pressure = [];
  for (let i = 0; i < 64; i += 1) {
    pressure.push(new Uint8Array(1024 * 1024));
  }
  assert.strictEqual(pressure.length, 64);
  console.log('v8-smoke ok');
})().catch((err) => {
  console.error(err && err.stack ? err.stack : err);
  process.exit(1);
});
