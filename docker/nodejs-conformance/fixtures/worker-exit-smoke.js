'use strict';

const { Worker, isMainThread, parentPort } = require('worker_threads');

if (!isMainThread) {
  parentPort.postMessage('ready');
} else {
  const worker = new Worker(__filename);
  let sawMessage = false;

  worker.once('message', (message) => {
    if (message !== 'ready') {
      throw new Error(`unexpected worker message: ${message}`);
    }
    sawMessage = true;
    console.log('worker-message ok');
  });

  worker.once('exit', (code) => {
    if (!sawMessage) {
      throw new Error('worker exited before its message was observed');
    }
    if (code !== 0) {
      throw new Error(`worker exited with code ${code}`);
    }
    console.log('worker-exit ok');
  });
}
