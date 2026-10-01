// Preloaded into every test process (main thread only): node bootstrap
// milestones, worker create/online/exit times, and process exit, appended
// as one JSON line per process to $NCP_OUT.
'use strict';
const wt = require('worker_threads');
if (wt.isMainThread && process.env.NCP_OUT) {
  const { performance } = require('perf_hooks');
  const fs = require('fs');
  const events = [];
  const Base = wt.Worker;
  wt.Worker = class Worker extends Base {
    constructor(...args) {
      const t = performance.now();
      super(...args);
      events.push(['new', t]);
      this.once('online', () => events.push(['online', performance.now()]));
      this.once('exit', () => events.push(['exit', performance.now()]));
    }
  };
  process.on('exit', () => {
    const n = performance.nodeTiming;
    fs.appendFileSync(process.env.NCP_OUT, JSON.stringify({
      file: process.argv[1] || process.argv.slice(1).join(' '),
      origin: performance.timeOrigin, nodeStart: n.nodeStart, v8Start: n.v8Start,
      environment: n.environment, bootstrap: n.bootstrapComplete, loop: n.loopStart,
      exit: performance.now(), events,
    }) + '\n');
  });
}
