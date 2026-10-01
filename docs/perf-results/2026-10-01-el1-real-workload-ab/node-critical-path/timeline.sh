#!/bin/bash
# Per-test critical-path timeline of the node-core worker-message-port shard,
# runnable unchanged under Carrick and Docker (same image, /ncp mounted).
# usage: timeline.sh <jobs|0> <outdir>
set -u
J="$1"; OUT="$2"
NODE=/opt/nodejs-conformance/bin/node24
mkdir -p "$OUT"; : > "$OUT/timeline.txt"; : > "$OUT/node.jsonl"
cat > /tmp/nodewrap <<WRAP
#!/bin/bash
s=\$EPOCHREALTIME
NCP_OUT=$OUT/node.jsonl $NODE -r /ncp/timing.js "\$@"
rc=\$?
e=\$EPOCHREALTIME
echo "\$s \$e \$rc \${@: -1}" >> $OUT/timeline.txt
exit \$rc
WRAP
chmod +x /tmp/nodewrap
cd /opt/node-src/v24
t0=$EPOCHREALTIME
python3 tools/test.py --shell /tmp/nodewrap --progress tap -j "$J" 'parallel/test-worker-message-port*' > "$OUT/tap.txt" 2>&1
rc=$?
t1=$EPOCHREALTIME
echo "$t0 $t1 $rc nproc=$(nproc) j=$J" > "$OUT/total.txt"
p0=$EPOCHREALTIME; for i in $(seq 20); do $NODE -e 0; done; p1=$EPOCHREALTIME
w=$($NODE -e "
const { Worker } = require('worker_threads');
(async () => { const t = process.hrtime.bigint();
for (let i = 0; i < 50; i++) { const w = new Worker('0', { eval: true }); await new Promise(r => w.on('exit', r)); }
console.log(Number(process.hrtime.bigint() - t) / 50 / 1e6); })();")
r=$($NODE -e "
const { Worker, MessageChannel } = require('worker_threads'); const { once } = require('events');
(async () => { const w = new Worker(\"require('worker_threads').parentPort.on('message', ({ port }) => { port.postMessage(1); port.postMessage(2); port.close(); });\", { eval: true });
const t = process.hrtime.bigint();
for (let i = 0; i < 2000; i++) { const { port1, port2 } = new MessageChannel(); w.postMessage({ port: port2 }, [port2]); await once(port1, 'message'); await once(port1, 'message'); }
console.log(Number(process.hrtime.bigint() - t) / 2000 / 1e3); await w.terminate(); })();")
python3 -c "print('node_e0_ms=%.1f' % ((float('$p1') - float('$p0')) * 1000 / 20))" > "$OUT/micro.txt"
echo "worker_create_join_ms=$w roundtrip_us=$r" >> "$OUT/micro.txt"
cat "$OUT/total.txt" "$OUT/micro.txt"
