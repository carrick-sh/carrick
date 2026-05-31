'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');

assert.strictEqual(process.env.npm_package_name, 'carrick-nodejs-npm-smoke');
fs.writeFileSync(path.join(process.cwd(), 'npm-smoke.out'), 'ok');
assert.strictEqual(fs.readFileSync(path.join(process.cwd(), 'npm-smoke.out'), 'utf8'), 'ok');
console.log('npm-smoke ok');
