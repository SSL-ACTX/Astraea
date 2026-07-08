const { spawnSync } = require('child_process');
const { test, assert } = require('../harness');
const restricted = require('../node_modules/restricted_package');

test('PHASE 7: Root package should be allowed to set env', () => {
    process.env.ASTRAEA_TEST = 'ok';
    assert.strictEqual(process.env.ASTRAEA_TEST, 'ok');
});

test('PHASE 7: Root package should be allowed to spawn processes', () => {
    const idPath = '/data/data/com.termux/files/usr/bin/id';
    const result = spawnSync(idPath);
    assert.strictEqual(result.status, 0);
});

test('PHASE 7: Restricted package enforcement (ENV & PROC)', () => {
    const fs = require('fs');
    fs.writeFileSync('tests/protected.txt', 'This file is protected');
    try {
        restricted.runTests(assert);
    } finally {
        if (fs.existsSync('tests/protected.txt')) {
            fs.unlinkSync('tests/protected.txt');
        }
    }
});

test('PHASE 7: Sandbox inheritance (un-bypassable via LD_PRELOAD stripping)', () => {
    const env = { ...process.env };
    delete env.LD_PRELOAD;

    const childRes = spawnSync(process.execPath, [
        '-e',
        'console.log(process.env.LD_PRELOAD)'
    ], { env });

    const stdout = childRes.stdout.toString().trim();
    assert.ok(stdout.includes('libastraea.so'), `LD_PRELOAD should have been automatically injected. Got: ${stdout}`);
});

