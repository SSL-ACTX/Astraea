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
    restricted.runTests(assert);
});
