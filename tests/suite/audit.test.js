const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');
const { test, assert } = require('../harness');

const AUDIT_LOG = path.join(__dirname, '../audit.json');

test('PHASE 8: Learning Mode (Audit Logging)', () => {
    // Ensure fresh state
    if (fs.existsSync(AUDIT_LOG)) fs.unlinkSync(AUDIT_LOG);

    // Run a small script with audit enabled
    const env = { ...process.env, ASTRAEA_AUDIT: AUDIT_LOG };
    
    // We'll use the current process but since it's already running Astraea, 
    // it's better to spawn a child with the env var.
    const code = `
        const fs = require('fs');
        try { fs.readFileSync('astraea.toml'); } catch(e) {}
        process.env.AUDIT_VAR = 'test';
    `;
    
    // Note: In our test harness, we don't easily have a 'node' binary that is pre-loaded 
    // with the interceptor via LD_PRELOAD if it's not already set up.
    // However, the test runner ./tests/run.sh sets up LD_PRELOAD.
    
    // For this test, we assume the interceptor is active.
    const res = spawnSync(process.execPath, ['-e', code], { env });
    
    // Wait a bit for the async logger to flush
    spawnSync('sleep', ['0.1']);

    assert.ok(fs.existsSync(AUDIT_LOG), 'Audit log should be created');
    
    const logContent = fs.readFileSync(AUDIT_LOG, 'utf8');
    assert.ok(logContent.includes('"action":"fs"'), 'Should log FS actions');
    assert.ok(logContent.includes('"action":"env"'), 'Should log ENV actions');
    assert.ok(logContent.includes('"target":"read:astraea.toml"'), 'Should log specific target');
});

test('PHASE 8: Manifest Generation (astraea-gen)', () => {
    // This assumes astraea-gen is built. The run.sh script builds the engine.
    const genPath = path.join(__dirname, '../../engine/target/debug/astraea-gen');
    if (!fs.existsSync(genPath)) {
        // Fallback or skip if not built (though it should be)
        console.warn('Skipping astraea-gen test as binary not found');
        return;
    }

    const result = spawnSync(genPath, [AUDIT_LOG]);
    const output = result.stdout.toString();
    
    assert.ok(output.includes('[packages.root]'), 'Generated manifest should have root package');
    assert.ok(output.includes('fs = ['), 'Generated manifest should have fs section');
    assert.ok(output.includes('"read:astraea.toml"'), 'Generated manifest should include observed file');
});
