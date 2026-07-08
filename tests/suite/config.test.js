const fs = require('fs');
const { spawnSync } = require('child_process');
const path = require('path');
const { test, assert } = require('../harness');

const CUSTOM_CONFIG = path.join(__dirname, '../custom_config.toml');

test('CONFIG: Custom config load via ASTRAEA_CONFIG', () => {
    // 1. Write a custom config that defines rules for a dummy package
    const configContent = `
[packages.config_test_package]
env = ["CONFIG_TEST_VAR"]
`;
    fs.writeFileSync(CUSTOM_CONFIG, configContent);

    // 2. Spawn a child process belonging to config_test_package
    // Note: We name the package directory and require it to simulate package context.
    const pkgDir = path.join(__dirname, '../node_modules/config_test_package');
    if (!fs.existsSync(pkgDir)) {
        fs.mkdirSync(pkgDir, { recursive: true });
    }
    fs.writeFileSync(
        path.join(pkgDir, 'package.json'),
        JSON.stringify({ name: 'config_test_package', main: 'index.js' })
    );

    const childCode = `
        const assert = require('assert');
        process.env.CONFIG_TEST_VAR = 'ok';
        assert.strictEqual(process.env.CONFIG_TEST_VAR, 'ok');

        process.env.OTHER_VAR = 'fail';
        if (process.env.OTHER_VAR !== 'fail') {
            console.log('SUCCESSFULLY_BLOCKED');
        } else {
            console.log('FAILED_TO_BLOCK');
        }
    `;
    fs.writeFileSync(path.join(pkgDir, 'index.js'), childCode);

    const env = {
        ...process.env,
        LD_PRELOAD: path.resolve(__dirname, '../../zig-out/lib/libastraea.so'),
        ASTRAEA_CONFIG: CUSTOM_CONFIG,
    };

    const res = spawnSync(process.execPath, [path.join(pkgDir, 'index.js')], { env });
    
    // Clean up files first
    try {
        fs.unlinkSync(CUSTOM_CONFIG);
        fs.unlinkSync(path.join(pkgDir, 'index.js'));
        fs.unlinkSync(path.join(pkgDir, 'package.json'));
        fs.rmdirSync(pkgDir);
    } catch(e) {}

    const stdout = res.stdout.toString().trim();
    assert.ok(stdout.includes('SUCCESSFULLY_BLOCKED'), `Astraea should respect custom config loaded from ASTRAEA_CONFIG. Output: ${stdout}`);
});
