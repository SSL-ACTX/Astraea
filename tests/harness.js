const assert = require('assert');

/**
 * Executes a synchronous test case.
 * @param {string} name - Component and scenario description.
 * @param {function} fn - Test execution logic.
 */
function test(name, fn) {
    try {
        fn();
        process.stdout.write(`  [OK]   ${name}\n`);
    } catch (e) {
        process.stdout.write(`  [FAIL] ${name}\n`);
        process.stderr.write(`         Error: ${e.message}\n`);
        process.exit(1);
    }
}

/**
 * Executes an asynchronous test case.
 * @param {string} name - Component and scenario description.
 * @param {function} fn - Async test execution logic.
 */
async function asyncTest(name, fn) {
    try {
        await fn();
        process.stdout.write(`  [OK]   ${name}\n`);
    } catch (e) {
        process.stdout.write(`  [FAIL] ${name}\n`);
        process.stderr.write(`         Error: ${e.message}\n`);
        process.exit(1);
    }
}

module.exports = { test, asyncTest, assert };
