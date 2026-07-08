const os = require('os');
const { test, assert } = require('../harness');

test('SYS: Seccomp syscall enforcement (os.release)', () => {
    // os.release() triggers uname. 
    // This test ensures Astraea hasn't broken required Node.js syscalls.
    const release = os.release();
    assert(release.length > 0);
});

test('SYS: sigaction SIGSYS protection', () => {
    // Attempting to listen to SIGSYS should be safely blocked by our interceptor
    // and should not cause any crashes.
    try {
        process.on('SIGSYS', () => {});
    } catch (e) {
        assert.fail('Should not throw when listening to SIGSYS');
    }
});
