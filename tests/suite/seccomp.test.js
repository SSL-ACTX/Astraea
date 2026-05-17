const os = require('os');
const { test, assert } = require('../harness');

test('SYS: Seccomp syscall enforcement (os.release)', () => {
    // os.release() triggers uname. 
    // This test ensures Astraea hasn't broken required Node.js syscalls.
    const release = os.release();
    assert(release.length > 0);
});
