const { test, assert } = require('../harness');

test('NATIVE: dlopen restriction (unauthorized.node)', () => {
    try {
        process.dlopen(module, './unauthorized.node');
        throw new Error('Native addon load should have been blocked');
    } catch (e) {
        // Astraea forces a dummy load error to populate dlerror
        assert(e.message.includes('not found') || e.message.includes('denied'));
    }
});
