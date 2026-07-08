const fs = require('fs');
const { test, asyncTest, assert } = require('../harness');

test('FS: Absolute path authorization (/etc/hosts)', () => {
    const data = fs.readFileSync('/etc/hosts');
    assert(data.length > 0);
});

test('FS: Relative path authorization (astraea.toml)', () => {
    const data = fs.readFileSync('astraea.toml');
    assert(data.length > 0);
});

test('FS: Unauthorized access restriction (.git/config)', () => {
    try {
        fs.readFileSync('.git/config');
        throw new Error('Access should have been denied');
    } catch (e) {
        assert.strictEqual(e.code, 'EACCES');
    }
});

test('FS: Content spoofing & redirection (secret.txt)', () => {
    const data = fs.readFileSync('secret.txt', 'utf8');
    assert(data.includes('MOCKED DATA'));
});

asyncTest('FS: Content spoofing & redirection async (secret.txt)', async () => {
    return new Promise((resolve, reject) => {
        fs.readFile('secret.txt', 'utf8', (err, data) => {
            if (err) return reject(err);
            try {
                assert(data.includes('MOCKED DATA'));
                resolve();
            } catch (e) {
                reject(e);
            }
        });
    });
});

