const http = require('http');
const net = require('net');
const { asyncTest, assert } = require('../harness');

asyncTest('NET: Domain whitelisting (api.github.com)', async () => {
    return new Promise((resolve, reject) => {
        const req = http.get('http://api.github.com', { timeout: 5000 }, (res) => {
            resolve();
        });
        req.on('error', (e) => reject(new Error(`Resolution failed: ${e.code}`)));
    });
});

asyncTest('NET: Unauthorized domain blocking', async () => {
    return new Promise((resolve, reject) => {
        const req = http.get('http://unauthorized.test', (res) => {
            reject(new Error('Connection should have been blocked'));
        });
        req.on('error', (e) => {
            const blocked = ['EAI_NONAME', 'EACCES', 'ENOTFOUND'].includes(e.code);
            if (blocked) resolve();
            else reject(new Error(`Unexpected error code: ${e.code}`));
        });
    });
});

asyncTest('NET: Raw IP connection blocking', async () => {
    return new Promise((resolve, reject) => {
        const socket = new net.Socket();
        socket.setTimeout(1000);
        socket.connect(80, '1.2.3.4', () => {
            socket.destroy();
            reject(new Error('Raw IP connection should have been blocked'));
        });
        socket.on('error', (e) => {
            socket.destroy();
            if (e.code === 'EACCES' || e.code === 'EPERM') resolve();
            else reject(new Error(`Unexpected error code: ${e.code}`));
        });
        socket.on('timeout', () => {
            socket.destroy();
            reject(new Error('Connection timed out instead of being blocked'));
        });
    });
});
