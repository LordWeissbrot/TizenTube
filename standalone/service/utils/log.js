"use strict";

// Small persistent log for the standalone proxy service.
// Retail TVs have no usable dlog, so we append to a file in the shared
// directory (readable with `sdb pull`) and rotate it at MAX_BYTES.
// Must run on very old Node versions (Tizen ships Node 4.x on some models):
// only sync fs calls that exist there, and no logging failure may ever throw.

const fs = require('fs');

const LOG_FILE = '/home/owner/share/tizentube-proxy.log';
const MAX_BYTES = 512 * 1024;

let bytesWritten = -1;

function pad(n, width) {
    let s = String(n);
    while (s.length < (width || 2)) s = '0' + s;
    return s;
}

function timestamp() {
    const d = new Date();
    return d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate()) +
        ' ' + pad(d.getHours()) + ':' + pad(d.getMinutes()) + ':' + pad(d.getSeconds()) +
        '.' + pad(d.getMilliseconds(), 3);
}

function rotateIfNeeded(extra) {
    if (bytesWritten < 0) {
        try {
            bytesWritten = fs.statSync(LOG_FILE).size;
        } catch (e) {
            bytesWritten = 0;
        }
    }

    if (bytesWritten + extra <= MAX_BYTES) return;

    try {
        fs.renameSync(LOG_FILE, LOG_FILE + '.1');
    } catch (e) {
        // Nothing to rotate.
    }
    bytesWritten = 0;
}

function log() {
    try {
        const parts = [];
        for (let i = 0; i < arguments.length; i++) {
            const a = arguments[i];
            if (a instanceof Error) {
                parts.push((a.code ? a.code + ' ' : '') + a.message);
            } else if (typeof a === 'object' && a !== null) {
                parts.push(JSON.stringify(a));
            } else {
                parts.push(String(a));
            }
        }
        const line = timestamp() + ' ' + parts.join(' ') + '\n';
        rotateIfNeeded(line.length);
        fs.appendFileSync(LOG_FILE, line);
        bytesWritten += line.length;
    } catch (e) {
        // Logging must never break the proxy.
    }
}

module.exports = log;
module.exports.LOG_FILE = LOG_FILE;
