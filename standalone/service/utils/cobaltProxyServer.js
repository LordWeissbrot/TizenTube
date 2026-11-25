"use strict";

const fs = require('fs');
const http = require('http');
const ogHttps = require('https');
const https = require('./https.js');
const net = require('net');
const tls = require('tls');
const forge = require('node-forge');
const url = require('url');
const log = require('./log.js');

const proxyPort = 8101;

// Counters for the periodic STATS log line.
const stats = { connects: 0, mitmRequests: 0, retries: 0, upstreamErrors: 0, tunnelErrors: 0, clientErrors: 0, openTunnels: 0 };

function startServer() {
    const caCertificate = forge.pki.certificateFromPem(
        fs.readFileSync('/home/owner/share/tizentube-ca.crt', 'utf8')
    );

    const caPrivateKey = forge.pki.privateKeyFromPem(
        fs.readFileSync('/home/owner/share/tizentube-ca.key', 'utf8')
    );

    function createHostCertificate(hostname) {
        const keys = forge.pki.rsa.generateKeyPair(2048);
        const certificate = forge.pki.createCertificate();

        certificate.publicKey = keys.publicKey;
        certificate.serialNumber = Date.now().toString(16);
        // Backdate a day to tolerate small clock differences.
        certificate.validity.notBefore = new Date(Date.now() - 24 * 60 * 60 * 1000);
        certificate.validity.notAfter = new Date(
            certificate.validity.notBefore.getTime() + 397 * 24 * 60 * 60 * 1000
        );

        certificate.setSubject([{ name: 'commonName', value: hostname }]);
        certificate.setIssuer(caCertificate.subject.attributes);
        certificate.setExtensions([
            { name: 'basicConstraints', cA: false, critical: true },
            {
                name: 'keyUsage',
                digitalSignature: true,
                keyEncipherment: true,
                critical: true
            },
            { name: 'extKeyUsage', serverAuth: true },
            {
                name: 'subjectAltName',
                altNames: [{ type: 2, value: hostname }]
            },
            { name: 'subjectKeyIdentifier' },
            {
                name: 'authorityKeyIdentifier',
                keyIdentifier: caCertificate.generateSubjectKeyIdentifier().getBytes()
            }
        ]);

        certificate.sign(caPrivateKey, forge.md.sha256.create());

        log('CERT generated for', hostname, 'valid', certificate.validity.notBefore.toISOString(), '->', certificate.validity.notAfter.toISOString());

        return {
            key: forge.pki.privateKeyToPem(keys.privateKey),
            cert: forge.pki.certificateToPem(certificate) + forge.pki.certificateToPem(caCertificate),
            notBefore: certificate.validity.notBefore.getTime(),
            notAfter: certificate.validity.notAfter.getTime()
        };
    }

    // The service starts on boot, possibly before the TV clock is synced
    // (it then reads 1970). A certificate made at that moment is expired for
    // Cobalt once the clock is right -> "A network error has occurred" until
    // the service restarts (upstream issue #771). So check validity on every
    // use and regenerate when the clock has moved outside it.
    const certCache = {};

    function getHostCertificate(hostname) {
        const now = Date.now();
        const cached = certCache[hostname];
        if (cached && now >= cached.notBefore && now < cached.notAfter - 24 * 60 * 60 * 1000) {
            return cached;
        }
        if (cached) log('CERT for', hostname, 'outside validity at', new Date(now).toISOString(), '- regenerating');
        certCache[hostname] = createHostCertificate(hostname);
        return certCache[hostname];
    }

    function tunnel(hostname, port, clientSocket, initialData) {
        const started = Date.now();
        stats.openTunnels++;
        let closed = false;
        const onClose = () => {
            if (!closed) { closed = true; stats.openTunnels--; }
        };
        const targetSocket = net.connect(port, hostname, () => {
            clientSocket.write(
                'HTTP/1.1 200 Connection Established\r\n\r\n'
            );

            if (initialData.length) {
                targetSocket.write(initialData);
            }

            clientSocket.pipe(targetSocket);
            targetSocket.pipe(clientSocket);
        });

        targetSocket.on('error', err => {
            stats.tunnelErrors++;
            log('TUNNEL upstream error', hostname + ':' + port, err, 'after', (Date.now() - started) + 'ms');
            clientSocket.destroy();
        });
        clientSocket.on('error', err => {
            stats.clientErrors++;
            log('TUNNEL client error', hostname + ':' + port, err);
            targetSocket.destroy();
        });
        targetSocket.on('close', onClose);
        clientSocket.on('close', onClose);
    }

    getHostCertificate('www.youtube.com');
    getHostCertificate('youtube.com');

    function mitm(hostname, port, clientSocket, initialData) {
        clientSocket.write(
            'HTTP/1.1 200 Connection Established\r\n\r\n'
        );

        clientSocket.on('error', err => {
            stats.clientErrors++;
            log('MITM client socket error', hostname, err);
        });

        const cert = getHostCertificate(hostname === 'www.youtube.com' ? 'www.youtube.com' : 'youtube.com');
        const tlsServer = new tls.Server({ key: cert.key, cert: cert.cert });

        tlsServer.on('secureConnection', clientTlsSocket => {
            const httpServer = http.createServer(
                (request, response) => {
                    const isTvPath =
                        request.url === '/tv' ||
                        request.url.startsWith('/tv?');

                    const reqHeaders = Object.assign({}, request.headers);

                    if (isTvPath) reqHeaders['accept-encoding'] = 'identity';

                    const httpsModule = parseInt(process.version.split('.')[0].replace('v', '')) >= 13 ? ogHttps : https;

                    stats.mitmRequests++;
                    const started = Date.now();
                    const shortPath = request.url.split('?')[0].slice(0, 80);
                    const bodyChunks = [];
                    let attempt = 0;

                    response.on('error', err => log('MITM response error', hostname + shortPath, err));
                    request.on('error', err => log('MITM request error', hostname + shortPath, err));

                    // Buffer the (small, JSON) request body so a failed upstream
                    // attempt can be retried once before anything reached the player.
                    request.on('data', chunk => bodyChunks.push(chunk));
                    request.on('end', () => send());

                    function send() {
                        const targetRequest = httpsModule.request({
                            hostname,
                            port,
                            method: request.method,
                            path: request.url,
                            headers: reqHeaders,
                            servername: hostname,
                            rejectUnauthorized: true,
                            maxHeaderSize: 1024 * 1024
                        }, targetResponse => {
                            const headers = Object.assign({}, targetResponse.headers);

                            if (!isTvPath) {
                                response.writeHead(
                                    targetResponse.statusCode,
                                    headers
                                );

                                return targetResponse.pipe(response);
                            }

                            delete headers['content-security-policy'];
                            delete headers['content-security-policy-report-only'];
                            headers['content-security-policy'] = [
                                "default-src * data: blob: 'unsafe-inline' 'unsafe-eval'",
                                'img-src * https://dearrow-thumb.ajay.app data: blob:',
                                'media-src * data: blob:',
                                "script-src * https://cdn.jsdelivr.net https://sponsor.ajay.app data: blob: 'unsafe-inline' 'unsafe-eval'",
                                "style-src * data: blob: 'unsafe-inline'",
                                'connect-src * https://cdn.jsdelivr.net https://sponsor.ajay.app https://dearrow-thumb.ajay.app',
                                'font-src * data:'
                            ].join('; ');

                            const chunks = [];

                            targetResponse.on('data', chunk => chunks.push(chunk));

                            targetResponse.on('end', () => {
                                let body = Buffer.concat(chunks).toString('utf8');

                                delete headers['content-length'];
                                delete headers['transfer-encoding'];
                                delete headers['content-encoding'];
                                delete headers['connection'];

                                body = body.replace(
                                    /<meta\b[^>]*http-equiv\s*=\s*["']Content-Security-Policy(?:-Report-Only)?["'][^>]*>/gi,
                                    ''
                                );

                                body = body.replace('</body>', `<script src="https://cdn.jsdelivr.net/npm/@foxreis/tizentube/dist/userScript.js?ver=${Date.now()}"></script></body>`);

                                headers['content-length'] = Buffer.byteLength(body, 'utf8');
                                headers['connection'] = 'close';
                                headers['content-encoding'] = 'identity';

                                response.writeHead(
                                    targetResponse.statusCode,
                                    headers
                                );

                                response.end(body);
                            });
                        });

                        targetRequest.on('error', error => {
                            const elapsed = Date.now() - started;
                            if (!response.headersSent && attempt === 0) {
                                attempt++;
                                stats.retries++;
                                log('UPSTREAM error, retrying', request.method, hostname + shortPath, error, 'phase=' + (error.phase || '?'), elapsed + 'ms');
                                return setTimeout(send, 250);
                            }
                            stats.upstreamErrors++;
                            log('UPSTREAM error, giving up', request.method, hostname + shortPath, error, 'phase=' + (error.phase || '?'), 'attempt=' + (attempt + 1), 'headersSent=' + response.headersSent, elapsed + 'ms');
                            response.destroy();
                        });

                        const body = Buffer.concat(bodyChunks);
                        if (body.length) targetRequest.write(body);
                        targetRequest.end();
                    }
                }
            );

            httpServer.emit('connection', clientTlsSocket);
        });

        tlsServer.on('tlsClientError', err => {
            stats.clientErrors++;
            log('MITM TLS client error', hostname, err);
            clientSocket.destroy();
        });

        if (initialData && initialData.length) {
            clientSocket.unshift(initialData);
        }

        tlsServer.emit('connection', clientSocket);
    }

    const proxyServer = http.createServer((request, response) => {
        // Direct (non-proxy) request for the log: http://<TV IP>:8101/__ttlog[?all]
        // Retail TVs don't allow `sdb pull` from the share directory, so this
        // is the only practical way to read it. Proxy requests always carry an
        // absolute URL, so a bare path can't collide with proxied traffic.
        if (request.url === '/__ttlog' || request.url === '/__ttlog?all') {
            let text = '';
            try {
                if (request.url === '/__ttlog?all') text += fs.readFileSync(log.LOG_FILE + '.1', 'utf8');
            } catch (e) { /* no rotated file yet */ }
            try {
                text += fs.readFileSync(log.LOG_FILE, 'utf8');
            } catch (e) {
                text += '(no log yet: ' + e.message + ')\n';
            }
            response.writeHead(200, { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store' });
            return response.end(text);
        }

        const targetUrl = url.parse(request.url);

        const targetRequest = http.request({
            hostname: targetUrl.hostname,
            port: targetUrl.port || 80,
            method: request.method,
            path: targetUrl.pathname + targetUrl.search,
            headers: request.headers
        }, targetResponse => {
            response.writeHead(
                targetResponse.statusCode,
                targetResponse.headers
            );

            targetResponse.pipe(response);
        });

        targetRequest.on('error', err => {
            log('HTTP proxy error', targetUrl.hostname, err);
            response.destroy();
        });
        request.pipe(targetRequest);
    });

    proxyServer.on('connect', (request, clientSocket, initialData) => {
        const reqUrl = request.url.split(':');
        const hostname = reqUrl[0];
        const port = reqUrl[1] || 443;
        stats.connects++;

        if (hostname !== 'youtube.com' && !hostname.endsWith('.youtube.com')) {
            return tunnel(
                hostname,
                Number(port),
                clientSocket,
                initialData
            );
        }

        mitm(
            hostname,
            Number(port),
            clientSocket,
            initialData
        );
    });

    proxyServer.on('error', err => log('PROXY server error', err));
    proxyServer.on('clientError', (err, socket) => {
        stats.clientErrors++;
        log('PROXY client error', err);
        try { socket.destroy(); } catch (e) { /* ignore */ }
    });
    proxyServer.listen(proxyPort, '0.0.0.0', () => log('PROXY listening on', proxyPort));

    const startedAt = Date.now();
    setInterval(() => {
        let mem = '';
        try {
            const m = process.memoryUsage();
            mem = ' rssMB=' + Math.round(m.rss / 1048576) + ' heapMB=' + Math.round(m.heapUsed / 1048576);
        } catch (e) {
            mem = ' mem=n/a';
        }
        log('STATS uptimeMin=' + Math.round((Date.now() - startedAt) / 60000) +
            ' connects=' + stats.connects + ' mitm=' + stats.mitmRequests + ' retries=' + stats.retries +
            ' upstreamErr=' + stats.upstreamErrors + ' tunnelErr=' + stats.tunnelErrors +
            ' clientErr=' + stats.clientErrors + ' openTunnels=' + stats.openTunnels + mem);
    }, 60000);
}

module.exports = startServer;