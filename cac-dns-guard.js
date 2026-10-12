// ═══════════════════════════════════════════════════════════════
// cac-dns-guard.js
// DNS-level telemetry domain blocking | mTLS certificate injection | fetch leak prevention
// Injected into Claude Code process via NODE_OPTIONS="--require <this>"
// ═══════════════════════════════════════════════════════════════
'use strict';

var dns  = require('dns');
var net  = require('net');
var tls  = require('tls');
var http = require('http');
var https = require('https');
var fs   = require('fs');

// ─── 1. DNS-level telemetry domain blocking ──────────────────────────────────

var BLOCKED_DOMAINS = new Set([
    'statsig.anthropic.com',
    'sentry.io',
    'o1137031.ingest.sentry.io',
    'cdn.growthbook.io',
    'http-intake.logs.us5.datadoghq.com',
]);

/**
 * Check if domain is in block list (including subdomain matching)
 * e.g. "foo.sentry.io" matches "sentry.io"
 */
function isDomainBlocked(hostname) {
    if (!hostname) return false;
    var h = hostname.toLowerCase().replace(/\.$/,'');
    if (BLOCKED_DOMAINS.has(h)) return true;
    var parts = h.split('.');
    for (var i = 1; i < parts.length - 1; i++) {
        if (BLOCKED_DOMAINS.has(parts.slice(i).join('.'))) return true;
    }
    return false;
}

function makeBlockedError(hostname, syscall) {
    var msg = 'connect ECONNREFUSED (blocked by cac): ' + hostname;
    var err = new Error(msg);
    err.code     = 'ECONNREFUSED';
    err.errno    = -111;
    err.hostname = hostname;
    err.syscall  = syscall || 'connect';
    return err;
}

// ── 1a. intercept dns.lookup ──
var _origLookup = dns.lookup;
dns.lookup = function cacLookup(hostname, options, callback) {
    if (typeof options === 'function') { callback = options; options = {}; }
    if (isDomainBlocked(hostname)) {
        var err = makeBlockedError(hostname, 'getaddrinfo');
        if (typeof callback === 'function') process.nextTick(function() { callback(err); });
        return {};
    }
    return _origLookup.call(dns, hostname, options, callback);
};

// ── 1b. intercept dns.resolve / resolve4 / resolve6 ──
['resolve','resolve4','resolve6'].forEach(function(method) {
    var orig = dns[method];
    if (!orig) return;
    dns[method] = function(hostname) {
        var args = Array.prototype.slice.call(arguments);
        var cb = args[args.length - 1];
        if (isDomainBlocked(hostname)) {
            var err = makeBlockedError(hostname, 'query');
            if (typeof cb === 'function') process.nextTick(function() { cb(err); });
            return;
        }
        return orig.apply(dns, args);
    };
});

// ── 1c. intercept dns.promises ──
if (dns.promises) {
    var _origPLookup = dns.promises.lookup;
    if (_origPLookup) {
        dns.promises.lookup = function cacPromiseLookup(hostname, options) {
            if (isDomainBlocked(hostname)) return Promise.reject(makeBlockedError(hostname, 'getaddrinfo'));
            return _origPLookup.call(dns.promises, hostname, options);
        };
    }
    ['resolve','resolve4','resolve6'].forEach(function(method) {
        var orig = dns.promises[method];
        if (!orig) return;
        dns.promises[method] = function(hostname) {
            if (isDomainBlocked(hostname)) return Promise.reject(makeBlockedError(hostname, 'query'));
            return orig.apply(dns.promises, arguments);
        };
    });
}

// ── 1d. network layer safety net: intercept net.connect to telemetry domains ──
var _origNetConnect    = net.connect;
var _origNetCreateConn = net.createConnection;

function getHostFromArgs(args) {
    if (typeof args[0] === 'object') return args[0].host || args[0].hostname || '';
    return '';
}

function makeBlockedSocket(host) {
    var sock = new net.Socket();
    var err = makeBlockedError(host, 'connect');
    process.nextTick(function() { sock.destroy(err); });
    return sock;
}

net.connect = function cacNetConnect() {
    var host = getHostFromArgs(arguments);
    if (isDomainBlocked(host)) return makeBlockedSocket(host);
    return _origNetConnect.apply(net, arguments);
};
net.createConnection = function cacNetCreateConnection() {
    var host = getHostFromArgs(arguments);
    if (isDomainBlocked(host)) return makeBlockedSocket(host);
    return _origNetCreateConn.apply(net, arguments);
};


// ─── 2. mTLS certificate injection ──────────────────────────────────

var mtlsCert = process.env.CAC_MTLS_CERT;
var mtlsKey  = process.env.CAC_MTLS_KEY;
var mtlsCa   = process.env.CAC_MTLS_CA;
var proxyHostPort = process.env.CAC_PROXY_HOST || '';

if (mtlsCert && mtlsKey) {
    var certData, keyData, caData;
    try {
        certData = fs.readFileSync(mtlsCert);
        keyData  = fs.readFileSync(mtlsKey);
        if (mtlsCa) caData = fs.readFileSync(mtlsCa);
    } catch(e) {
        certData = null; keyData = null;
    }

    if (certData && keyData) {
        // inject mTLS cert only for proxy connections
        var proxyHost = proxyHostPort.split(':')[0];
        var proxyPort = parseInt(proxyHostPort.split(':')[1], 10) || 0;

        // 2a. intercept tls.connect, inject client cert for proxy connections
        var _origTlsConnect = tls.connect;
        tls.connect = function cacTlsConnect() {
            // normalize parameters: tls.connect(options[, cb]) or tls.connect(port[, host][, options][, cb])
            var args = Array.prototype.slice.call(arguments);
            var options, callback;

            if (typeof args[0] === 'object') {
                options = args[0];
                callback = (typeof args[1] === 'function') ? args[1] : undefined;
            } else {
                // tls.connect(port, host, options, cb) form
                var port = args[0];
                var host = (typeof args[1] === 'string') ? args[1] : 'localhost';
                var optIdx = (typeof args[1] === 'string') ? 2 : 1;
                options = (typeof args[optIdx] === 'object') ? args[optIdx] : {};
                options.port = port;
                options.host = host;
                callback = args[args.length - 1];
                if (typeof callback !== 'function') callback = undefined;
            }

            // inject only for proxy connections (exact host:port match)
            var targetHost = options.host || options.hostname || '';
            var targetPort = options.port || 0;
            if (proxyHost && targetHost === proxyHost &&
                (proxyPort === 0 || targetPort === proxyPort)) {
                if (!options.cert) {
                    options.cert = certData;
                    options.key  = keyData;
                    if (caData) {
                        options.ca = options.ca
                            ? [].concat(options.ca, caData)
                            : [caData];
                    }
                }
            }

            if (callback) return _origTlsConnect.call(tls, options, callback);
            return _origTlsConnect.call(tls, options);
        };

        // 2b. inject CA into https.globalAgent (trust CA only, no client private key)
        if (caData && https.globalAgent && https.globalAgent.options) {
            https.globalAgent.options.ca = https.globalAgent.options.ca
                ? [].concat(https.globalAgent.options.ca, caData)
                : [caData];
        }
    }
}


// ─── 3. fetch telemetry interception patch ──────────────────────────────────
// Wrap native fetch to block telemetry domains by URL check
// (do NOT replace with node-fetch — its Response.body lacks ReadableStream.cancel(),
//  which breaks Bun-based Claude Code streaming)

(function patchFetch() {
    if (typeof globalThis === 'undefined' || typeof globalThis.fetch !== 'function') return;

    var _origFetch = globalThis.fetch;
    globalThis.fetch = function cacFetch(input, init) {
        var hostname;
        try {
            var urlStr = typeof input === 'string' ? input :
                         (input && input.url) ? input.url : '';
            if (urlStr) hostname = new URL(urlStr).hostname;
        } catch(e) { /* ignore */ }

        if (hostname && isDomainBlocked(hostname)) {
            return Promise.reject(makeBlockedError(hostname, 'fetch'));
        }
        return _origFetch(input, init);
    };
})();


// ─── 4. health check bypass (in-process interception, URL-specific) ────────────────
// Claude Code pings https://api.anthropic.com/api/hello on startup
// Cloudflare blocks Node.js TLS fingerprint (JA3/JA4) -> 403
// Solution: intercept this request at Node.js layer, return 200 directly, no network traffic
// Only intercepts health check, does not affect OAuth/API or other requests

function isHealthCheck(url) {
    if (!url) return false;
    // match https://api.anthropic.com/api/hello or variants with query params
    return /^https?:\/\/api\.anthropic\.com\/api\/hello/.test(url);
}

function makeHealthResponse(callback) {
    var EventEmitter = require('events');
    var body = '{"message":"hello"}';

    // Fake IncomingMessage
    var res = new EventEmitter();
    res.statusCode = 200;
    res.headers = { 'content-type': 'application/json' };
    res.setEncoding = function() { return res; };

    // Callback first (so caller attaches handlers), then emit data/end
    if (typeof callback === 'function') {
        process.nextTick(function() {
            callback(res);
            process.nextTick(function() {
                res.emit('data', body);
                res.emit('end');
            });
        });
    } else {
        process.nextTick(function() {
            res.emit('data', body);
            res.emit('end');
        });
    }

    // Fake ClientRequest (no-op)
    var req = new EventEmitter();
    req.end = function() { return req; };
    req.write = function() { return true; };
    req.destroy = function() {};
    req.setTimeout = function() { return req; };
    req.on = function(ev, fn) { EventEmitter.prototype.on.call(req, ev, fn); return req; };
    return req;
}

// 4a. intercept https.get / https.request
var _origHttpsRequest = https.request;
var _origHttpsGet = https.get;

https.request = function cacHttpsRequest(urlOrOpts, optsOrCb, cb) {
    var url = '';
    if (typeof urlOrOpts === 'string') {
        url = urlOrOpts;
    } else if (urlOrOpts && typeof urlOrOpts === 'object' && urlOrOpts.href) {
        url = urlOrOpts.href;
    } else if (urlOrOpts && typeof urlOrOpts === 'object') {
        var proto = urlOrOpts.protocol || 'https:';
        var host = urlOrOpts.hostname || urlOrOpts.host || '';
        var path = urlOrOpts.path || '/';
        url = proto + '//' + host + path;
    }
    var callback = typeof optsOrCb === 'function' ? optsOrCb : cb;
    if (isHealthCheck(url)) return makeHealthResponse(callback);
    return _origHttpsRequest.apply(https, arguments);
};

https.get = function cacHttpsGet(urlOrOpts, optsOrCb, cb) {
    var url = '';
    if (typeof urlOrOpts === 'string') {
        url = urlOrOpts;
    } else if (urlOrOpts && typeof urlOrOpts === 'object' && urlOrOpts.href) {
        url = urlOrOpts.href;
    } else if (urlOrOpts && typeof urlOrOpts === 'object') {
        var proto = urlOrOpts.protocol || 'https:';
        var host = urlOrOpts.hostname || urlOrOpts.host || '';
        var path = urlOrOpts.path || '/';
        url = proto + '//' + host + path;
    }
    var callback = typeof optsOrCb === 'function' ? optsOrCb : cb;
    if (isHealthCheck(url)) return makeHealthResponse(callback);
    return _origHttpsGet.apply(https, arguments);
};

// 4b. intercept fetch (undici bypasses https module)
(function patchHealthFetch() {
    if (typeof globalThis === 'undefined' || typeof globalThis.fetch !== 'function') return;
    var _prevFetch = globalThis.fetch;
    globalThis.fetch = function cacHealthFetch(input, init) {
        var url = '';
        try {
            url = typeof input === 'string' ? input : (input && input.url) ? input.url : '';
        } catch(e) {}
        if (isHealthCheck(url)) {
            return Promise.resolve(new Response('{"message":"hello"}', {
                status: 200,
                headers: { 'content-type': 'application/json' }
            }));
        }
        return _prevFetch(input, init);
    };
})();


// ─── 5. SOCKS5 network layer ─────────────────────────────────────
// Loopback stays local in the managed process. Every other TCP stream is sent
// to CAC_SOCKS_PROXY with its original domain (or IP literal) preserved.

(function socksNetworkLayer() {
    var socksEnv = process.env.CAC_SOCKS_PROXY;
    if (!socksEnv || socksEnv.indexOf('socks5://') !== 0) return;
    delete process.env.CAC_SOCKS_PROXY;

    // Bun snapshots the environment at boot, so deleting it here cannot undo
    // inheritance. The exact managed-entry check is what keeps descendants inert.
    var clawgodDir = process.env.CLAWGOD_DIR || '';
    if (process.argv[1] !== require('path').join(clawgodDir, 'cli.cjs')) return;

    var conflicts = ['NO_PROXY', 'no_proxy', 'HTTP_PROXY', 'http_proxy',
        'HTTPS_PROXY', 'https_proxy', 'ALL_PROXY', 'all_proxy'].filter(function(name) {
            return process.env[name];
        });
    if (conflicts.length) {
        process.stderr.write('cac: SOCKS5 mode requires unset proxy environment variables: ' +
            conflicts.join(', ') + '\n');
        process.exit(1);
    }

    var proxyUrl;
    try { proxyUrl = new URL(socksEnv); } catch (e) {
        process.stderr.write('cac: invalid CAC_SOCKS_PROXY URL\n');
        process.exit(1);
    }
    var PROXY_HOST = proxyUrl.hostname;
    var PROXY_PORT = parseInt(proxyUrl.port, 10) || 1080;
    var PROXY_USER = decodeURIComponent(proxyUrl.username || '');
    var PROXY_PASS = decodeURIComponent(proxyUrl.password || '');
    var Duplex = require('stream').Duplex;
    var RawSocket = net.Socket;
    var rawSocketConnect = RawSocket.prototype.connect;

    function normalizeHost(host) {
        host = String(host || '').toLowerCase().replace(/\.$/, '');
        if (host.charAt(0) === '[' && host.charAt(host.length - 1) === ']') host = host.slice(1, -1);
        return host;
    }
    function isLoopback(host) {
        host = normalizeHost(host);
        if (host === 'localhost' || host === '::1') return true;
        if (!net.isIPv4(host)) return false;
        return parseInt(host.split('.')[0], 10) === 127;
    }
    function restoreHost(host) {
        return fakeByIp[normalizeHost(host)] || normalizeHost(host);
    }
    function routeTarget(host) {
        host = restoreHost(host);
        return { host: host, loopback: isLoopback(host) };
    }
    function shallow(value) {
        var out = {};
        if (value) Object.keys(value).forEach(function(key) { out[key] = value[key]; });
        return out;
    }
    function displayHost(host) {
        return host.indexOf(':') !== -1 ? '[' + host + ']' : host;
    }

    // Fake tokens are consumed only in this process. Exhaustion fails rather
    // than wrapping and accidentally reusing a live hostname mapping.
    var fakeByIp = Object.create(null);
    var fakeByHost = Object.create(null);
    var fakeSeq = 0;
    function fakeIpFor(host) {
        host = normalizeHost(host);
        var ip = fakeByHost[host];
        if (ip) return ip;
        if (fakeSeq > 65535) {
            var err = new Error('cac: SOCKS fake IP address space exhausted');
            err.code = 'ENOSPC';
            throw err;
        }
        ip = '198.18.' + ((fakeSeq >> 8) & 255) + '.' + (fakeSeq & 255);
        fakeSeq++;
        fakeByHost[host] = ip;
        fakeByIp[ip] = host;
        return ip;
    }
    function explicitDomain(host) {
        host = normalizeHost(host);
        return host && !net.isIP(host) ? host : null;
    }
    function dnsError(syscall, hostname) {
        var err = new Error(syscall + ' ENOTFOUND ' + hostname);
        err.code = 'ENOTFOUND';
        err.errno = 'ENOTFOUND';
        err.syscall = syscall;
        err.hostname = hostname;
        return err;
    }
    function unsupportedDnsError(syscall, hostname) {
        var err = new Error(syscall + ' ENOTSUP ' + hostname +
            ' (cac SOCKS mode exposes only address records)');
        err.code = 'ENOTSUP';
        err.errno = 'ENOTSUP';
        err.syscall = syscall;
        err.hostname = hostname;
        return err;
    }

    function ipv6ToBytes(host) {
        host = host.split('%')[0];
        var v4 = host.match(/(\d{1,3}\.){3}\d{1,3}$/);
        if (v4) {
            var o = v4[0].split('.').map(Number);
            host = host.slice(0, host.length - v4[0].length) +
                (((o[0] << 8) | o[1]).toString(16)) + ':' +
                (((o[2] << 8) | o[3]).toString(16));
        }
        var halves = host.split('::');
        var head = halves[0] ? halves[0].split(':') : [];
        var tail = halves.length > 1 ? (halves[1] ? halves[1].split(':') : []) : null;
        var groups = head;
        if (tail) {
            for (var i = 0; i < 8 - head.length - tail.length; i++) groups.push('0');
            groups = groups.concat(tail);
        }
        if (groups.length !== 8) return null;
        var buf = Buffer.alloc(16);
        for (var j = 0; j < 8; j++) {
            var group = parseInt(groups[j] || '0', 16);
            if (isNaN(group) || group > 0xffff) return null;
            buf.writeUInt16BE(group, j * 2);
        }
        return buf;
    }

    function socksHandshake(sock, host, port, done) {
        var stage = 0;
        var buf = Buffer.alloc(0);
        var settled = false;
        function finish(err, leftover) {
            if (settled) return;
            settled = true;
            sock.removeListener('data', onData);
            done(err, leftover || Buffer.alloc(0));
        }
        function sendRequest() {
            var addr;
            if (net.isIPv4(host)) {
                addr = Buffer.concat([Buffer.from([1]), Buffer.from(host.split('.').map(Number))]);
            } else if (host.indexOf(':') !== -1) {
                var bytes = ipv6ToBytes(host);
                if (!bytes) return finish(new Error('socks5: bad ipv6 literal ' + host));
                addr = Buffer.concat([Buffer.from([4]), bytes]);
            } else {
                var name = Buffer.from(host, 'utf8');
                if (name.length > 255) return finish(new Error('socks5: domain too long'));
                addr = Buffer.concat([Buffer.from([3, name.length]), name]);
            }
            var portBuf = Buffer.alloc(2);
            portBuf.writeUInt16BE(port, 0);
            sock.write(Buffer.concat([Buffer.from([5, 1, 0]), addr, portBuf]));
        }
        function onData(chunk) {
            buf = Buffer.concat([buf, chunk]);
            for (;;) {
                if (stage === 0) {
                    if (buf.length < 2) return;
                    if (buf[0] !== 5 || buf[1] === 0xff) {
                        return finish(new Error('socks5: no acceptable auth method'));
                    }
                    var method = buf[1];
                    buf = buf.slice(2);
                    if (method === 2) {
                        var user = Buffer.from(PROXY_USER, 'utf8');
                        var pass = Buffer.from(PROXY_PASS, 'utf8');
                        if (user.length > 255 || pass.length > 255) {
                            return finish(new Error('socks5: credentials too long'));
                        }
                        sock.write(Buffer.concat([Buffer.from([1, user.length]), user,
                            Buffer.from([pass.length]), pass]));
                        stage = 1;
                    } else if (method === 0) {
                        stage = 2;
                        sendRequest();
                    } else {
                        return finish(new Error('socks5: unacceptable auth method ' + method));
                    }
                    continue;
                }
                if (stage === 1) {
                    if (buf.length < 2) return;
                    if (buf[0] !== 1 || buf[1] !== 0) {
                        return finish(new Error('socks5: authentication failed'));
                    }
                    buf = buf.slice(2);
                    stage = 2;
                    sendRequest();
                    continue;
                }
                if (buf.length < 5) return;
                var atyp = buf[3];
                var need = atyp === 1 ? 4 : atyp === 4 ? 16 : atyp === 3 ? buf[4] + 1 : 0;
                if (!need || buf.length < 4 + need + 2) return;
                if (buf[0] !== 5 || buf[1] !== 0) {
                    return finish(new Error('socks5: connect failed, reply ' + buf[1]));
                }
                return finish(null, buf.slice(4 + need + 2));
            }
        }
        sock.on('data', onData);
        sock.write(PROXY_USER ? Buffer.from([5, 2, 0, 2]) : Buffer.from([5, 1, 0]));
    }

    // The proxy control connection deliberately uses the original Socket
    // prototype. A proxy hostname uses the system resolver for this bootstrap;
    // zero-local-DNS users must configure a proxy IP literal.
    function socksSocket(host, port) {
        var inner = new RawSocket();
        var ready = false;
        var failed = null;
        var paused = false;
        var pending = [];
        var out = new Duplex({
            write: function(chunk, encoding, callback) {
                if (failed) return callback(failed);
                if (ready) return inner.write(chunk, encoding, callback);
                pending.push([chunk, encoding, callback]);
            },
            read: function() {
                if (paused) { paused = false; inner.resume(); }
            },
            final: function(callback) { inner.end(callback); },
            destroy: function(err, callback) { inner.destroy(); callback(err); }
        });
        out.connecting = true;
        out.remoteAddress = host;
        out.remotePort = port;
        out.cacSocksHost = net.isIP(host) ? undefined : host;
        out.localAddress = '';
        out.localPort = 0;
        out.setNoDelay = function(value) { inner.setNoDelay(value); return out; };
        out.setKeepAlive = function(value, delay) { inner.setKeepAlive(value, delay); return out; };
        out.setTimeout = function(timeout, callback) {
            if (callback) out.once('timeout', callback);
            inner.setTimeout(timeout);
            return out;
        };
        out.ref = function() { inner.ref(); return out; };
        out.unref = function() { inner.unref(); return out; };
        inner.on('timeout', function() { out.emit('timeout'); });
        inner.on('error', function(err) {
            if (!failed) { failed = err; out.destroy(err); }
        });
        inner.on('close', function() {
            if (!out.destroyed) out.destroy(failed);
        });
        rawSocketConnect.call(inner, { host: PROXY_HOST, port: PROXY_PORT }, function() {
            socksHandshake(inner, host, port, function(err, leftover) {
                if (err) { failed = err; out.destroy(err); return; }
                ready = true;
                out.connecting = false;
                out.localAddress = inner.localAddress;
                out.localPort = inner.localPort;
                inner.on('data', function(chunk) {
                    if (!out.push(chunk)) { paused = true; inner.pause(); }
                });
                inner.on('end', function() { out.push(null); });
                if (leftover.length && !out.push(leftover)) {
                    paused = true;
                    inner.pause();
                }
                var write;
                while ((write = pending.shift())) inner.write(write[0], write[1], write[2]);
                out.emit('connect');
            });
        });
        return out;
    }

    function rawConnect(host, port, callback) {
        var socket = new RawSocket();
        rawSocketConnect.call(socket, { host: host, port: port }, callback);
        return socket;
    }
    function openUpstream(host, port, callback) {
        var target = routeTarget(host);
        return target.loopback ? rawConnect(target.host, port, callback) :
            socksSocket(target.host, port).once('connect', callback);
    }
    function parseConnectTarget(target) {
        var host, portText;
        if (target.charAt(0) === '[') {
            var end = target.indexOf(']');
            if (end < 0) return null;
            host = target.slice(1, end);
            portText = target.slice(end + 2);
        } else {
            var colon = target.lastIndexOf(':');
            if (colon < 0) return { host: target, port: 443 };
            host = target.slice(0, colon);
            portText = target.slice(colon + 1);
        }
        return { host: host, port: parseInt(portText, 10) || 443 };
    }
    function absoluteRequest(head, method, url) {
        var lines = head.split('\r\n');
        lines[0] = method + ' ' + (url.pathname + url.search || '/') + ' HTTP/1.1';
        var replaced = false;
        var kept = [lines[0]];
        for (var i = 1; i < lines.length; i++) {
            if (/^proxy-connection:/i.test(lines[i])) continue;
            if (/^connection:/i.test(lines[i])) {
                if (!replaced) { kept.push('Connection: close'); replaced = true; }
                continue;
            }
            kept.push(lines[i]);
        }
        if (!replaced) kept.push('Connection: close');
        return kept.join('\r\n') + '\r\n\r\n';
    }

    var bridgeUrl = '';
    var bridge = net.createServer(function(client) {
        client.unref();
        client.on('error', function() {});
        var buffer = Buffer.alloc(0);
        client.on('data', function head(data) {
            buffer = Buffer.concat([buffer, data]);
            var end = buffer.indexOf('\r\n\r\n');
            if (end < 0) {
                if (buffer.length > 65536) client.destroy();
                return;
            }
            client.removeListener('data', head);
            client.pause();
            var first = buffer.slice(0, buffer.indexOf('\r\n')).toString('latin1');
            var parts = first.split(' ');
            var leftover = buffer.slice(end + 4);
            var upstream = null;
            var closed = false;
            function connect(host, port, ready) {
                upstream = openUpstream(host, port, ready);
                upstream.unref();
                upstream.on('error', function() { client.destroy(); });
                upstream.on('close', function() { client.destroy(); });
            }
            client.on('close', function() {
                closed = true;
                if (upstream) upstream.destroy();
            });
            if (parts[0] === 'CONNECT' && parts[1]) {
                var target = parseConnectTarget(parts[1]);
                if (!target) return client.destroy();
                connect(target.host, target.port, function() {
                    if (closed) return upstream.destroy();
                    client.write('HTTP/1.1 200 Connection Established\r\n\r\n');
                    if (leftover.length) upstream.write(leftover);
                    client.pipe(upstream);
                    upstream.pipe(client);
                    client.resume();
                });
                return;
            }
            var url;
            try { url = new URL(parts[1] || ''); } catch (e) { return client.destroy(); }
            if (url.protocol !== 'http:') return client.destroy();
            connect(normalizeHost(url.hostname), parseInt(url.port, 10) || 80, function() {
                if (closed) return upstream.destroy();
                var requestHead = Buffer.from(absoluteRequest(buffer.slice(0, end).toString('latin1'), parts[0], url), 'latin1');
                upstream.write(Buffer.concat([requestHead, leftover]));
                client.pipe(upstream);
                upstream.pipe(client);
                upstream.on('end', function() { client.end(); });
                client.resume();
            });
        });
    });
    bridge.unref();
    bridge.on('error', function(err) {
        process.stderr.write('cac: SOCKS bridge failed: ' + err.message + '\n');
        process.exit(1);
    });
    bridge.listen(0, '127.0.0.1');
    bridgeUrl = 'http://127.0.0.1:' + bridge.address().port;

    function withProxyInit(original) {
        return function(input, init) {
            if (init && init.proxy !== undefined) return original(input, init);
            return original(input, Object.assign({}, init, { proxy: bridgeUrl }));
        };
    }
    globalThis.fetch = withProxyInit(globalThis.fetch);
    // Known boundary: Bun 1.3.14 exposes Bun.fetch on a non-writable,
    // non-configurable Bun object. Direct Bun.fetch calls stay native; callers
    // through globalThis.fetch and node:http(s) remain routed.
    globalThis.fetch.preconnect = function() {};

    var nativeWebSocket;
    function CacWebSocket(url, protocols, options) {
        var args;
        if (protocols && typeof protocols === 'object' && !Array.isArray(protocols)) {
            if (protocols.proxy === undefined) {
                protocols = Object.assign({}, protocols, { proxy: bridgeUrl });
            }
            args = [url, protocols];
        } else if (options && typeof options === 'object') {
            if (options.proxy === undefined) {
                options = Object.assign({}, options, { proxy: bridgeUrl });
            }
            args = [url, protocols, options];
        } else {
            args = [url, { protocols: protocols, proxy: bridgeUrl }];
        }
        return Reflect.construct(nativeWebSocket, args);
    }
    if (typeof globalThis.WebSocket === 'function') {
        nativeWebSocket = globalThis.WebSocket;
        CacWebSocket.prototype = nativeWebSocket.prototype;
        Object.setPrototypeOf(CacWebSocket, nativeWebSocket);
        globalThis.WebSocket = CacWebSocket;
    }

    function parseRequestArgs(args) {
        var first = args[0];
        if (typeof first === 'string' || (first && typeof first === 'object' && (first.url || first.href))) {
            var options = args[1] && typeof args[1] === 'object' ? shallow(args[1]) : {};
            return {
                urlInput: first,
                options: options,
                callback: typeof args[2] === 'function' ? args[2] :
                    (typeof args[1] === 'function' ? args[1] : null)
            };
        }
        if (first && typeof first === 'object') {
            return { urlInput: null, options: shallow(first), callback: typeof args[1] === 'function' ? args[1] : null };
        }
        return null;
    }
    function makeProxyAgent(options, secure) {
        if (!bridgeUrl || (options.agent && options.agent.cacProxyAgent)) return null;
        var Agent = secure ? https.Agent : http.Agent;
        var source;
        if (options.agent === false) source = new Agent({});
        else source = options.agent || (secure ? https.globalAgent : http.globalAgent);
        var agentOptions = shallow(source.options || {});
        if (source.keepAlive !== undefined) agentOptions.keepAlive = source.keepAlive;
        var agent = new Agent(agentOptions);
        agent.connectOpts = shallow(source.connectOpts || {});
        agent.proxy = new URL(bridgeUrl);
        agent.cacProxyAgent = true;
        return agent;
    }
    function proxyRequestArgs(args, secure) {
        var parsed = parseRequestArgs(args);
        if (!parsed) return null;
        var agent = makeProxyAgent(parsed.options, secure);
        if (!agent) return null;
        parsed.options.agent = agent;
        var out = parsed.urlInput ? [parsed.urlInput, parsed.options] : [parsed.options];
        if (parsed.callback) out.push(parsed.callback);
        return out;
    }
    function wrapHttpModule(module, secure) {
        var oldRequest = module.request;
        var oldGet = module.get;
        module.request = function() {
            var fixed = proxyRequestArgs(arguments, secure);
            return oldRequest.apply(module, fixed || arguments);
        };
        module.get = function() {
            var fixed = proxyRequestArgs(arguments, secure);
            return oldGet.apply(module, fixed || arguments);
        };
        var OldClientRequest = module.ClientRequest;
        if (OldClientRequest && !OldClientRequest.cacWrappedClientRequest) {
            function CacClientRequest() {
                var fixed = proxyRequestArgs(arguments, secure);
                return Reflect.construct(OldClientRequest, fixed || arguments,
                    new.target || CacClientRequest);
            }
            CacClientRequest.prototype = OldClientRequest.prototype;
            Object.setPrototypeOf(CacClientRequest, OldClientRequest);
            Object.defineProperty(CacClientRequest, 'cacWrappedClientRequest', { value: true });
            module.ClientRequest = CacClientRequest;
        }
    }
    wrapHttpModule(http, false);
    wrapHttpModule(https, true);

    var guardedNetConnect = net.connect;
    net.connect = net.createConnection = function() {
        var options = null;
        var listener = null;
        if (arguments[0] && typeof arguments[0] === 'object') options = arguments[0];
        else if (typeof arguments[0] === 'number') {
            options = { port: arguments[0] };
            if (typeof arguments[1] === 'string') options.host = arguments[1];
        }
        for (var i = arguments.length - 1; i >= 0; i--) {
            if (typeof arguments[i] === 'function') { listener = arguments[i]; break; }
        }
        if (!options || options.path) return guardedNetConnect.apply(net, arguments);
        var target = routeTarget(options.host || options.hostname || 'localhost');
        if (isDomainBlocked(target.host)) return makeBlockedSocket(target.host);
        if (target.loopback) return guardedNetConnect.apply(net, arguments);
        var socket = socksSocket(target.host, options.port || 80);
        if (listener) socket.once('connect', listener);
        return socket;
    };

    var guardedTlsConnect = tls.connect;
    tls.connect = function() {
        var args = Array.prototype.slice.call(arguments);
        var options = null;
        var callback = null;
        if (args[0] && typeof args[0] === 'object') {
            options = args[0];
            callback = typeof args[1] === 'function' ? args[1] : null;
        } else if (typeof args[0] === 'number') {
            options = { port: args[0] };
            var index = 1;
            if (typeof args[index] === 'string') { options.host = args[index]; index++; }
            if (args[index] && typeof args[index] === 'object') {
                Object.keys(args[index]).forEach(function(key) { options[key] = args[index][key]; });
                index++;
            }
            callback = typeof args[index] === 'function' ? args[index] : null;
        }
        if (!options) return guardedTlsConnect.apply(tls, arguments);
        var connectHost = normalizeHost(options.host || options.hostname || options.servername ||
            (options.socket && options.socket.remoteAddress) || '');
        var restored = fakeByIp[connectHost];
        if (options.socket) {
            var servername = restored || options.socket.cacSocksHost;
            if (!servername) return guardedTlsConnect.apply(tls, arguments);
            var socketOptions = shallow(options);
            socketOptions.servername = servername;
            return guardedTlsConnect.call(tls, socketOptions, callback || undefined);
        }
        if (!connectHost || options.path) return guardedTlsConnect.apply(tls, arguments);
        var target = routeTarget(connectHost);
        if (isDomainBlocked(target.host)) {
            return guardedTlsConnect.call(tls, {
                socket: makeBlockedSocket(target.host),
                servername: target.host
            }, callback || undefined);
        }
        if (target.loopback) return guardedTlsConnect.apply(tls, arguments);
        var tlsOptions = shallow(options);
        tlsOptions.socket = socksSocket(target.host, options.port || 443);
        tlsOptions.servername = net.isIP(target.host) ? options.servername : target.host;
        delete tlsOptions.host;
        delete tlsOptions.hostname;
        delete tlsOptions.port;
        return guardedTlsConnect.call(tls, tlsOptions, callback || undefined);
    };

    if (typeof Bun !== 'undefined' && typeof Bun.connect === 'function') {
        var rawBunConnect = Bun.connect;
        Bun.connect = function(options) {
            if (!options || typeof options !== 'object') return rawBunConnect.apply(Bun, arguments);
            if (options.unix || options.fd !== undefined) return rawBunConnect.apply(Bun, arguments);
            if (options.tls) {
                // Known boundary: Bun.connect configures TLS while opening its
                // native socket, so it cannot start TLS after a bridge CONNECT.
                return Promise.reject(new Error('cac: Bun.connect TLS over SOCKS is not supported'));
            }
            if (!options.hostname || !options.port || !bridgeUrl) {
                return rawBunConnect.apply(Bun, arguments);
            }
            var user = options.socket || {};
            var target = routeTarget(options.hostname);
            var tunneled = false;
            var handshake = Buffer.alloc(0);
            var proxyOptions = shallow(options);
            proxyOptions.hostname = '127.0.0.1';
            proxyOptions.port = bridge.address().port;
            proxyOptions.socket = shallow(user);
            proxyOptions.socket.open = function(socket) {
                socket.write('CONNECT ' + displayHost(target.host) + ':' +
                    options.port + ' HTTP/1.1\r\n\r\n');
            };
            proxyOptions.socket.data = function(socket, data) {
                if (tunneled) return user.data && user.data(socket, data);
                handshake = Buffer.concat([handshake, Buffer.from(data)]);
                var end = handshake.indexOf('\r\n\r\n');
                if (end < 0) return;
                var status = handshake.slice(0, handshake.indexOf('\r\n')).toString('latin1');
                var leftover = handshake.slice(end + 4);
                tunneled = true;
                if (!/^HTTP\/1\.\d 200/.test(status)) {
                    var err = new Error('cac: bridge CONNECT failed: ' + status);
                    if (user.error) user.error(socket, err);
                    socket.end();
                    return;
                }
                if (user.open) user.open(socket);
                if (leftover.length && user.data) user.data(socket, leftover);
            };
            proxyOptions.socket.error = function(socket, err) { user.error && user.error(socket, err); };
            proxyOptions.socket.close = function(socket, err) { user.close && user.close(socket, err); };
            proxyOptions.socket.drain = function(socket) { user.drain && user.drain(socket); };
            return rawBunConnect.call(Bun, proxyOptions);
        };
    }

    function addressRecords(hostname, family, options) {
        var host = explicitDomain(hostname);
        if (!host) return null;
        if (family !== 4 && family !== 6) throw unsupportedDnsError('query', hostname);
        if (isDomainBlocked(host)) throw makeBlockedError(host, 'query');
        if (family === 6) throw dnsError('queryAaaa', hostname);
        var ip = fakeIpFor(host);
        return options && options.ttl ? [{ address: ip, family: 4, ttl: 0 }] : [ip];
    }
    var guardedLookup = dns.lookup;
    dns.lookup = function(hostname, options, callback) {
        if (typeof options === 'function') { callback = options; options = {}; }
        if (typeof options === 'number') options = { family: options };
        options = options || {};
        var host = explicitDomain(hostname);
        if (!host) return guardedLookup.call(dns, hostname, options, callback);
        if (isDomainBlocked(host)) {
            var blocked = makeBlockedError(host, 'getaddrinfo');
            process.nextTick(function() { callback(blocked); });
        } else if (options.family === 6) {
            var missing = dnsError('queryAaaa', hostname);
            process.nextTick(function() { callback(missing); });
        } else {
            var ip = fakeIpFor(host);
            process.nextTick(function() {
                if (options.all) callback(null, [{ address: ip, family: 4 }]);
                else callback(null, ip, 4);
            });
        }
        return {};
    };
    function callbackResolve(module, method, family) {
        var original = module[method];
        if (!original) return;
        module[method] = function(hostname) {
            var args = Array.prototype.slice.call(arguments);
            var options = typeof args[1] === 'object' ? args[1] : null;
            var callback = args[args.length - 1];
            try {
                var records = addressRecords(hostname, family, options);
                if (records) {
                    return void process.nextTick(function() { callback(null, records); });
                }
            } catch (err) {
                return void process.nextTick(function() { callback(err); });
            }
            return original.apply(this, args);
        };
    }
    callbackResolve(dns, 'resolve4', 4);
    callbackResolve(dns, 'resolve6', 6);
    var guardedResolve = dns.resolve;
    dns.resolve = function(hostname, rrtype, callback) {
        if (typeof rrtype === 'function') { callback = rrtype; rrtype = 'A'; }
        var host = explicitDomain(hostname);
        if (!host) return guardedResolve.apply(dns, arguments);
        var family = rrtype === 'A' || !rrtype ? 4 : rrtype === 'AAAA' ? 6 : 0;
        process.nextTick(function() {
            try { callback(null, addressRecords(hostname, family, null)); }
            catch (err) { callback(err); }
        });
    };
    ['resolveAny', 'resolveCaa', 'resolveCname', 'resolveMx', 'resolveNaptr',
        'resolveNs', 'resolvePtr', 'resolveSoa', 'resolveSrv', 'resolveTxt', 'reverse'
    ].forEach(function(method) {
        if (!dns[method]) return;
        dns[method] = function(hostname) {
            var args = Array.prototype.slice.call(arguments);
            var callback = args[args.length - 1];
            var host = normalizeHost(hostname);
            process.nextTick(function() {
                callback(unsupportedDnsError(method, host));
            });
        };
    });

    function wrapPromiseDns(module) {
        var originalLookup = module.lookup;
        if (originalLookup) module.lookup = function(hostname, options) {
            var host = explicitDomain(hostname);
            if (!host) return originalLookup.apply(this, arguments);
            if (isDomainBlocked(host)) return Promise.reject(makeBlockedError(host, 'getaddrinfo'));
            if (options && options.family === 6) return Promise.reject(dnsError('queryAaaa', hostname));
            var ip = fakeIpFor(host);
            return Promise.resolve(options && options.all ?
                [{ address: ip, family: 4 }] : { address: ip, family: 4 });
        };
        ['resolve4', 'resolve6'].forEach(function(method) {
            var original = module[method];
            if (!original) return;
            module[method] = function(hostname, options) {
                try {
                    var records = addressRecords(hostname, method === 'resolve4' ? 4 : 6, options);
                    if (records) return Promise.resolve(records);
                } catch (err) { return Promise.reject(err); }
                return original.apply(this, arguments);
            };
        });
        var originalResolve = module.resolve;
        if (originalResolve) module.resolve = function(hostname, rrtype) {
            var host = explicitDomain(hostname);
            if (!host) return originalResolve.apply(this, arguments);
            var family = rrtype === 'A' || !rrtype ? 4 : rrtype === 'AAAA' ? 6 : 0;
            try { return Promise.resolve(addressRecords(hostname, family, null)); }
            catch (err) { return Promise.reject(err); }
        };
        ['resolveAny', 'resolveCaa', 'resolveCname', 'resolveMx', 'resolveNaptr',
            'resolveNs', 'resolvePtr', 'resolveSoa', 'resolveSrv', 'resolveTxt', 'reverse'
        ].forEach(function(method) {
            if (!module[method]) return;
            module[method] = function(hostname) {
                return Promise.reject(unsupportedDnsError(method, normalizeHost(hostname)));
            };
        });
    }
    if (dns.promises) wrapPromiseDns(dns.promises);
    // Bun 1.3.14: instances of dns.Resolver are not on the exposed prototype
    // chain, so prototype patching never fires; wrap the constructor and put
    // the overrides on each instance instead.
    if (dns.Resolver) {
        var RawResolver = dns.Resolver;
        var CacResolver = function() {
            var instance = Reflect.construct(RawResolver, arguments);
            callbackResolve(instance, 'resolve4', 4);
            callbackResolve(instance, 'resolve6', 6);
            instance.resolve = function(hostname, rrtype, callback) {
                if (typeof rrtype === 'function') { callback = rrtype; rrtype = 'A'; }
                var host = explicitDomain(hostname);
                if (!host) {
                    var original = RawResolver.prototype.resolve;
                    return original.apply(instance, arguments);
                }
                var family = rrtype === 'A' || !rrtype ? 4 : rrtype === 'AAAA' ? 6 : 0;
                process.nextTick(function() {
                    try { callback(null, addressRecords(hostname, family, null)); }
                    catch (err) { callback(err); }
                });
            };
            ['resolveAny', 'resolveCaa', 'resolveCname', 'resolveMx', 'resolveNaptr',
                'resolveNs', 'resolvePtr', 'resolveSoa', 'resolveSrv', 'resolveTxt', 'reverse'
            ].forEach(function(method) {
                instance[method] = function(hostname, callback) {
                    process.nextTick(function() {
                        callback(unsupportedDnsError(method, normalizeHost(hostname)));
                    });
                };
            });
            return instance;
        };
        CacResolver.prototype = RawResolver.prototype;
        Object.setPrototypeOf(CacResolver, RawResolver);
        dns.Resolver = CacResolver;
    }
    if (dns.promises && dns.promises.Resolver) wrapPromiseDns(dns.promises.Resolver.prototype);
    if (typeof Bun !== 'undefined' && Bun.dns) {
        if (Bun.dns.prefetch) Bun.dns.prefetch = function() {};
        var rawBunLookup = Bun.dns.lookup;
        if (rawBunLookup) Bun.dns.lookup = function(hostname, options) {
            var host = explicitDomain(hostname);
            if (!host) return rawBunLookup.call(Bun.dns, hostname, options);
            if (options && options.family === 6) {
                return Promise.reject(dnsError('queryAaaa', hostname));
            }
            var ip = fakeIpFor(host);
            return Promise.resolve(options && options.single ?
                { address: ip, family: 4, ttl: 0 } :
                [{ address: ip, family: 4, ttl: 0 }]);
        };
        var rawBunResolve = Bun.dns.resolve;
        if (rawBunResolve) Bun.dns.resolve = function(hostname) {
            var host = explicitDomain(hostname);
            if (!host) return rawBunResolve.call(Bun.dns, hostname);
            return Promise.resolve([fakeIpFor(host)]);
        };
    }

    // Known boundary: constructing net.Socket and calling its prototype
    // connect method cannot be converted to a SOCKS Duplex while preserving that
    // same object. The bundle's direct JS callers use module exports or
    // Bun.connect, which are covered above.
})();
