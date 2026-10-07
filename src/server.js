import http from 'node:http';
import { randomBytes } from 'node:crypto';
import { spawn } from 'node:child_process';
import html from './ui/index.html';
import logo from '../assets/logo.png';
import { monitor } from './monitor.js';
import { firewall } from './firewall.js';
import { setTrusted } from './config.js';
import { scanPersistence } from './persistence.js';
import { getIcon } from './enrich.js';

const token = randomBytes(24).toString('hex');
const clients = new Set();
let lastPersistence = null;

function send(res, status, body, type = 'application/json; charset=utf-8', extra = {}) {
    res.writeHead(status, { 'Content-Type': type, 'Cache-Control': 'no-store', ...extra });
    res.end(typeof body === 'string' || Buffer.isBuffer(body) ? body : JSON.stringify(body));
}

function readBody(req) {
    return new Promise((resolve, reject) => {
        let data = '';
        req.on('data', (chunk) => {
            data += chunk;
            if (data.length > 1e6) req.destroy();
        });
        req.on('end', () => {
            try { resolve(data ? JSON.parse(data) : {}); } catch (err) { reject(err); }
        });
        req.on('error', reject);
    });
}

const actions = {
    async pause({ paused }) {
        monitor.setPaused(paused);
    },
    async kill({ pid }) {
        pid = Number(pid);
        if (!Number.isInteger(pid) || pid <= 4 || pid === process.pid) throw new Error('Invalid PID');
        process.kill(pid, 'SIGKILL');
    },
    async openFolder({ path }) {
        if (!path) throw new Error('No path');
        spawn('explorer.exe', [`/select,"${path}"`], { windowsVerbatimArguments: true, detached: true, stdio: 'ignore' }).unref();
    },
    async trust({ path, value }) {
        if (!path) throw new Error('No path');
        setTrusted(path, value);
    },
    async block({ path, name }) {
        if (!path) throw new Error('No path');
        await firewall.block(path, name);
    },
    async unblock({ path }) {
        if (!path) throw new Error('No path');
        await firewall.unblock(path);
    },
    async scanPersistence() {
        lastPersistence = await scanPersistence();
        return lastPersistence;
    },
    async persistence() {
        return lastPersistence;
    },
};

export function startServer({ onAllClientsGone } = {}) {
    let goneTimer = null;

    const server = http.createServer(async (req, res) => {
        const { port } = server.address();
        // Bloqueia DNS rebinding: só aceita requisições endereçadas ao próprio localhost
        if (req.headers.host !== `127.0.0.1:${port}` && req.headers.host !== `localhost:${port}`) {
            return send(res, 403, { error: 'Forbidden' });
        }

        const url = new URL(req.url, `http://${req.headers.host}`);
        const authorized = url.searchParams.get('t') === token || req.headers['x-token'] === token;

        if (req.method === 'GET' && url.pathname === '/') {
            return send(res, 200, html.replace('__TOKEN__', token), 'text/html; charset=utf-8');
        }
        if (req.method === 'GET' && url.pathname === '/logo.png') {
            return send(res, 200, Buffer.from(logo), 'image/png', { 'Cache-Control': 'max-age=86400' });
        }
        if (!authorized) return send(res, 401, { error: 'Unauthorized' });

        if (req.method === 'GET' && url.pathname === '/api/events') {
            res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-store', Connection: 'keep-alive' });
            res.write('retry: 2000\n\n');
            if (monitor.snapshot) res.write(`data: ${JSON.stringify(monitor.snapshot)}\n\n`);
            clients.add(res);
            clearTimeout(goneTimer);
            req.on('close', () => {
                clients.delete(res);
                if (clients.size === 0 && onAllClientsGone) {
                    goneTimer = setTimeout(() => clients.size === 0 && onAllClientsGone(), 15000);
                }
            });
            return;
        }

        if (req.method === 'GET' && url.pathname === '/api/icon') {
            const path = url.searchParams.get('p');
            const png = path ? await getIcon(path) : null;
            if (!png) return send(res, 404, { error: 'No icon' }, undefined, { 'Cache-Control': 'max-age=3600' });
            return send(res, 200, png, 'image/png', { 'Cache-Control': 'max-age=3600' });
        }

        if (req.method === 'GET' && url.pathname === '/api/export') {
            const report = { generatedAt: new Date().toISOString(), snapshot: monitor.snapshot, persistence: lastPersistence };
            const name = `nvi-report-${new Date().toISOString().replace(/[:.]/g, '-')}.json`;
            return send(res, 200, JSON.stringify(report, null, 2), 'application/json', { 'Content-Disposition': `attachment; filename="${name}"` });
        }

        if (req.method === 'POST' && url.pathname.startsWith('/api/action/')) {
            const action = actions[url.pathname.slice('/api/action/'.length)];
            if (!action) return send(res, 404, { error: 'Unknown action' });
            try {
                const result = await action(await readBody(req));
                send(res, 200, { ok: true, result: result ?? null });
                // Ações que mudam o estado: força um ciclo para a UI refletir na hora
                if (!monitor.paused) monitor.tick();
            } catch (err) {
                send(res, 500, { ok: false, error: err.message });
            }
            return;
        }

        send(res, 404, { error: 'Not found' });
    });

    monitor.on('update', (snapshot) => {
        const payload = `data: ${JSON.stringify(snapshot)}\n\n`;
        for (const client of clients) client.write(payload);
    });

    return new Promise((resolve) => {
        server.listen(0, '127.0.0.1', () => resolve(`http://127.0.0.1:${server.address().port}/`));
    });
}
