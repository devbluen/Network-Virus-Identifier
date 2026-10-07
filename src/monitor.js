import { EventEmitter } from 'node:events';
import { getConnections, getProcesses } from './collector.js';
import { getFileInfo, getHash, getHostname, getSignature, invalidateFileInfo } from './enrich.js';
import { analyzeProcess } from './analyzer.js';
import { ipScope, isWildcard } from './ip.js';
import { isTrusted } from './config.js';
import { firewall } from './firewall.js';

const INTERVAL = 2500;
const HISTORY_LIMIT = 1000;
const BEACON_WINDOW = 10 * 60 * 1000;
const BEACON_MIN = 6;

const connKey = (c) => `${c.proto}|${c.localIp}|${c.localPort}|${c.remoteIp}|${c.remotePort}|${c.pid}`;

class Monitor extends EventEmitter {
    constructor() {
        super();
        this.paused = false;
        this.isAdmin = false;
        this.ticks = 0;
        this.snapshot = null;
        this.lastError = null;
        this.history = [];
        this.eventId = 0;
        this.previous = new Map();     // connKey -> conexão do ciclo anterior
        this.firstSeen = new Map();    // connKey -> timestamp
        this.knownProcs = new Set();   // caminhos/nomes já vistos com rede
        this.alerted = new Set();      // caminhos que já geraram alerta
        this.opens = new Map();        // `${proc}|${ip}` -> [timestamps] (detecção de beaconing)
        this.timeline = [];            // estatísticas dos últimos ciclos (gráfico do painel)
    }

    start() {
        const loop = async () => {
            if (!this.paused) await this.tick();
            this.timer = setTimeout(loop, INTERVAL);
        };
        loop();
        setInterval(invalidateFileInfo, 5 * 60 * 1000).unref();
    }

    setPaused(value) {
        this.paused = !!value;
        if (this.snapshot) {
            this.snapshot.paused = this.paused;
            this.emit('update', this.snapshot);
        }
    }

    log(event) {
        this.history.unshift({ id: ++this.eventId, t: Date.now(), ...event });
        if (this.history.length > HISTORY_LIMIT) this.history.length = HISTORY_LIMIT;
    }

    // Evita dois ciclos simultâneos (o loop e uma ação do usuário podem pedir ao mesmo tempo)
    async tick() {
        if (this.running) return this.running;
        this.running = this.scan().finally(() => (this.running = null));
        return this.running;
    }

    async scan() {
        const started = Date.now();
        let procMap, rawConns;
        try {
            [procMap, rawConns] = await Promise.all([getProcesses(), getConnections()]);
            this.lastError = null;
        } catch (err) {
            this.lastError = err.message;
            if (this.snapshot) this.emit('update', { ...this.snapshot, error: this.lastError });
            return;
        }

        const baseline = this.ticks === 0;
        this.ticks++;
        const now = Date.now();
        const current = new Map();
        const byPid = new Map();

        const entryFor = (pid) => {
            if (!byPid.has(pid)) {
                const p = procMap.get(pid);
                const parent = p ? procMap.get(p.ppid) : null;
                byPid.set(pid, {
                    pid,
                    ppid: p?.ppid ?? null,
                    parentName: parent?.name ?? null,
                    name: pid === 0 ? 'System Idle' : (p?.name ?? 'Unknown'),
                    path: p?.path ?? null,
                    cmd: p?.cmd ?? null,
                    created: p?.created ?? null,
                    connections: [],
                    listening: [],
                    beaconing: [],
                    hasActivity: false,
                });
            }
            return byPid.get(pid);
        };

        for (const c of rawConns) {
            // PID 0 são sockets já fechados aguardando TIME_WAIT: só ruído
            if (c.pid === 0) continue;
            const isListen = c.state === 'LISTENING' || (c.proto === 'UDP' && !c.remoteIp);
            if (isListen) {
                const localScope = ipScope(c.localIp);
                const pub = isWildcard(c.localIp) || localScope === 'lan' || localScope === 'internet';
                const entry = entryFor(c.pid);
                entry.listening.push({ proto: c.proto, localIp: c.localIp, localPort: c.localPort, public: pub });
                if (pub && c.proto === 'TCP') entry.hasActivity = true;
                continue;
            }

            const scope = ipScope(c.remoteIp);
            if (scope === 'local' || scope === 'none') continue;

            const key = connKey(c);
            if (!this.firstSeen.has(key)) this.firstSeen.set(key, now);
            const conn = { ...c, scope, host: getHostname(c.remoteIp), firstSeen: this.firstSeen.get(key) };
            current.set(key, conn);

            const entry = entryFor(c.pid);
            entry.connections.push(conn);
            entry.hasActivity = true;
        }

        // Conexões novas e encerradas
        for (const [key, conn] of current) {
            if (this.previous.has(key)) continue;
            const proc = byPid.get(conn.pid);
            if (!baseline) {
                this.log({ type: 'open', pid: conn.pid, name: proc.name, path: proc.path, remote: `${conn.remoteIp}:${conn.remotePort}`, host: conn.host, scope: conn.scope, state: conn.state });
            }
            if (conn.proto === 'TCP' && conn.scope === 'internet') {
                const bKey = `${(proc.path ?? proc.name).toLowerCase()}|${conn.remoteIp}`;
                const list = (this.opens.get(bKey) ?? []).filter((t) => now - t < BEACON_WINDOW);
                list.push(now);
                this.opens.set(bKey, list);
            }
        }
        for (const [key, conn] of this.previous) {
            if (current.has(key)) continue;
            this.firstSeen.delete(key);
            this.log({ type: 'close', pid: conn.pid, name: conn.procName, path: conn.procPath, remote: `${conn.remoteIp}:${conn.remotePort}`, host: getHostname(conn.remoteIp), scope: conn.scope, duration: now - conn.firstSeen });
        }
        for (const [key, conn] of current) {
            const proc = byPid.get(conn.pid);
            conn.procName = proc.name;
            conn.procPath = proc.path;
        }
        this.previous = current;

        // Limpa contadores de beaconing antigos
        for (const [key, list] of this.opens) {
            if (now - list[list.length - 1] > BEACON_WINDOW) this.opens.delete(key);
        }

        const processes = [];
        for (const entry of byPid.values()) {
            if (!entry.hasActivity) continue;

            const id = (entry.path ?? entry.name).toLowerCase();
            for (const [bKey, list] of this.opens) {
                if (list.length >= BEACON_MIN && bKey.startsWith(id + '|')) entry.beaconing.push(bKey.slice(id.length + 1));
            }

            const signature = getSignature(entry.path);
            const file = getFileInfo(entry.path);
            const trusted = isTrusted(entry.path);
            const risk = analyzeProcess(entry, { signature, file, trusted, isAdmin: this.isAdmin });
            delete entry.hasActivity;

            const proc = {
                ...entry,
                signature,
                file: file?.exists ? { size: file.size, birth: file.birth, mtime: file.mtime } : file,
                sha256: entry.path ? getHash(entry.path) : null,
                trusted,
                blocked: firewall.isBlocked(entry.path),
                risk,
            };
            processes.push(proc);

            if (!this.knownProcs.has(id)) {
                this.knownProcs.add(id);
                if (!baseline) this.log({ type: 'proc_new', pid: proc.pid, name: proc.name, path: proc.path, level: risk.level });
            }
            if (risk.level === 'high' && !this.alerted.has(id)) {
                this.alerted.add(id);
                this.log({ type: 'alert', pid: proc.pid, name: proc.name, path: proc.path, level: risk.level, reasons: risk.reasons.map((r) => r.code) });
            }
        }

        processes.sort((a, b) => b.risk.score - a.risk.score || b.connections.length - a.connections.length);

        const allConns = processes.flatMap((p) => p.connections);
        this.timeline.push({
            t: now,
            internet: allConns.filter((c) => c.scope === 'internet').length,
            established: allConns.filter((c) => c.state === 'ESTABLISHED').length,
            processes: processes.length,
        });
        if (this.timeline.length > 120) this.timeline.shift();

        this.snapshot = {
            time: now,
            scanMs: now - started,
            paused: this.paused,
            isAdmin: this.isAdmin,
            error: null,
            stats: {
                processes: processes.length,
                established: allConns.filter((c) => c.state === 'ESTABLISHED').length,
                internet: allConns.filter((c) => c.scope === 'internet').length,
                listening: processes.reduce((acc, p) => acc + p.listening.filter((l) => l.public && l.proto === 'TCP').length, 0),
                high: processes.filter((p) => p.risk.level === 'high').length,
                medium: processes.filter((p) => p.risk.level === 'medium').length,
            },
            processes,
            timeline: this.timeline,
            history: this.history.slice(0, 400),
        };
        this.emit('update', this.snapshot);
    }
}

export const monitor = new Monitor();
