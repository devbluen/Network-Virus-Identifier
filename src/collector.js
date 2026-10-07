import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { ps } from './powershell.js';

const execFileAsync = promisify(execFile);

const PROCESS_SCRIPT = `
$epoch = [datetime]'1970-01-01'
Get-CimInstance Win32_Process | ForEach-Object {
  [pscustomobject]@{
    pid = $_.ProcessId
    ppid = $_.ParentProcessId
    name = $_.Name
    path = $_.ExecutablePath
    cmd = $_.CommandLine
    created = $(if ($_.CreationDate) { [int64]($_.CreationDate.ToUniversalTime() - $epoch).TotalMilliseconds } else { $null })
  }
}`;

export async function getProcesses() {
    const list = await ps.run(PROCESS_SCRIPT);
    return new Map(list.map((p) => [p.pid, p]));
}

// "[fe80::1%12]:443" | "192.168.0.1:443" | "*:*"
export function parseEndpoint(text) {
    if (!text || text === '*:*') return { ip: null, port: null };
    const idx = text.lastIndexOf(':');
    let ip = text.slice(0, idx);
    const port = parseInt(text.slice(idx + 1), 10);
    if (ip.startsWith('[')) ip = ip.slice(1, -1).replace(/%\d+$/, '');
    return { ip, port: Number.isNaN(port) ? null : port };
}

// Alguns Windows traduzem os estados do netstat; normalizamos para o nome em inglês
const STATE_ALIASES = {
    ESTABELECIDA: 'ESTABLISHED', ESTABELECIDO: 'ESTABLISHED', HERGESTELLT: 'ESTABLISHED', ESTABLECIDO: 'ESTABLISHED', ETABLI: 'ESTABLISHED',
    ESCUTANDO: 'LISTENING', ABHÖREN: 'LISTENING', ESCUCHANDO: 'LISTENING', ECOUTE: 'LISTENING',
};

export async function getConnections() {
    const { stdout } = await execFileAsync('netstat', ['-ano'], { windowsHide: true, maxBuffer: 1024 * 1024 * 20 });
    const result = [];

    for (const line of stdout.split(/\r?\n/)) {
        const parts = line.trim().split(/\s+/);
        const proto = parts[0];
        if (proto !== 'TCP' && proto !== 'UDP') continue;

        const isTcp = proto === 'TCP';
        if (parts.length < (isTcp ? 5 : 4)) continue;

        const local = parseEndpoint(parts[1]);
        const remote = parseEndpoint(parts[2]);
        const rawState = isTcp ? parts[3].toUpperCase() : '';
        const state = isTcp ? (STATE_ALIASES[rawState] ?? rawState) : 'UDP';
        const pid = parseInt(parts[isTcp ? 4 : 3], 10);

        result.push({
            proto,
            localIp: local.ip,
            localPort: local.port,
            remoteIp: remote.ip,
            remotePort: remote.port,
            state,
            pid,
        });
    }
    return result;
}
