import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { stat } from 'node:fs/promises';
import dns from 'node:dns/promises';
import { psBackground as ps, psQuote } from './powershell.js';

// Informações caras de obter (assinatura, hash, DNS reverso) ficam em cache
// e são calculadas em segundo plano; o painel recebe o resultado no ciclo seguinte.

const signatures = new Map(); // path(lower) -> { status, signer } | 'pending'
const fileInfo = new Map();   // path(lower) -> { size, mtime, birth, exists } | 'pending'
const hashes = new Map();     // `${path}|${size}|${mtime}` -> sha256 | 'pending' | null
const hostnames = new Map();  // ip -> hostname | null | 'pending'

const MAX_HASH_SIZE = 200 * 1024 * 1024;

const SIGNATURE_SCRIPT = (paths) => `
foreach ($p in @(${paths.map(psQuote).join(',')})) {
  try {
    $s = Get-AuthenticodeSignature -LiteralPath $p
    $signer = $null
    if ($s.SignerCertificate) { $signer = $s.SignerCertificate.GetNameInfo('SimpleName', $false) }
    [pscustomobject]@{ path = $p; status = $s.Status.ToString(); signer = $signer; os = [bool]$s.IsOSBinary }
  } catch {
    [pscustomobject]@{ path = $p; status = 'Error'; signer = $null; os = $false }
  }
}`;

let signatureQueue = [];
let signatureRunning = false;

async function drainSignatures() {
    if (signatureRunning) return;
    signatureRunning = true;
    try {
        while (signatureQueue.length) {
            const batch = signatureQueue.splice(0, 25);
            try {
                const rows = await ps.run(SIGNATURE_SCRIPT(batch), 60000);
                for (const row of rows) {
                    signatures.set(row.path.toLowerCase(), { status: row.status, signer: row.signer, os: row.os });
                }
            } catch {
                // deixa como desconhecido, tenta de novo depois
            }
            for (const p of batch) {
                if (signatures.get(p.toLowerCase()) === 'pending') signatures.delete(p.toLowerCase());
            }
        }
    } finally {
        signatureRunning = false;
    }
}

export function getSignature(path) {
    if (!path) return null;
    const key = path.toLowerCase();
    const cached = signatures.get(key);
    if (cached === 'pending') return null;
    if (cached) return cached;

    signatures.set(key, 'pending');
    signatureQueue.push(path);
    drainSignatures();
    return null;
}

// Usado pela varredura de inicialização, que precisa esperar o resultado
export async function getSignaturesNow(paths) {
    const missing = [...new Set(paths.filter((p) => p && !signatures.has(p.toLowerCase())))];
    for (let i = 0; i < missing.length; i += 25) {
        try {
            const rows = await ps.run(SIGNATURE_SCRIPT(missing.slice(i, i + 25)), 60000);
            for (const row of rows) {
                signatures.set(row.path.toLowerCase(), { status: row.status, signer: row.signer, os: row.os });
            }
        } catch {}
    }
}

export function getFileInfo(path) {
    if (!path) return null;
    const key = path.toLowerCase();
    const cached = fileInfo.get(key);
    if (cached === 'pending') return null;
    if (cached) return cached;

    fileInfo.set(key, 'pending');
    stat(path)
        .then((s) => fileInfo.set(key, { exists: true, size: s.size, mtime: s.mtimeMs, birth: s.birthtimeMs }))
        .catch(() => fileInfo.set(key, { exists: false }));
    return null;
}

export async function getFileInfoNow(path) {
    getFileInfo(path);
    const key = path.toLowerCase();
    while (fileInfo.get(key) === 'pending') await new Promise((r) => setTimeout(r, 10));
    return fileInfo.get(key);
}

// Recarrega info de arquivo de vez em quando (o arquivo pode ter sido trocado)
export function invalidateFileInfo() {
    fileInfo.clear();
}

function sha256(path) {
    return new Promise((resolve, reject) => {
        const hash = createHash('sha256');
        createReadStream(path)
            .on('data', (chunk) => hash.update(chunk))
            .on('end', () => resolve(hash.digest('hex')))
            .on('error', reject);
    });
}

let hashQueue = [];
let hashRunning = false;

async function drainHashes() {
    if (hashRunning) return;
    hashRunning = true;
    while (hashQueue.length) {
        const { key, path } = hashQueue.shift();
        try {
            hashes.set(key, await sha256(path));
        } catch {
            hashes.set(key, null);
        }
    }
    hashRunning = false;
}

export function getHash(path) {
    const info = getFileInfo(path);
    if (!info?.exists || info.size > MAX_HASH_SIZE) return null;

    const key = `${path.toLowerCase()}|${info.size}|${info.mtime}`;
    const cached = hashes.get(key);
    if (cached === 'pending') return null;
    if (cached !== undefined) return cached;

    hashes.set(key, 'pending');
    hashQueue.push({ key, path });
    drainHashes();
    return null;
}

let dnsActive = 0;
const dnsQueue = [];

function pumpDns() {
    while (dnsActive < 4 && dnsQueue.length) {
        const ip = dnsQueue.shift();
        dnsActive++;
        const timeout = new Promise((resolve) => setTimeout(() => resolve([]), 3000));
        Promise.race([dns.reverse(ip).catch(() => []), timeout])
            .then((names) => hostnames.set(ip, names[0] ?? null))
            .finally(() => {
                dnsActive--;
                pumpDns();
            });
    }
}

export function getHostname(ip) {
    if (!ip) return null;
    const cached = hostnames.get(ip);
    if (cached === 'pending') return null;
    if (cached !== undefined) return cached;

    hostnames.set(ip, 'pending');
    dnsQueue.push(ip);
    pumpDns();
    return null;
}

// Ícone do executável (PNG 32x32 em base64), usado no painel para reconhecer o programa de relance
const icons = new Map(); // path(lower) -> Promise<Buffer | null>

const ICON_SCRIPT = (path) => `
Add-Type -AssemblyName System.Drawing
$icon = [System.Drawing.Icon]::ExtractAssociatedIcon(${psQuote(path)})
$stream = New-Object System.IO.MemoryStream
$icon.ToBitmap().Save($stream, [System.Drawing.Imaging.ImageFormat]::Png)
[Convert]::ToBase64String($stream.ToArray())`;

export function getIcon(path) {
    const key = path.toLowerCase();
    if (!icons.has(key)) {
        icons.set(key, ps.run(ICON_SCRIPT(path), 15000)
            .then(([b64]) => (b64 ? Buffer.from(b64, 'base64') : null))
            .catch(() => null));
    }
    return icons.get(key);
}
