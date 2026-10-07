// Heurísticas de risco. Cada regra adiciona um motivo { code, weight, detail }.
// O painel traduz o "code" e mostra a lista de motivos para o usuário entender o porquê.

const env = process.env;
const lower = (s) => (s ?? '').toLowerCase();
const WINDIR = lower(env.WINDIR || env.SystemRoot || 'C:\\Windows');

// Nomes de processos do Windows que malwares costumam imitar
const SYSTEM_NAMES = new Set([
    'svchost.exe', 'lsass.exe', 'csrss.exe', 'winlogon.exe', 'services.exe', 'smss.exe',
    'wininit.exe', 'explorer.exe', 'spoolsv.exe', 'taskhostw.exe', 'dllhost.exe',
    'conhost.exe', 'rundll32.exe', 'lsm.exe', 'dwm.exe', 'sihost.exe', 'ctfmon.exe',
    'searchindexer.exe', 'runtimebroker.exe', 'wuauclt.exe', 'taskmgr.exe', 'audiodg.exe',
]);

// Binários legítimos do Windows muito usados por malwares ("LOLBins")
const LOLBINS = new Set([
    'powershell.exe', 'pwsh.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe',
    'rundll32.exe', 'regsvr32.exe', 'certutil.exe', 'bitsadmin.exe', 'msbuild.exe',
    'installutil.exe', 'regasm.exe', 'regsvcs.exe', 'wmic.exe', 'cmstp.exe', 'msiexec.exe',
    'forfiles.exe', 'hh.exe', 'odbcconf.exe', 'curl.exe',
]);

const OFFICE_PARENTS = new Set(['winword.exe', 'excel.exe', 'powerpnt.exe', 'outlook.exe', 'msaccess.exe', 'mspub.exe', 'onenote.exe']);

// Portas comumente usadas por RATs / C2 / backdoors
export const SUSPICIOUS_PORTS = {
    4444: 'Metasploit', 1337: 'Backdoor', 31337: 'Back Orifice', 5552: 'njRAT', 1177: 'njRAT',
    1604: 'DarkComet', 2404: 'Remcos', 4782: 'Quasar RAT', 6606: 'AsyncRAT', 7707: 'AsyncRAT',
    8808: 'AsyncRAT', 8848: 'DcRat', 3460: 'Poison Ivy', 54984: 'NanoCore', 6667: 'IRC (botnet)',
    6697: 'IRC (botnet)', 9001: 'Tor', 9030: 'Tor', 9050: 'Tor', 9150: 'Tor', 5900: 'VNC', 5938: 'TeamViewer',
    3389: 'RDP',
};

const SUSPICIOUS_CMD = [
    /\s-e(nc|ncodedcommand)?\s+[a-z0-9+/=]{20,}/i,
    /-w(indowstyle)?\s+hid(den)?/i,
    /downloadstring|downloadfile|downloaddata|invoke-webrequest|\biwr\b|start-bitstransfer|net\.webclient/i,
    /\biex\b|invoke-expression|frombase64string/i,
    /mshta(\.exe)?\s+["']?(https?:|vbscript:|javascript:)/i,
    /regsvr32.*\/i:https?:/i,
    /certutil.*-urlcache/i,
    /-nop\b.*-w\s*h|bypass\s+-nop/i,
];

const LOCATION_RULES = [
    { code: 'loc_recycle', weight: 40, test: (p) => p.includes('\\$recycle.bin\\') },
    { code: 'loc_temp', weight: 30, test: (p) => p.includes('\\appdata\\local\\temp\\') || p.startsWith(WINDIR + '\\temp\\') },
    { code: 'loc_public', weight: 30, test: (p) => p.includes('\\users\\public\\') },
    { code: 'loc_startup', weight: 30, test: (p) => p.includes('\\start menu\\programs\\startup\\') },
    { code: 'loc_downloads', weight: 20, test: (p) => p.includes('\\downloads\\') },
    { code: 'loc_roaming', weight: 15, test: (p) => p.includes('\\appdata\\roaming\\') },
    { code: 'loc_programdata', weight: 10, test: (p) => /^[a-z]:\\programdata\\[^\\]+(\\[^\\]+)?$/.test(p) && !p.includes('\\microsoft\\') },
    { code: 'loc_desktop', weight: 10, test: (p) => p.includes('\\desktop\\') },
];

// Retorna a regra de local mais grave que se aplica ao texto (caminho ou linha de comando)
export function locationReason(text) {
    const p = lower(text);
    if (!p) return null;
    const rule = LOCATION_RULES.find((r) => r.test(p));
    return rule ? { code: rule.code, weight: rule.weight } : null;
}

export function suspiciousCommand(cmd) {
    if (!cmd) return null;
    const hit = SUSPICIOUS_CMD.find((re) => re.test(cmd));
    return hit ? cmd.match(hit)[0].trim().slice(0, 80) : null;
}

export const isUnderWindows = (path) => lower(path).startsWith(WINDIR + '\\');

export function signatureReasons(signature, fileExists) {
    if (!signature || fileExists === false) return [];
    switch (signature.status) {
        case 'Valid': return [];
        case 'NotSigned': return [{ code: 'unsigned', weight: 25 }];
        case 'HashMismatch': return [{ code: 'sig_tampered', weight: 50 }];
        default: return [{ code: 'sig_invalid', weight: 20, detail: signature.status }];
    }
}

export function levelFor(score) {
    if (score >= 50) return 'high';
    if (score >= 25) return 'medium';
    if (score > 0) return 'low';
    return 'clean';
}

const NO_SIGNATURE_DISCOUNT = new Set(['lolbin_network', 'suspicious_cmd', 'script_host', 'office_parent', 'masquerade', 'ifeo_debugger', 'winlogon_modified']);

export function finalize(reasons, { signature, trusted }) {
    if (trusted) return { score: 0, level: 'trusted', reasons };

    let score = reasons.reduce((acc, r) => acc + r.weight, 0);
    // Editor verificado reduz o peso de sinais fracos (não zera: malware assinado existe).
    // Não vale para abuso de binários do Windows: a assinatura é da Microsoft, não do que está rodando.
    const abusesSignedBinary = reasons.some((r) => NO_SIGNATURE_DISCOUNT.has(r.code));
    if (signature?.status === 'Valid' && score > 0 && !abusesSignedBinary) {
        reasons.push({ code: 'sig_valid', weight: -15, detail: signature.signer });
        score = Math.max(0, score - 15);
    }
    reasons.sort((a, b) => b.weight - a.weight);
    return { score, level: levelFor(score), reasons };
}

/**
 * Analisa um processo com atividade de rede.
 * proc: { name, path, cmd, parentName, connections[], listening[], beaconing[] }
 */
export function analyzeProcess(proc, { signature, file, trusted, isAdmin }) {
    const reasons = [];
    const name = lower(proc.name);
    const path = lower(proc.path);
    const external = proc.connections.filter((c) => c.scope === 'internet');

    if (proc.pid === 0 || proc.pid === 4) return { score: 0, level: 'clean', reasons };

    if (path) {
        const loc = locationReason(path);
        if (loc) reasons.push(loc);

        if (SYSTEM_NAMES.has(name) && !isUnderWindows(path)) {
            reasons.push({ code: 'masquerade', weight: 60, detail: proc.path });
        }

        reasons.push(...signatureReasons(signature, file?.exists));

        if (file?.birth && Date.now() - file.birth < 3 * 24 * 3600 * 1000) {
            reasons.push({ code: 'new_file', weight: 10 });
        }
        if (file && file.exists === false) {
            reasons.push({ code: 'file_missing', weight: 30 });
        }
    } else if (isAdmin) {
        // Como administrador quase todo caminho é visível; esconder é estranho
        reasons.push({ code: 'path_hidden', weight: 10 });
    }

    if (LOLBINS.has(name) && external.length) {
        reasons.push({ code: 'lolbin_network', weight: 25, detail: proc.name });
    }

    const cmdHit = suspiciousCommand(proc.cmd);
    if (cmdHit) reasons.push({ code: 'suspicious_cmd', weight: 30, detail: cmdHit });

    if (OFFICE_PARENTS.has(lower(proc.parentName))) {
        reasons.push({ code: 'office_parent', weight: 25, detail: proc.parentName });
    }

    const badPorts = new Map();
    for (const c of external) {
        if (SUSPICIOUS_PORTS[c.remotePort] && c.remotePort !== 3389 && c.remotePort !== 5938) {
            badPorts.set(c.remotePort, SUSPICIOUS_PORTS[c.remotePort]);
        }
    }
    if (badPorts.size) {
        const detail = [...badPorts].map(([port, label]) => `${port} (${label})`).join(', ');
        reasons.push({ code: 'rat_port', weight: 30, detail });
    }

    const publicListeners = proc.listening.filter((l) => l.public && l.proto === 'TCP');
    if (publicListeners.length && signature && signature.status !== 'Valid') {
        reasons.push({ code: 'listening_unsigned', weight: 15, detail: publicListeners.map((l) => l.localPort).join(', ') });
    }
    const backdoorListen = publicListeners.filter((l) => SUSPICIOUS_PORTS[l.localPort] && ![3389, 5938, 5900].includes(l.localPort));
    if (backdoorListen.length) {
        reasons.push({ code: 'listening_rat_port', weight: 35, detail: backdoorListen.map((l) => l.localPort).join(', ') });
    }

    // Serviços do Windows reconectam o tempo todo (Update, Store...); só conta para programas de terceiros ou LOLBins
    if (proc.beaconing?.length && path && (!isUnderWindows(path) || LOLBINS.has(name))) {
        reasons.push({ code: 'beaconing', weight: 15, detail: proc.beaconing.join(', ') });
    }

    return finalize(reasons, { signature, trusted });
}
