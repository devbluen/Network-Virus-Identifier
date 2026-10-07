import { psBackground as ps } from './powershell.js';
import { getFileInfoNow, getSignature, getSignaturesNow } from './enrich.js';
import { finalize, isUnderWindows, locationReason, signatureReasons, suspiciousCommand } from './analyzer.js';
import { isTrusted } from './config.js';

// Lugares onde malwares costumam se registrar para iniciar junto com o Windows
const SCAN_SCRIPT = `
$items = New-Object System.Collections.ArrayList

Get-CimInstance Win32_StartupCommand | ForEach-Object {
  [void]$items.Add([pscustomobject]@{ type = 'startup'; name = $_.Name; command = $_.Command; location = $_.Location })
}

Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\\Microsoft\\*' } | ForEach-Object {
  $task = $_
  foreach ($a in $task.Actions) {
    if ($a.Execute) {
      [void]$items.Add([pscustomobject]@{ type = 'task'; name = $task.TaskName; command = ($a.Execute + ' ' + $a.Arguments).Trim(); location = $task.TaskPath; state = $task.State.ToString() })
    }
  }
}

Get-CimInstance Win32_Service | Where-Object { $_.PathName -and $_.PathName -notmatch '\\\\Windows\\\\' } | ForEach-Object {
  [void]$items.Add([pscustomobject]@{ type = 'service'; name = $_.DisplayName; command = $_.PathName; location = $_.Name; state = $_.State })
}

$wl = Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon' -ErrorAction SilentlyContinue
if ($wl) {
  [void]$items.Add([pscustomobject]@{ type = 'winlogon'; name = 'Shell'; command = [string]$wl.Shell; location = 'HKLM\\...\\Winlogon' })
  [void]$items.Add([pscustomobject]@{ type = 'winlogon'; name = 'Userinit'; command = [string]$wl.Userinit; location = 'HKLM\\...\\Winlogon' })
}

Get-ChildItem 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options' -ErrorAction SilentlyContinue | ForEach-Object {
  $dbg = (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).Debugger
  if ($dbg) { [void]$items.Add([pscustomobject]@{ type = 'ifeo'; name = $_.PSChildName; command = [string]$dbg; location = 'Image File Execution Options' }) }
}

$items
`;

const EXEC_EXT = /^(.*?\.(?:exe|com|bat|cmd|scr|pif|ps1|vbs|vbe|js|jse|wsf|hta|dll|msi|cpl|sys))(?=\s|,|"|$)/i;
const SCRIPT_HOSTS = /^(powershell|pwsh|cmd|wscript|cscript|mshta|rundll32|regsvr32)(\.exe)?$/i;

const expandEnv = (text) => text.replace(/%([^%]+)%/g, (m, name) => process.env[name] ?? process.env[name.toUpperCase()] ?? m);

// Extrai o caminho do executável de uma linha de comando
export function extractExecutable(command) {
    if (!command) return null;
    // Algumas tarefas agendadas usam "C:/Program Files/..." com barras normais
    let cmd = expandEnv(command.trim()).replace(/\//g, '\\');
    const windir = process.env.WINDIR || 'C:\\Windows';

    cmd = cmd.replace(/^\\\?\?\\/, '').replace(/^\\SystemRoot\\/i, windir + '\\');
    if (/^system32\\/i.test(cmd)) cmd = `${windir}\\${cmd}`;

    if (cmd.startsWith('"')) {
        const end = cmd.indexOf('"', 1);
        return end > 0 ? cmd.slice(1, end) : cmd.slice(1);
    }
    const match = cmd.match(EXEC_EXT);
    if (match) return match[1];
    return cmd.split(/\s+/)[0];
}

function resolveBareName(exe) {
    // "rundll32.exe x" ou "cmd /c ..." sem caminho completo -> System32
    if (exe && !exe.includes('\\') && !exe.includes(':')) {
        const name = exe.toLowerCase().endsWith('.exe') ? exe : `${exe}.exe`;
        return `${process.env.WINDIR || 'C:\\Windows'}\\System32\\${name}`;
    }
    return exe;
}

const DEFAULT_WINLOGON = {
    shell: /^explorer\.exe,?$/i,
    userinit: /^[a-z]:\\windows\\system32\\userinit\.exe,?$/i,
};

export async function scanPersistence() {
    const rows = await ps.run(SCAN_SCRIPT, 120000);

    const items = rows.map((row) => {
        const exe = resolveBareName(extractExecutable(row.command));
        return { ...row, exe };
    });

    await getSignaturesNow(items.map((i) => i.exe).filter(Boolean));

    const result = [];
    for (const item of items) {
        const reasons = [];
        const file = item.exe ? await getFileInfoNow(item.exe) : null;
        const signature = file?.exists ? getSignature(item.exe) : null;

        if (item.type === 'winlogon') {
            const def = DEFAULT_WINLOGON[item.name.toLowerCase()];
            if (def && !def.test(item.command.trim())) reasons.push({ code: 'winlogon_modified', weight: 60, detail: item.command });
            else continue; // valor padrão, não precisa listar
        }
        if (item.type === 'ifeo') reasons.push({ code: 'ifeo_debugger', weight: 40, detail: item.name });

        const exeName = (item.exe ?? '').split('\\').pop();
        const loc = locationReason(item.exe) ?? locationReason(item.command);
        if (loc) reasons.push(loc);
        if (file && !file.exists && item.exe) reasons.push({ code: 'file_missing', weight: 10 });
        reasons.push(...signatureReasons(signature, file?.exists));

        if (SCRIPT_HOSTS.test(exeName) && isUnderWindows(item.exe)) {
            reasons.push({ code: 'script_host', weight: 20, detail: exeName });
        }
        const cmdHit = suspiciousCommand(item.command);
        if (cmdHit) reasons.push({ code: 'suspicious_cmd', weight: 30, detail: cmdHit });
        if (file?.birth && Date.now() - file.birth < 3 * 24 * 3600 * 1000) reasons.push({ code: 'new_file', weight: 10 });

        const trusted = isTrusted(item.exe);
        result.push({
            ...item,
            signature,
            exists: file?.exists ?? null,
            trusted,
            risk: finalize(reasons, { signature, trusted }),
        });
    }

    result.sort((a, b) => b.risk.score - a.risk.score);
    return { time: Date.now(), items: result };
}
