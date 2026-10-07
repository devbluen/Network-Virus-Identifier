import { existsSync } from 'node:fs';
import { spawn, execFileSync } from 'node:child_process';
import { join } from 'node:path';
import { startServer } from './server.js';
import { monitor } from './monitor.js';
import { firewall } from './firewall.js';
import { ps, psBackground } from './powershell.js';

const args = new Set(process.argv.slice(2));
const noBrowser = args.has('--no-browser');
const keepAlive = args.has('--keep-alive') || noBrowser;

function isAdmin() {
    try {
        execFileSync('net', ['session'], { stdio: 'ignore', windowsHide: true });
        return true;
    } catch {
        return false;
    }
}

// Abre o painel como "app" (janela própria, sem barra de endereço) no Edge/Chrome; senão no navegador padrão
function openWindow(url) {
    const candidates = [
        join(process.env['ProgramFiles(x86)'] || '', 'Microsoft\\Edge\\Application\\msedge.exe'),
        join(process.env.ProgramFiles || '', 'Microsoft\\Edge\\Application\\msedge.exe'),
        join(process.env.ProgramFiles || '', 'Google\\Chrome\\Application\\chrome.exe'),
        join(process.env.LOCALAPPDATA || '', 'Google\\Chrome\\Application\\chrome.exe'),
    ];
    const browser = candidates.find((p) => p && existsSync(p));
    if (browser) {
        spawn(browser, [`--app=${url}`, '--window-size=1440,900'], { detached: true, stdio: 'ignore' }).unref();
    } else {
        spawn('cmd.exe', ['/c', 'start', '""', `"${url}"`], { windowsVerbatimArguments: true, detached: true, stdio: 'ignore' }).unref();
    }
}

function shutdown() {
    ps.stop();
    psBackground.stop();
    process.exit(0);
}

async function main() {
    process.title = 'Network Virus Identifier';

    if (process.platform !== 'win32') {
        console.error('Network Virus Identifier currently supports Windows only.');
        process.exit(1);
    }

    monitor.isAdmin = isAdmin();
    const url = await startServer({ onAllClientsGone: keepAlive ? null : shutdown });

    console.log('');
    console.log('  Network Virus Identifier');
    console.log('  ------------------------');
    console.log(`  Dashboard: ${url}`);
    console.log(`  Administrator: ${monitor.isAdmin ? 'yes' : 'NO - some paths and actions will be unavailable'}`);
    console.log('');
    console.log('  Close the dashboard window or press Ctrl+C to exit.');
    console.log('');

    firewall.refresh();
    monitor.start();
    if (!noBrowser) openWindow(url);

    process.on('SIGINT', shutdown);
    process.on('SIGTERM', shutdown);
}

main();
