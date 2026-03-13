import child from 'child_process';
import { promisify } from 'util';

const execAsync = promisify(child.exec);

let activeConnectionsCache = new Map(); 
let disconnectLog = []; 

// Formata o IP (IPv4 e IPv6)
const formatIP = (address) => {
    if (!address) return '---';
    if (address.includes(']')) return address.match(/\[(.*?)\]/)?.[0] || address;
    return address.split(':').slice(0, -1).join(':') || address;
};

// Pega o nome do arquivo com extensão
const formatProcessName = (proc) => {
    if (!proc) return 'Unknown';
    if (proc.Path) return proc.Path.split('\\').pop();
    return proc.Name;
};

// Encurta o caminho para caber na tabela, mantendo o final (que é o mais importante)
const truncatePath = (path) => {
    if (!path) return 'RESTRICTED ACCESS';
    return path;
};

async function monitor() {
    try {
        // Busca processos via PowerShell
        const psCmd = `powershell -Command "Get-Process | Select-Object Id, Name, Path | ConvertTo-Json"`;
        const { stdout: psOut } = await execAsync(psCmd, { maxBuffer: 1024 * 1024 * 10 });
        const processMap = new Map(JSON.parse(psOut).map(p => [p.Id, p]));

        // Busca conexões
        const { stdout: netstatOut } = await execAsync('netstat -ano');
        const lines = netstatOut.split('\n');
        
        let currentConnections = new Map();
        let currentTable = [];

        for (const line of lines) {
            const parts = line.trim().split(/\s+/);
            if (parts.length < 5) continue;

            const [proto, local, foreign, state, pidStr] = parts;
            const pid = parseInt(pidStr);

            // Ignora tráfego local
            if (foreign.includes('127.0.0.1') || foreign.includes('[::1]') || foreign === '*:*' || foreign === '0.0.0.0:0') continue;

            const proc = processMap.get(pid);
            const processName = formatProcessName(proc);
            const remoteIP = formatIP(foreign);
            const connectionKey = `${pid}-${remoteIP}`;

            const data = {
                PROCESS: processName,
                PID: pid,
                REMOTE_IP: remoteIP,
                STATUS: state,
                PATH: truncatePath(proc?.Path)
            };

            currentConnections.set(connectionKey, data);
            if (state === 'ESTABLISHED') currentTable.push(data);
        }

        // Detecta desconexões
        for (let [key, oldData] of activeConnectionsCache) {
            if (!currentConnections.has(key)) {
                disconnectLog.unshift({
                    PROCESS: oldData.PROCESS,
                    IP: oldData.REMOTE_IP,
                    CLOSED_AT: new Date().toLocaleTimeString(),
                    PATH: oldData.PATH
                });
            }
        }

        if (disconnectLog.length > 200) disconnectLog.pop();
        activeConnectionsCache = currentConnections;

        // Limpeza total da tela (ANSI Escape Codes)
        process.stdout.write('\x1Bc'); 
        process.stdout.write('\x1B[0;0f'); 

        console.log("====================================================================================================");
        console.log(`| Network Security Monitor - Real-Time Directories | ${new Date().toLocaleTimeString()}`);
        console.log("====================================================================================================");
        
        console.log("\n[ CONNECTIONS ESTABLISHED ]");
        if (currentTable.length > 0) {
            console.table(currentTable);
        } else {
            console.log("No active external connection...");
        }

        console.log("\n[ LATEST DISCONNECTIONS ]");
        if (disconnectLog.length > 0) {
            console.table(disconnectLog);
        } else {
            console.log("Waiting for connections to close...");
        }

    } catch (err) {
        
    }
}

// Execução
setInterval(monitor, 2500);
monitor();