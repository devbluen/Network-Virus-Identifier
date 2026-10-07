import { spawn } from 'node:child_process';

// Mantém um único processo PowerShell aberto e envia comandos por stdin.
// Abrir um PowerShell novo a cada ciclo custa ~0.5s de CPU; reaproveitar é bem mais leve.
// Protocolo: cada comando vai em uma linha (base64 UTF-8), cada resposta volta em uma linha (base64 UTF-8 de JSON).
const BOOTSTRAP = `
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::InputEncoding = [Text.Encoding]::UTF8
[Console]::OutputEncoding = [Text.Encoding]::UTF8
while ($true) {
  $line = [Console]::In.ReadLine()
  if ($line -eq $null) { break }
  try {
    $script = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($line))
    $result = Invoke-Expression $script
    $json = ConvertTo-Json -InputObject @{ ok = $true; data = @($result) } -Depth 4 -Compress
  } catch {
    $json = ConvertTo-Json -InputObject @{ ok = $false; error = $_.Exception.Message } -Compress
  }
  [Console]::Out.WriteLine([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json)))
}
`;

const encode = (text) => Buffer.from(text, 'utf16le').toString('base64');

export const psQuote = (value) => `'${String(value).replace(/'/g, "''")}'`;

export class PowerShellHost {
    constructor() {
        this.proc = null;
        this.queue = [];
        this.current = null;
        this.buffer = '';
    }

    start() {
        this.proc = spawn('powershell.exe', ['-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', encode(BOOTSTRAP)], {
            windowsHide: true,
            stdio: ['pipe', 'pipe', 'ignore'],
        });
        this.proc.stdout.setEncoding('utf8');
        this.proc.stdout.on('data', (chunk) => this.onData(chunk));
        this.proc.on('exit', () => {
            this.proc = null;
            this.current?.reject(new Error('PowerShell exited unexpectedly'));
            this.current = null;
            this.buffer = '';
            this.next();
        });
    }

    onData(chunk) {
        this.buffer += chunk;
        let index;
        while ((index = this.buffer.indexOf('\n')) !== -1) {
            const line = this.buffer.slice(0, index).trim();
            this.buffer = this.buffer.slice(index + 1);
            if (!line || !this.current) continue;

            const { resolve, reject, timer } = this.current;
            clearTimeout(timer);
            this.current = null;
            try {
                const res = JSON.parse(Buffer.from(line, 'base64').toString('utf8'));
                if (res.ok) resolve((res.data ?? []).filter((item) => item !== null));
                else reject(new Error(res.error));
            } catch (err) {
                reject(err);
            }
            this.next();
        }
    }

    // Executa um script e devolve sempre um array com os objetos retornados
    run(script, timeoutMs = 30000) {
        return new Promise((resolve, reject) => {
            this.queue.push({ script, resolve, reject, timeoutMs });
            this.next();
        });
    }

    next() {
        if (this.current || this.queue.length === 0) return;
        if (!this.proc) this.start();

        const job = this.queue.shift();
        job.timer = setTimeout(() => {
            // Comando travado: mata o host, o evento 'exit' rejeita e o próximo comando sobe um host novo
            this.proc?.kill();
        }, job.timeoutMs);
        this.current = job;
        this.proc.stdin.write(Buffer.from(job.script, 'utf8').toString('base64') + '\n');
    }

    stop() {
        this.queue = [];
        this.proc?.kill();
    }
}

// Host principal (coleta a cada ciclo) e host para tarefas lentas (assinaturas, firewall, inicialização),
// assim uma tarefa demorada nunca atrasa a atualização do painel
export const ps = new PowerShellHost();
export const psBackground = new PowerShellHost();
