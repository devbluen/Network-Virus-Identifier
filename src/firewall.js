import { psBackground as ps, psQuote } from './powershell.js';

const GROUP = 'NetworkVirusIdentifier';

class Firewall {
    constructor() {
        this.blocked = new Set();
    }

    isBlocked(path) {
        return !!path && this.blocked.has(path.toLowerCase());
    }

    async refresh() {
        try {
            const rows = await ps.run(`Get-NetFirewallRule -Group ${psQuote(GROUP)} -ErrorAction SilentlyContinue | Get-NetFirewallApplicationFilter | Select-Object -ExpandProperty Program`, 60000);
            this.blocked = new Set(rows.filter((p) => typeof p === 'string').map((p) => p.toLowerCase()));
        } catch {
            this.blocked = new Set();
        }
    }

    // Bloqueia entrada e saída do executável no Firewall do Windows
    async block(path, name) {
        const display = `NVI Block - ${name || path}`;
        await ps.run(`
            New-NetFirewallRule -DisplayName ${psQuote(display + ' (out)')} -Group ${psQuote(GROUP)} -Direction Outbound -Program ${psQuote(path)} -Action Block | Out-Null
            New-NetFirewallRule -DisplayName ${psQuote(display + ' (in)')} -Group ${psQuote(GROUP)} -Direction Inbound -Program ${psQuote(path)} -Action Block | Out-Null
        `, 60000);
        this.blocked.add(path.toLowerCase());
    }

    async unblock(path) {
        await ps.run(`
            Get-NetFirewallRule -Group ${psQuote(GROUP)} -ErrorAction SilentlyContinue |
              Where-Object { ($_ | Get-NetFirewallApplicationFilter).Program -eq ${psQuote(path)} } |
              Remove-NetFirewallRule
        `, 60000);
        this.blocked.delete(path.toLowerCase());
    }
}

export const firewall = new Firewall();
