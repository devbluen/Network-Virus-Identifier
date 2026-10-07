import net from 'node:net';

const ipv4ToInt = (ip) => ip.split('.').reduce((acc, octet) => (acc << 8) + parseInt(octet, 10), 0) >>> 0;

const inRange = (ip, base, bits) => {
    const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
    return (ipv4ToInt(ip) & mask) === (ipv4ToInt(base) & mask);
};

const PRIVATE_V4 = [
    ['10.0.0.0', 8], ['172.16.0.0', 12], ['192.168.0.0', 16],
    ['169.254.0.0', 16], ['100.64.0.0', 10],
];

// 'local' = a própria máquina, 'lan' = rede interna, 'internet' = fora da rede
export function ipScope(ip) {
    if (!ip) return 'none';
    if (ip.startsWith('::ffff:')) ip = ip.slice(7);

    if (net.isIPv4(ip)) {
        if (ip === '0.0.0.0') return 'none';
        if (inRange(ip, '127.0.0.0', 8)) return 'local';
        if (PRIVATE_V4.some(([base, bits]) => inRange(ip, base, bits))) return 'lan';
        if (inRange(ip, '224.0.0.0', 4) || ip === '255.255.255.255') return 'lan';
        return 'internet';
    }

    const lower = ip.toLowerCase();
    if (lower === '::') return 'none';
    if (lower === '::1') return 'local';
    if (/^fe[89ab]/.test(lower) || /^f[cd]/.test(lower) || lower.startsWith('ff')) return 'lan';
    return 'internet';
}

export const isWildcard = (ip) => ip === '0.0.0.0' || ip === '::';
