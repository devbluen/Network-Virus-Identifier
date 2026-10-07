import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import os from 'node:os';

const dir = join(process.env.APPDATA || os.homedir(), 'NetworkVirusIdentifier');
const file = join(dir, 'config.json');

const defaults = { trusted: [] };

function load() {
    try {
        return { ...defaults, ...JSON.parse(readFileSync(file, 'utf8')) };
    } catch {
        return { ...defaults };
    }
}

export const config = load();

export function saveConfig() {
    try {
        mkdirSync(dir, { recursive: true });
        writeFileSync(file, JSON.stringify(config, null, 2));
    } catch (err) {
        console.error('Could not save config:', err.message);
    }
}

export const isTrusted = (path) => !!path && config.trusted.includes(path.toLowerCase());

export function setTrusted(path, value) {
    const key = path.toLowerCase();
    config.trusted = config.trusted.filter((p) => p !== key);
    if (value) config.trusted.push(key);
    saveConfig();
}
