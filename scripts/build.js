// Gera o bundle (dist/bundle.cjs) e, sem --bundle-only, o executável portátil via Node SEA.
//   npm run bundle  -> só o bundle
//   npm run build   -> bundle + build/NetworkVirusIdentifier.exe
import { copyFileSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';
import * as esbuild from 'esbuild';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
const distDir = join(root, 'dist');
const buildDir = join(root, 'build');
const bundleOnly = process.argv.includes('--bundle-only');

const step = (msg) => console.log(`> ${msg}`);

step('Bundling sources...');
mkdirSync(distDir, { recursive: true });
await esbuild.build({
    entryPoints: [join(root, 'src/main.js')],
    outfile: join(distDir, 'bundle.cjs'),
    bundle: true,
    platform: 'node',
    format: 'cjs',
    target: 'node20',
    loader: { '.html': 'text', '.png': 'binary' },
    logLevel: 'warning',
});

if (bundleOnly) process.exit(0);

if (process.platform !== 'win32') {
    console.error('The executable build currently targets Windows only.');
    process.exit(1);
}

const [major] = process.versions.node.split('.').map(Number);
if (major < 20) {
    console.error(`Node 20+ is required to build the executable (current: ${process.version}).`);
    process.exit(1);
}

const blob = join(distDir, 'sea-prep.blob');
const exe = join(buildDir, 'NetworkVirusIdentifier.exe');
const seaConfig = join(distDir, 'sea-config.json');

step('Generating SEA blob...');
writeFileSync(seaConfig, JSON.stringify({
    main: join(distDir, 'bundle.cjs'),
    output: blob,
    disableExperimentalSEAWarning: true,
}, null, 2));
execFileSync(process.execPath, ['--experimental-sea-config', seaConfig], { stdio: 'inherit' });

step('Copying Node runtime...');
mkdirSync(buildDir, { recursive: true });
rmSync(exe, { force: true });
copyFileSync(process.execPath, exe);

step('Applying icon and metadata...');
const { rcedit } = await import('rcedit');
await rcedit(exe, {
    icon: join(root, 'assets/logo.ico'),
    'requested-execution-level': 'requireAdministrator',
    'version-string': {
        ProductName: 'Network Virus Identifier',
        FileDescription: 'Network Virus Identifier',
        CompanyName: 'devbluen',
        LegalCopyright: 'devbluen',
        OriginalFilename: 'NetworkVirusIdentifier.exe',
    },
    'file-version': pkg.version,
    'product-version': pkg.version,
});

step('Injecting application...');
// Chama o postject pela API em vez de "npx", que falha quando o caminho tem espaços ou sem rede
const require = createRequire(import.meta.url);
const { inject } = require('postject');
await inject(exe, 'NODE_SEA_BLOB', readFileSync(blob), {
    sentinelFuse: 'NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2',
});

step('Hiding console window...');
// Troca o subsistema do PE de CONSOLE (3) para WINDOWS_GUI (2): o Windows deixa de abrir
// a janela preta do console ao executar. O campo fica no offset 68 do Optional Header.
const image = readFileSync(exe);
const peOffset = image.readUInt32LE(0x3c);
if (image.toString('ascii', peOffset, peOffset + 4) !== 'PE\0\0') throw new Error('Invalid PE header');
const subsystemOffset = peOffset + 24 + 68;
image.writeUInt16LE(2, subsystemOffset);
writeFileSync(exe, image);

console.log(`\nDone: ${exe}`);
