import { copyFileSync, mkdirSync, chmodSync } from 'node:fs';
import { spawn } from 'node:child_process';
import { build } from 'esbuild';

const c = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  cyan: '\x1b[36m',
  gray: '\x1b[90m',
};

const VERBOSE = process.argv.includes('--verbose');
const TTY = Boolean(process.stdout.isTTY);
const isWin = process.platform === 'win32';

const outDir = 'build';
const exe = isWin
  ? `${outDir}/NetworkVirusIdentifier.exe`
  : `${outDir}/network-virus-identifier`;

const run = (cmd) =>
  new Promise((resolve, reject) => {
    const child = spawn(cmd, { shell: true, stdio: ['ignore', 'pipe', 'pipe'] });
    let saida = '';
    child.stdout.on('data', (d) => (saida += d));
    child.stderr.on('data', (d) => (saida += d));
    child.on('error', reject);
    child.on('close', (code) => {
      if (code === 0) return resolve(saida);
      const err = new Error(`Comando falhou (código ${code}): ${cmd}`);
      err.output = saida;
      reject(err);
    });
  });

const steps = [
  {
    label: 'Bundling script',
    run: async () => {
      mkdirSync(outDir, { recursive: true });
      mkdirSync('dist', { recursive: true });
      await build({
        entryPoints: ['index.js'],
        bundle: true,
        platform: 'node',
        format: 'cjs',
        outfile: 'dist/bundle.cjs',
        logLevel: 'silent',
      });
    },
  },
  {
    label: 'Generating blob',
    run: () => run('node --no-warnings --experimental-sea-config sea-config.json'),
  },
  {
    label: 'Copying Node',
    run: async () => {
      copyFileSync(process.execPath, exe);
      if (!isWin) chmodSync(exe, 0o755);
    },
  },
  ...(isWin
    ? [
        {
          label: 'Applying icon',
          run: async () => {
            const { rcedit } = await import('rcedit');
            await rcedit(exe, {
              icon: 'assets/logo.ico',
              'requested-execution-level': 'requireAdministrator',
              'version-string': {
                ProductName: 'Network Virus Identifier Monitor',
                FileDescription: 'Network Virus Identifier',
                CompanyName: 'devbluen',
                LegalCopyright: 'devbluen',
                OriginalFilename: 'NetworkVirusIdentifier.exe',
              },
              'file-version': '1.0.0',
              'product-version': '1.0.0',
            });
          },
        },
      ]
    : []),
  {
    label: 'Injecting script',
    run: () =>
      run(
        `npx postject ${exe} NODE_SEA_BLOB dist/sea-prep.blob ` +
          `--sentinel-fuse NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2`
      ),
  },
];


const LARGURA = 30;
const SPINNER = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];
const total = steps.length;
let feitos = 0;
let atual = '';
let quadro = 0;
let timer = null;

const barra = () => {
  const cheios = Math.round((feitos / total) * LARGURA);
  let blocos = '';
  for (let i = 0; i < LARGURA; i++) {
    if (i < cheios) {
      const p = i / LARGURA;
      blocos += (p < 0.34 ? c.red : p < 0.67 ? c.yellow : c.green) + '█';
    } else {
      blocos += c.gray + '░';
    }
  }
  const pct = Math.round((feitos / total) * 100);
  return `${blocos}${c.reset} ${c.bold}${String(pct).padStart(3)}%${c.reset} ${c.gray}(${feitos}/${total})${c.reset}`;
};

const limparLinha = () => TTY && process.stdout.write('\r\x1b[2K');

const desenhar = () => {
  if (!TTY) return;
  const giro = `${c.cyan}${SPINNER[quadro++ % SPINNER.length]}${c.reset}`;
  const texto = atual ? ` ${giro} ${atual}` : '';
  process.stdout.write(`\r\x1b[2K${barra()}${texto}`);
};

const log = (texto) => {
  limparLinha();
  console.log(texto);
  desenhar();
};

const iniciar = () => {
  if (!TTY) return;
  process.stdout.write('\x1b[?25l');
  timer = setInterval(desenhar, 80);
};

const parar = () => {
  if (timer) clearInterval(timer);
  timer = null;
  if (TTY) process.stdout.write('\x1b[?25h');
};

process.on('SIGINT', () => {
  parar();
  process.exit(130);
});

const segundos = (t0) => ((Date.now() - t0) / 1000).toFixed(1) + 's';

iniciar();
try {
  for (const etapa of steps) {
    atual = `${etapa.label}...`;
    desenhar();
    const t0 = Date.now();

    let saida;
    try {
      saida = await etapa.run();
    } catch (err) {
      err.etapa = etapa.label;
      throw err;
    }

    feitos++;
    atual = '';
    log(`${c.green}✔${c.reset} ${etapa.label} ${c.gray}(${segundos(t0)})${c.reset}`);
    if (VERBOSE && typeof saida === 'string' && saida.trim()) {
      log(`${c.gray}${saida.trim().replace(/^/gm, '    ')}${c.reset}`);
    }
  }

  parar();
  limparLinha();
  console.log(barra());
  console.log(`\n${c.bold}${c.green}✔ Done: ${exe}${c.reset}`);
} catch (err) {
  parar();
  limparLinha();
  console.error(`${c.red}✖${c.reset} ${err.etapa ?? 'Build'} ${c.red}falhou${c.reset}`);
  if (err.output && err.output.trim()) console.error(`\n${err.output.trim()}`);
  console.error(`\n${c.bold}${c.red}✖ Build failed: ${err.message}${c.reset}`);
  process.exit(1);
}