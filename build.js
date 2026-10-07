import { copyFileSync, mkdirSync, chmodSync } from 'node:fs';
import { execSync } from 'node:child_process';

const isWin = process.platform === 'win32';

const outDir = 'build';
const exe = isWin
  ? `${outDir}/NetworkVirusIdentifier.exe`
  : `${outDir}/network-virus-identifier`;
const run = (cmd) => execSync(cmd, { stdio: 'inherit' });

mkdirSync(outDir, { recursive: true });
mkdirSync('dist', { recursive: true });

console.log('> Generating blob...');
run('node --experimental-sea-config sea-config.json');

console.log('> Copying Node...');
copyFileSync(process.execPath, exe);

if (isWin) {
  console.log('> Applying icon...');
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
} else {
  chmodSync(exe, 0o755);
}

console.log('> Injecting script...');
run(
  `npx postject ${exe} NODE_SEA_BLOB dist/sea-prep.blob ` +
  `--sentinel-fuse NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2`
);

console.log(`\nDone: ${exe}`);