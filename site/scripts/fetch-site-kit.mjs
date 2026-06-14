// Fetch @weft/site-kit from the weft hub repo into ./vendor/site-kit/.
//
// The shared kit lives in a SUBDIRECTORY (packages/site-kit) of a DIFFERENT
// repo (foundryside-dev/weft). npm cannot install a git subdirectory as a
// `file:` dep directly, so this sparse-fetches just that subtree and copies it
// into vendor/site-kit/, which package.json then references as
// "@weft/site-kit": "file:./vendor/site-kit". This is the sanctioned
// realization of the "git subdirectory dependency" decision (IA §1.3, §6):
// not a published registry package, not a submodule, not a hand-vendored static
// copy — a regenerated, never-committed vendor tree refreshed on every build.
//
// Runs before `npm install` (the preinstall hook) so the file: target exists
// when the install resolves it; the Pages workflow runs it explicitly too.
import { cp, mkdir, rm } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { tmpdir } from 'node:os';

const here = dirname(fileURLToPath(import.meta.url));
const siteRoot = join(here, '..');

const REPO = process.env.WEFT_SITE_KIT_REPO || 'https://github.com/foundryside-dev/weft.git';
const REF = process.env.WEFT_SITE_KIT_REF || 'main';
const SUBDIR = 'packages/site-kit';

const dest = join(siteRoot, 'vendor', 'site-kit');

// Escape hatch for local builds: if a sibling weft checkout is present, vendor
// from it directly (no network). Lets the site build offline next to the hub.
const localKit = join(siteRoot, '..', '..', 'weft', 'packages', 'site-kit');

function run(cmd, args, opts) {
  execFileSync(cmd, args, { stdio: 'inherit', ...opts });
}

async function vendorFrom(srcDir, label) {
  if (!existsSync(join(srcDir, 'package.json'))) {
    throw new Error(`[fetch-site-kit] ${label}: no package.json at ${srcDir}`);
  }
  await rm(dest, { recursive: true, force: true });
  await mkdir(dirname(dest), { recursive: true });
  await cp(srcDir, dest, {
    recursive: true,
    filter: (p) => !p.includes(`${join(srcDir, 'node_modules')}`),
  });
  console.log(`[fetch-site-kit] vendored @weft/site-kit from ${label} -> ${dest}`);
}

async function main() {
  if (process.env.WEFT_SITE_KIT_LOCAL === '1' || (existsSync(localKit) && process.env.WEFT_SITE_KIT_REMOTE !== '1')) {
    if (existsSync(localKit)) {
      await vendorFrom(localKit, `local checkout (${localKit})`);
      return;
    }
  }

  const tmp = await mkdir(join(tmpdir(), `weft-site-kit-${Date.now()}`), { recursive: true }).then(
    (d) => d || join(tmpdir(), `weft-site-kit-${Date.now()}`),
  );
  const clonePath = join(tmpdir(), `weft-site-kit-${process.pid}-${Date.now()}`);
  try {
    run('git', ['clone', '--depth', '1', '--filter=blob:none', '--sparse', '--branch', REF, REPO, clonePath]);
    run('git', ['sparse-checkout', 'set', SUBDIR], { cwd: clonePath });
    await vendorFrom(join(clonePath, SUBDIR), `${REPO}#${REF}:${SUBDIR}`);
  } finally {
    await rm(clonePath, { recursive: true, force: true });
    await rm(tmp, { recursive: true, force: true });
  }
}

main().catch((err) => {
  console.error(err.message || err);
  process.exit(1);
});
