// The release check for the public KMS web releases repository (6B A3, A6, A9).
// GitHub runs it from the accepted base branch (pull_request_target) and it
// reads the pull request's files only as git objects: nothing from the pull
// request is ever run, so a release cannot change its own check. --bootstrap
// copies this file into the release repository as .github/release-check/check.cjs;
// --release and --check-release run that accepted copy locally too.
//   node check.cjs --git-dir <dir> --base <commit> --head <commit>
//   node check.cjs --git-dir <dir> --state <commit>
// Node built-ins only. No secrets, no network, no token.
'use strict';
const {spawnSync} = require('child_process');
const crypto = require('crypto');

const BRANCH = 'main';
const VERSION_PATTERN = /^\d+\.\d+\.\d+(-[a-z0-9.]{1,24})?$/;
// Files in a version folder: the page, its manifest, screens and pinned vendor files.
const FOLDER_FILE = /^(index\.html|manifest\.json|screens\/[A-Za-z][A-Za-z0-9]{0,63}\.html|vendor\/[a-z0-9][a-z0-9.-]{0,63}\.js)$/;
// Vendored files are checked by their exact hash instead of the content scan.
const VENDOR_PINS = Object.freeze({'vendor/heic-to.js': 'c189220a7a1e87559758a48ab4700e55629fb23a4cb57489e1e8970be1b9d018'});
const ROOT_FILES = ['public/404.html', 'public/_headers', 'public/index.html', 'public/policy.json'];
// No pull request may change these. Changing the check or the hosting settings
// is a deliberate owner act outside the ruleset, recorded in the LOG.
const LOCKED = path => path.startsWith('.github/') || path === 'wrangler.jsonc';
const WITHDRAWN_CODES = ['defect', 'security'];
const MANIFEST_KEYS = ['schema', 'version', 'release', 'source', 'screens', 'files', 'hash'];
const ENTRY_KEYS = ['version', 'release', 'source', 'tree', 'hash'];
// The outgoing-content scan (A6). Patterns are assembled so this file never
// matches its own scan. A scan cannot prove that no secret exists; it is one layer.
const ID = '[A-Za-z0-9_-]';
const SCAN = Object.freeze([
  {name: 'a real Apps Script deployment address', pattern: new RegExp('/mac' + 'ros/s/' + ID + '{20,}')},
  {name: 'an Apps Script deployment ID', pattern: new RegExp('AK' + 'fy' + ID + '{10,}')},
  {name: 'a Google file or script ID', pattern: new RegExp('(?<!' + ID + ')1' + ID + '{32,80}(?!' + ID + ')', 'g'), test: match => /[A-Z]/.test(match) && /[a-z]/.test(match)},
  {name: 'an e-mail address', pattern: /[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}/},
  {name: 'the word pep' + 'per', pattern: new RegExp('pep' + 'per', 'i')},
  {name: 'a credential', pattern: new RegExp(['client' + '_secret', 'GOC' + 'SPX-', 'ya' + '29\\.', 'gh' + 'p_', 'github' + '_pat_', 'PRIVATE' + ' KEY', 'AI' + 'za' + ID + '{35}', 'refresh' + '_token'].join('|'))}
]);

const sha256 = data => crypto.createHash('sha256').update(data).digest('hex');
const sameJson = (a, b) => JSON.stringify(a) === JSON.stringify(b);
const isObject = value => !!value && typeof value === 'object' && !Array.isArray(value);
const keysAre = (value, keys) => isObject(value) && sameJson(Object.keys(value), keys);

/** Runs git on a repository without a shell; returns a Buffer or a string. */
function git(gitDir, args, binary) {
  const result = spawnSync('git', ['--git-dir', gitDir].concat(args), {maxBuffer: 512 * 1024 * 1024, encoding: binary ? 'buffer' : 'utf8'});
  if (result.error) throw result.error;
  if (result.status !== 0) throw Error('git ' + args[0] + ' failed: ' + String(result.stderr).trim());
  return result.stdout;
}

/** A commit's files as {path: {mode, type, id}}, plus a reader for their bytes. */
function snapshot(gitDir, commit) {
  const files = {};
  git(gitDir, ['ls-tree', '-r', '-z', '--full-tree', commit]).split('\0').filter(Boolean).forEach(line => {
    const tab = line.indexOf('\t'), [mode, type, id] = line.slice(0, tab).split(' ');
    files[line.slice(tab + 1)] = {mode, type, id};
  });
  let blobs = null;
  // Every file's bytes in one git call, read on first use.
  const load = () => {
    const ids = [...new Set(Object.values(files).filter(f => f.type === 'blob').map(f => f.id))];
    const result = spawnSync('git', ['--git-dir', gitDir, 'cat-file', '--batch'], {input: ids.join('\n') + '\n', maxBuffer: 512 * 1024 * 1024});
    if (result.error || result.status !== 0) throw Error('git cat-file failed: ' + String(result.stderr || result.error).trim());
    const out = result.stdout, found = {};
    let at = 0;
    ids.forEach(() => {
      const end = out.indexOf(10, at), [id, type, size] = out.slice(at, end).toString('latin1').split(' ');
      if (type !== 'blob') throw Error('git object ' + id + ' is not a file.');
      found[id] = out.subarray(end + 1, end + 1 + Number(size));
      at = end + 2 + Number(size);
    });
    return found;
  };
  return {
    commit, files,
    read: path => (blobs || (blobs = load()))[files[path].id],
    tree: path => git(gitDir, ['rev-parse', commit + ':' + path]).trim()
  };
}

/** Each scan rule a text breaks, by name (rules in extra add known IDs, A6). */
function scanText(text, extra) {
  const found = [];
  SCAN.concat(extra || []).forEach(rule => {
    if (rule.text !== undefined ? text.includes(rule.text) : rule.test ? (text.match(rule.pattern) || []).some(rule.test) : rule.pattern.test(text)) found.push(rule.name);
  });
  return found;
}

function parseJson(snap, path, errors) {
  try { return JSON.parse(snap.read(path).toString('utf8')); } catch (e) { errors.push(path + ' is not readable JSON.'); return null; }
}

/** The published list built into the root page (6B D2). */
function publishedList(snap, errors) {
  const text = snap.read('public/index.html').toString('utf8'), lines = text.match(/^ *const PUBLISHED = (.*);\r?$/mg) || [];
  if (lines.length !== 1) { errors.push('public/index.html must hold one published list.'); return null; }
  try { return JSON.parse(lines[0].replace(/^ *const PUBLISHED = /, '').replace(/;\r?$/, '')); } catch (e) { errors.push('public/index.html has an unreadable published list.'); return null; }
}

function headerRules(text) {
  const rules = {};
  let current = null;
  text.split(/\r?\n/).forEach(line => {
    if (!line.trim() || /^\s*#/.test(line)) return;
    if (!/^\s/.test(line)) { current = rules[line.trim()] = rules[line.trim()] || {}; return; }
    const match = line.match(/^\s+([A-Za-z0-9-]+):\s*(.*)$/);
    if (!match || !current) throw Error('unreadable line');
    current[match[1]] = match[2];
  });
  return rules;
}

/**
 * Checks that one commit is a consistent release site: allowed paths only,
 * plain files, the registry, every version folder against its manifest and
 * registry entry, the root's list, the withdrawal policy, the headers and the
 * scan. Returns {errors, registry}.
 */
function checkState(snap, extraScan) {
  const errors = [], paths = Object.keys(snap.files).sort();
  paths.forEach(path => {
    const file = snap.files[path];
    if (file.type !== 'blob' || file.mode !== '100644') errors.push(path + ' must be a plain file (no links, submodules or executables).');
    const folder = path.match(/^public\/ui\/([^/]+)\/(.+)$/);
    if (folder) { if (!VERSION_PATTERN.test(folder[1]) || !FOLDER_FILE.test(folder[2])) errors.push(path + ' is not an allowed release file.'); }
    else if (!LOCKED(path) && path !== 'registry.json' && !ROOT_FILES.includes(path)) errors.push(path + ' is not an allowed file in the release repository.');
  });
  ROOT_FILES.concat(['registry.json', 'wrangler.jsonc', '.github/release-check/check.cjs', '.github/workflows/release-check.yml']).forEach(path => {
    if (!snap.files[path]) errors.push(path + ' is missing.');
  });
  if (errors.length) return {errors, registry: null};

  // The registry: one fixed entry per published version, releases rising.
  const registry = parseJson(snap, 'registry.json', errors);
  if (!registry) return {errors, registry: null};
  if (!keysAre(registry, ['schema', 'versions']) || registry.schema !== 1 || !Array.isArray(registry.versions)) return {errors: errors.concat('registry.json must be {schema:1, versions:[...]}.'), registry: null};
  let top = 0;
  registry.versions.forEach((entry, i) => {
    const name = 'registry.json entry ' + (i + 1);
    if (!keysAre(entry, ENTRY_KEYS)) { errors.push(name + ' must have exactly ' + ENTRY_KEYS.join(', ') + '.'); return; }
    if (typeof entry.version !== 'string' || !VERSION_PATTERN.test(entry.version)) errors.push(name + ' has a version that cannot be a folder name.');
    if (!Number.isSafeInteger(entry.release) || entry.release <= top) errors.push(name + ' must have a whole-number release above every earlier one.');
    else top = entry.release;
    if (!/^[0-9a-f]{40}$/.test(entry.source)) errors.push(name + ' must name its source commit.');
    if (!/^[0-9a-f]{40}([0-9a-f]{24})?$/.test(entry.tree)) errors.push(name + ' must name its folder\'s tree.');
    if (!/^[0-9a-f]{64}$/.test(entry.hash)) errors.push(name + ' must carry its manifest hash.');
    if (registry.versions.findIndex(other => other.version === entry.version) !== i) errors.push(name + ' repeats version ' + entry.version + '.');
  });
  if (errors.length) return {errors, registry: null};

  // Version folders: exactly the registry's, each unchanged since registration.
  const folders = [...new Set(paths.filter(p => p.startsWith('public/ui/')).map(p => p.split('/')[2]))].sort();
  if (!sameJson(folders, registry.versions.map(e => e.version).sort())) errors.push('The folders under public/ui must be exactly the versions in registry.json.');
  registry.versions.forEach(entry => {
    const base = 'public/ui/' + entry.version + '/', name = 'Version ' + entry.version;
    const inside = paths.filter(p => p.startsWith(base)).map(p => p.slice(base.length)).sort();
    if (!inside.length) return;
    if (snap.tree(base.slice(0, -1)) !== entry.tree) errors.push(name + ' differs from the folder registered for it.');
    if (!inside.includes('manifest.json') || !inside.includes('index.html')) { errors.push(name + ' needs index.html and manifest.json.'); return; }
    const manifest = parseJson(snap, base + 'manifest.json', errors);
    if (!manifest) return;
    if (!keysAre(manifest, MANIFEST_KEYS) || manifest.schema !== 1 || !isObject(manifest.files) || !Array.isArray(manifest.screens)) { errors.push(name + ' has a manifest in the wrong form.'); return; }
    if (manifest.version !== entry.version || manifest.release !== entry.release || manifest.source !== entry.source) errors.push(name + '\'s manifest does not match its registry entry.');
    const listed = Object.keys(manifest.files), actual = inside.filter(p => p !== 'manifest.json');
    if (!sameJson(listed, actual)) errors.push(name + '\'s manifest does not list exactly its files.');
    actual.forEach(p => { if (manifest.files[p] !== sha256(snap.read(base + p))) errors.push(name + ': ' + p + ' does not match its manifest.'); });
    const hash = sha256(JSON.stringify(Object.entries(manifest.files)));
    if (manifest.hash !== hash || entry.hash !== hash) errors.push(name + '\'s manifest hash does not match its files.');
    manifest.screens.forEach(screen => { if (typeof screen !== 'string' || !actual.includes('screens/' + screen + '.html')) errors.push(name + ' lists a screen it does not have.'); });
    actual.filter(p => p.startsWith('vendor/')).forEach(p => { if (VENDOR_PINS[p] !== manifest.files[p]) errors.push(name + ': ' + p + ' is not a pinned vendor file.'); });
  });

  // The root page lists exactly the registered versions.
  const published = publishedList(snap, errors);
  if (published && !sameJson(published, registry.versions.map(e => ({version: e.version, release: e.release})))) errors.push('public/index.html must list exactly the versions in registry.json, in order.');

  // The withdrawal policy (A1): fixed codes for registered versions only.
  const policy = parseJson(snap, 'public/policy.json', errors);
  if (policy) {
    if (!keysAre(policy, ['schema', 'updated', 'withdrawn']) || policy.schema !== 1 || typeof policy.updated !== 'string' || policy.updated.length > 40 || !isObject(policy.withdrawn)) errors.push('public/policy.json must be {schema:1, updated, withdrawn:{}}.');
    else Object.entries(policy.withdrawn).forEach(([version, code]) => {
      if (!registry.versions.some(e => e.version === version)) errors.push('public/policy.json withdraws ' + JSON.stringify(version).slice(0, 40) + ', which is not published.');
      if (!WITHDRAWN_CODES.includes(code)) errors.push('public/policy.json may only use the codes ' + WITHDRAWN_CODES.join(' and ') + '.');
    });
  }

  // Headers (D8, A1): the policy everywhere, no caching for the root and policy.
  try {
    const rules = headerRules(snap.read('public/_headers').toString('utf8')), csp = (rules['/*'] || {})['Content-Security-Policy'] || '';
    if (!/(^|; )default-src 'none'(;|$)/.test(csp) || !/(^|; )frame-ancestors 'self'(;|$)/.test(csp)) errors.push('public/_headers must keep the content security policy on every path.');
    if ((rules['/policy.json'] || {})['Cache-Control'] !== 'no-store') errors.push('public/_headers must keep policy.json uncached.');
    if ((rules['/'] || {})['Cache-Control'] !== 'no-cache' || (rules['/index.html'] || {})['Cache-Control'] !== 'no-cache') errors.push('public/_headers must keep the root page revalidated.');
  } catch (e) { errors.push('public/_headers is not readable.'); }

  // The scan (A6) on every file except pinned vendor files.
  paths.forEach(path => {
    const folder = path.match(/^public\/ui\/[^/]+\/(vendor\/.+)$/);
    if (folder && VENDOR_PINS[folder[1]] === sha256(snap.read(path))) return;
    scanText(snap.read(path).toString('utf8'), extraScan).forEach(found => errors.push(path + ' contains ' + found + '.'));
  });
  return {errors, registry};
}

/**
 * Checks a pull request's head against the accepted base (A3): the base is
 * valid, the head is up to date with it, nothing locked changes, existing
 * versions and registry entries are untouched, at most one version is added
 * with a higher release, and adding a version leaves the withdrawal policy alone.
 */
function checkChange(base, head, extraScan) {
  const before = checkState(base, extraScan);
  if (before.errors.length) return before.errors.map(e => 'The accepted base is not valid: ' + e);
  const errors = [];
  const paths = [...new Set(Object.keys(base.files).concat(Object.keys(head.files)))].sort();
  paths.filter(LOCKED).forEach(path => {
    const a = base.files[path], b = head.files[path];
    if (!a || !b || a.id !== b.id || a.mode !== b.mode) errors.push(path + ' cannot be changed by a pull request.');
  });
  const after = checkState(head, extraScan);
  errors.push(...after.errors);
  if (!after.registry) return errors;
  const old = before.registry.versions, now = after.registry.versions;
  if (now.length < old.length || !sameJson(now.slice(0, old.length), old)) errors.push('Existing registry.json entries cannot change or be removed.');
  old.forEach(entry => {
    const tree = 'public/ui/' + entry.version + '/';
    paths.filter(p => p.startsWith(tree)).forEach(p => {
      const a = base.files[p], b = head.files[p];
      if (!a || !b || a.id !== b.id) errors.push(p + ' is in a published version and cannot change.');
    });
  });
  const added = now.slice(old.length);
  if (added.length > 1) errors.push('Publish one version per pull request.');
  if (added.length && (!base.files['public/policy.json'] || !head.files['public/policy.json'] || base.files['public/policy.json'].id !== head.files['public/policy.json'].id)) {
    errors.push('A pull request that publishes a version must keep public/policy.json unchanged; change withdrawals on their own.');
  }
  return errors;
}

function report(title, errors) {
  if (!errors.length) { console.log(title + ': passed.'); return true; }
  console.log(title + ': FAILED');
  errors.forEach(e => console.log(' - ' + e));
  return false;
}

function main(argv) {
  const args = {};
  for (let i = 0; i < argv.length; i += 2) args[argv[i].replace(/^--/, '')] = argv[i + 1];
  if (!args['git-dir'] || !(args.state || (args.base && args.head))) throw Error('Usage: check.cjs --git-dir <dir> (--state <commit> | --base <commit> --head <commit>)');
  const dir = args['git-dir'];
  const commit = name => {
    if (!/^[0-9a-f]{40}([0-9a-f]{24})?$/.test(name)) throw Error('Commits are given by their full ID.');
    return git(dir, ['rev-parse', '--verify', name + '^{commit}']).trim();
  };
  if (args.state) return report('Release state ' + args.state.slice(0, 12), checkState(snapshot(dir, commit(args.state))).errors);
  const base = commit(args.base), head = commit(args.head);
  const upToDate = spawnSync('git', ['--git-dir', dir, 'merge-base', '--is-ancestor', base, head]).status === 0;
  if (!upToDate) return report('Release check', ['The pull request is not up to date with ' + BRANCH + '. Update the branch; the check runs again.']);
  return report('Release check ' + base.slice(0, 12) + '..' + head.slice(0, 12), checkChange(snapshot(dir, base), snapshot(dir, head)));
}

module.exports = {checkState, checkChange, scanText, snapshot, git, VERSION_PATTERN, VENDOR_PINS, FOLDER_FILE, ROOT_FILES, LOCKED, SCAN};
if (require.main === module) {
  try { process.exitCode = main(process.argv.slice(2)) ? 0 : 1; } catch (e) { console.log('Release check could not run: ' + e.message); process.exitCode = 1; }
}
