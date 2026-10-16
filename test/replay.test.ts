import { test } from 'node:test';
import assert from 'node:assert/strict';
import { AnalysisService } from '../src/modules/analysis/analysis.service.js';
import { CodeDiffSignal } from '../src/modules/analysis/signals/code-diff.signal.js';
import { InstallScriptSignal } from '../src/modules/analysis/signals/install-script.signal.js';
import { NameCheckSignal } from '../src/modules/analysis/signals/name-check.signal.js';
import { NewDepsSignal } from '../src/modules/analysis/signals/new-deps.signal.js';
import { ProvenanceDropSignal } from '../src/modules/analysis/signals/provenance-drop.signal.js';
import { PublisherChangeSignal } from '../src/modules/analysis/signals/publisher-change.signal.js';
import { ReleaseTimingSignal } from '../src/modules/analysis/signals/release-timing.signal.js';
import { decide } from '../src/modules/analysis/verdict.js';
import { IncidentsService } from '../src/modules/incidents/incidents.service.js';

const analysis = new AnalysisService(
  new ProvenanceDropSignal(),
  new PublisherChangeSignal(),
  new InstallScriptSignal(),
  new NewDepsSignal(),
  new ReleaseTimingSignal(),
  new CodeDiffSignal(),
  new NameCheckSignal(),
);
const incidents = new IncidentsService();

/** The signals each replay must raise: the evidence the demo and README promise. */
const expected: Record<string, string[]> = {
  axios: ['new-deps', 'provenance-drop', 'publisher-change'],
  keyv: ['install-script', 'code-diff'],
  chalk: ['code-diff'],
  nx: ['provenance-drop', 'install-script', 'code-diff'],
  tinycolor: ['install-script', 'code-diff'],
};

for (const [id, signals] of Object.entries(expected)) {
  test(`replay ${id}: BLOCK, raised by ${signals.join(', ')}`, async () => {
    const result = await analysis.analyze(incidents.toContext(id));
    assert.equal(result.verdict, 'BLOCK');
    const raised = new Set(result.findings.map((f) => f.signal));
    for (const s of signals) assert.ok(raised.has(s), `${id} should raise ${s}; got ${[...raised].join(', ')}`);
  });
}

test('keyv is blocked although its provenance is valid', async () => {
  const result = await analysis.analyze(incidents.toContext('keyv'));
  assert.ok(!result.findings.some((f) => f.signal === 'provenance-drop'));
  assert.equal(result.verdict, 'BLOCK');
});

test('verdict thresholds: critical blocks, weights add up', () => {
  const f = (severity: 'warn' | 'high' | 'critical', weight: number) => ({ signal: 's', severity, title: 't', evidence: [], weight });
  assert.equal(decide([]).verdict, 'ALLOW');
  assert.equal(decide([f('warn', 15)]).verdict, 'ALLOW');
  assert.equal(decide([f('warn', 15), f('warn', 15)]).verdict, 'REVIEW');
  assert.equal(decide([f('high', 35), f('high', 35)]).verdict, 'BLOCK');
  assert.equal(decide([f('critical', 70)]).verdict, 'BLOCK');
});
