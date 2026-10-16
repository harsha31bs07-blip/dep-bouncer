import { Injectable } from '@nitrostack/core';
import { createHash } from 'node:crypto';
import { isMinified, scanSource, shannonEntropy, type PatternHit } from '../code-patterns.js';
import { SEVERITY_WEIGHT, type AnalysisContext, type Finding, type Severity, type Signal } from '../signal.js';

const MB = 1024 * 1024;
const INSTALL_EVENTS = new Set(['preinstall', 'install', 'postinstall', 'prepublish', 'preprepare', 'prepare', 'postprepare']);
const LOWER: Record<Severity, Severity> = { critical: 'high', high: 'warn', warn: 'info', info: 'info' };

function scriptReferences(script: string, path: string): boolean {
  const normalize = (value: string) => value.replace(/\\/g, '/').replace(/^(?:\.\/)+/, '');
  return (script.match(/"[^"]*"|'[^']*'|[^\s;&|<>]+/g) ?? []).some(token => {
    const value = token.replace(/^['"]|['"]$/g, '');
    return normalize(value) === path || (value.includes('=') && normalize(value.slice(value.indexOf('=') + 1)) === path);
  });
}

@Injectable()
export class CodeDiffSignal implements Signal {
  readonly id = 'code-diff';

  async evaluate(ctx: AnalysisContext): Promise<Finding[]> {
    try {
      const previous = ctx.baseline[0];
      const target = await ctx.loadFiles(ctx.target.version);
      const baseline = previous ? await ctx.loadFiles(previous.version) : new Map<string, Uint8Array>();
      const hash = (bytes: Uint8Array) => createHash('sha256').update(bytes).digest('hex');
      const diff: { path: string; kind: 'added' | 'changed' | 'removed' }[] = [];
      for (const [path, bytes] of target) {
        const old = baseline.get(path);
        if (!old) diff.push({ path, kind: 'added' });
        else if (hash(bytes) !== hash(old)) diff.push({ path, kind: 'changed' });
      }
      for (const path of baseline.keys()) if (!target.has(path)) diff.push({ path, kind: 'removed' });

      const scripts = Object.entries(ctx.target.scripts ?? {}).filter(([event]) => INSTALL_EVENTS.has(event));
      const newScripts = scripts.filter(([event, command]) => previous?.scripts?.[event] !== command);
      const findings = new Map<PatternHit['category'], Finding>();
      const report = (path: string, hit: PatternHit, severity: Severity) => {
        const effective = previous ? severity : LOWER[severity];
        const evidence = `${path}:${hit.line} [${hit.id}] ${hit.snippet.slice(0, 120)}`;
        const current = findings.get(hit.category);
        if (!current) {
          findings.set(hit.category, { signal: this.id, severity: effective,
            title: `Suspicious ${hit.category} in release code${previous ? '' : ' (no previous release to compare)'}`,
            evidence: [evidence], weight: SEVERITY_WEIGHT[effective] });
        } else {
          if (SEVERITY_WEIGHT[effective] > current.weight) {
            current.severity = effective;
            current.weight = SEVERITY_WEIGHT[effective];
            // Keep the evidence supporting the highest severity visible even after the cap.
            current.evidence.unshift(evidence);
            current.evidence = current.evidence.slice(0, 5);
          } else if (current.evidence.length < 5 && !current.evidence.includes(evidence)) current.evidence.push(evidence);
        }
      };

      for (const { path, kind } of diff) {
        if (kind === 'removed') continue;
        const bytes = target.get(path)!;
        const js = /\.(?:js|cjs|mjs)$/i.test(path);
        const referenced = scripts.some(([, command]) => scriptReferences(command, path));
        const newInstall = newScripts.some(([, command]) => scriptReferences(command, path));
        if (bytes.byteLength > 8 * MB) {
          report(path, { id: 'oversized-file', category: 'obfuscation', severity: 'warn',
            line: 1, snippet: `${bytes.byteLength} bytes; exceeds 8 MB source scanning limit` }, 'warn');
          continue;
        }
        // Inspect paths for auto-run configuration even when the content is not JavaScript.
        let hits = scanSource(path, path).filter(hit => hit.id === 'agent-autorun' || hit.id === 'native-install');
        if (js || referenced) hits = hits.concat(scanSource(path, Buffer.from(bytes).toString('utf8')));
        if (kind === 'added' && bytes.byteLength > 300 * 1024) {
          // Latin-1 preserves binary byte diversity, including payloads disguised as JS.
          const entropy = shannonEntropy(Buffer.from(bytes).toString('latin1'));
          if (entropy > 5.5) hits.push({ id: 'packed-payload', category: 'obfuscation', severity: 'high',
            line: 1, snippet: `encrypted/packed payload: ${bytes.byteLength} bytes, entropy ${entropy.toFixed(2)} bits/char` });
        }
        hits = hits.filter((hit, index) => hits.findIndex(other => other.id === hit.id) === index)
          .filter(hit => kind === 'added' || (hit.id !== 'native-install' && hit.id !== 'packed-payload'));
        if (kind === 'added' && js && bytes.byteLength > 500 * 1024
          && isMinified(Buffer.from(bytes).toString('utf8'))) {
          hits.push({ id: 'large-minified-file', category: 'obfuscation', severity: 'high',
            line: 1, snippet: `New minified JavaScript file: ${bytes.byteLength} bytes` });
        }
        const walletObfuscation = hits.some(hit => hit.category === 'wallet')
          && hits.some(hit => hit.category === 'obfuscation');
        for (const hit of hits) {
          let severity = hit.severity;
          if (['ai-agent-abuse', 'exfil', 'credentials'].includes(hit.category)) severity = 'high';
          if (newInstall || (walletObfuscation && ['wallet', 'obfuscation'].includes(hit.category))) severity = 'critical';
          report(path, hit, severity);
        }
      }
      return [...findings.values()];
    } catch (error) {
      const reason = (error instanceof Error ? error.message : String(error)).replace(/[\r\n]/g, ' ').slice(0, 200);
      return [{ signal: this.id, severity: 'info', title: `code comparison unavailable: ${reason}`, evidence: [],
        weight: SEVERITY_WEIGHT.info }];
    }
  }
}
