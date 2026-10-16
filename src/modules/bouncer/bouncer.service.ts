import { Injectable } from '@nitrostack/core';
import { AnalysisService } from '../analysis/analysis.service.js';
import type { AnalysisContext, FileMap, Finding, VersionManifest } from '../analysis/signal.js';
import { finding, formatAge, hoursBetween, REPLAY_NOW } from '../analysis/signals/finding.js';
import { decide, type Verdict } from '../analysis/verdict.js';
import { IncidentsService } from '../incidents/incidents.service.js';
import { NpmRegistryService, type Packument } from '../registry/npm-registry.service.js';
import { OsvService, type AdvisoryLookup } from '../registry/osv.service.js';
import { compare, isPrerelease, parse, satisfies } from '../registry/semver.js';
import { TarballService } from '../registry/tarball.service.js';
import { TtlCache } from '../registry/ttl-cache.js';

const BASELINE_SIZE = 10;
const SAFE_VERSION_ATTEMPTS = 4;

/** What the free, advisory-based tools would say about the same release right now. */
export interface OtherTools {
  osv: string;
  npmAudit: string;
  cooldown: string;
}

export interface Report {
  package: string;
  version: string;
  verdict: Verdict;
  score: number;
  summary: string;
  findings: Finding[];
  notes: string[];
  otherTools: OtherTools;
  safeVersion?: { version: string; reason: string };
  publishedAt?: string;
  checks: string[];
  /** Present on replays: what is real and what was reconstructed. */
  replay?: {
    incident: string;
    title: string;
    disclaimer: string;
    real: string[];
    reconstructed: string[];
    firstAdvisory: { id: string; lagHours: number };
    sources: { name: string; url: string }[];
  };
}

export class PackageNotFoundError extends Error {}

/**
 * Turns a package name and version into a verdict: fetches the release and its history from
 * the registry, runs every signal, and adds what other tools would say.
 */
@Injectable({ deps: [NpmRegistryService, TarballService, OsvService, AnalysisService, IncidentsService] })
export class BouncerService {
  private readonly files = new TtlCache<FileMap>(10 * 60_000, 12);

  constructor(
    private readonly registry: NpmRegistryService,
    private readonly tarballs: TarballService,
    private readonly osv: OsvService,
    private readonly analysis: AnalysisService,
    private readonly incidents: IncidentsService,
  ) {}

  /** Vet one release (default: the `latest` dist-tag) before installing it. */
  async checkPackage(name: string, version?: string): Promise<Report> {
    const packument = await this.registry.getPackument(name);
    if (!packument) return this.notFound(name);
    const resolved = this.resolveVersion(packument, version);
    const manifest = packument.versions[resolved];
    if (!manifest) {
      const report = this.removed(packument, resolved, await this.osv.query(name, resolved));
      report.safeVersion = await this.findSafeVersion(packument, `<${resolved}`, resolved);
      return report;
    }

    const ctx = await this.liveContext(packument, manifest);
    const [result, advisories] = await Promise.all([
      this.analysis.analyze(ctx),
      this.osv.query(name, resolved),
    ]);

    const findings = [...result.findings, ...result.notes];
    const malware = advisories.advisories.filter((a) => a.malicious);
    if (malware.length) {
      findings.push(
        finding('known-advisory', 'critical', `Listed as malware in OSV (${malware[0].id})`, malware.map((a) => `${a.id}: ${a.summary ?? ''}`)),
      );
    }
    const verdict = decide(findings);
    const report = this.report(name, resolved, packument.time[resolved], verdict, result.checks, advisories, false);
    if (verdict.verdict !== 'ALLOW') {
      report.safeVersion = await this.findSafeVersion(packument, `<${resolved}`, resolved);
    }
    return report;
  }

  /** Vet a version bump: the target is judged against the history up to it. */
  async checkUpgrade(name: string, from: string, to: string): Promise<Report & { change: string[] }> {
    const report = await this.checkPackage(name, to);
    const packument = await this.registry.getPackument(name);
    const a = packument?.versions[from];
    const b = packument?.versions[to];
    const change: string[] = [];
    if (!a) change.push(`${from} is not on the registry`);
    if (a && b) change.push(...describeChange(a, b));
    if (packument?.time[from] && packument.time[to]) {
      change.push(`${to} was published ${formatAge(Math.abs(hoursBetween(packument.time[from], packument.time[to])))} after ${from}`);
    }
    return { ...report, change };
  }

  /** The newest version in `range` that passes every check. */
  async safeVersion(name: string, range = '*'): Promise<{
    package: string;
    range: string;
    safeVersion?: string;
    verdict?: Verdict;
    skipped: { version: string; verdict: Verdict; reason: string }[];
    note?: string;
  }> {
    const packument = await this.registry.getPackument(name);
    if (!packument) throw new PackageNotFoundError(`${name} does not exist on npm`);
    const skipped: { version: string; verdict: Verdict; reason: string }[] = [];
    const candidates = this.candidates(packument, range);
    for (const v of candidates.slice(0, SAFE_VERSION_ATTEMPTS)) {
      const r = await this.checkLive(packument, v);
      if (r.verdict === 'ALLOW') {
        return { package: name, range, safeVersion: v, verdict: r.verdict, skipped };
      }
      skipped.push({ version: v, verdict: r.verdict, reason: r.findings[0]?.title ?? r.verdict });
    }
    return {
      package: name,
      range,
      skipped,
      note: candidates.length
        ? `No version passed among the newest ${Math.min(candidates.length, SAFE_VERSION_ATTEMPTS)} in range; ask a human.`
        : `No published version matches ${range}.`,
    };
  }

  /** Replays a real hijack on its labelled reconstruction. */
  async replay(id: string): Promise<Report> {
    const incident = this.incidents.get(id);
    const ctx = this.incidents.toContext(id);
    const result = await this.analysis.analyze(ctx);
    const verdict = decide([...result.findings, ...result.notes]);
    const advisories: AdvisoryLookup = { available: true, advisories: [] };
    const report = this.report(
      incident.packageName,
      incident.targetVersion,
      ctx.time[incident.targetVersion],
      verdict,
      result.checks,
      advisories,
      true,
    );
    report.otherTools.osv = `No advisory yet: OSV's first entry (${incident.osvFirstAdvisory.id}) arrived ${incident.osvFirstAdvisory.lagHours} h after publication`;
    report.otherTools.npmAudit = 'found 0 vulnerabilities (npm audit only knows published advisories)';
    report.safeVersion = { version: incident.safeVersion, reason: 'last release before the hijack' };
    report.replay = {
      incident: incident.id,
      title: incident.title,
      disclaimer:
        'Replay on a labelled reconstruction: the malicious version was removed from npm. Last-good release data is real; the bad release is rebuilt from public reports with benign stand-in code.',
      real: incident.real,
      reconstructed: incident.reconstructed,
      firstAdvisory: incident.osvFirstAdvisory,
      sources: incident.sources,
    };
    return report;
  }

  listIncidents() {
    return this.incidents.list();
  }

  private async checkLive(packument: Packument, version: string) {
    const manifest = packument.versions[version];
    return this.analysis.analyze(await this.liveContext(packument, manifest));
  }

  private async liveContext(packument: Packument, target: VersionManifest): Promise<AnalysisContext> {
    return {
      weeklyDownloads: await this.registry.getWeeklyDownloads(packument.name),
      name: packument.name,
      target,
      baseline: this.baseline(packument, target.version),
      time: packument.time,
      loadFiles: (version) => this.loadFiles(packument, version),
      lookupPackage: (dep) => this.registry.lookupPackage(dep),
    };
  }

  /**
   * Previous releases, newest first: same major line first (so a 0.x maintenance release is
   * compared with 0.x, not with 1.x), then the rest; prereleases only for prerelease targets.
   */
  private baseline(packument: Packument, version: string): VersionManifest[] {
    const published = Date.parse(packument.time[version] ?? '');
    const pre = isPrerelease(version);
    const major = parse(version)?.major;
    const earlier = Object.keys(packument.versions)
      .filter((v) => v !== version && (pre || !isPrerelease(v)))
      .filter((v) => {
        const t = Date.parse(packument.time[v] ?? '');
        return Number.isNaN(published) ? compare(v, version) < 0 : t < published;
      })
      .sort((a, b) => Date.parse(packument.time[b] ?? '') - Date.parse(packument.time[a] ?? ''));
    const same = earlier.filter((v) => parse(v)?.major === major);
    const ordered = same.length >= 3 ? same : [...same, ...earlier.filter((v) => !same.includes(v))];
    return ordered.slice(0, BASELINE_SIZE).map((v) => packument.versions[v]);
  }

  private loadFiles(packument: Packument, version: string): Promise<FileMap> {
    const manifest = packument.versions[version];
    if (!manifest?.dist?.tarball) return Promise.reject(new Error(`no tarball for ${version}`));
    return this.files.get(`${packument.name}@${version}`, () =>
      this.tarballs.fetchFiles(manifest.dist.tarball),
    );
  }

  private resolveVersion(packument: Packument, version?: string): string {
    const v = (version ?? 'latest').trim();
    if (packument['dist-tags'][v]) return packument['dist-tags'][v];
    if (packument.versions[v] || packument.time[v]) return v;
    const matching = this.candidates(packument, v);
    if (matching.length) return matching[0];
    throw new PackageNotFoundError(`${packument.name} has no version matching "${v}"`);
  }

  /** Versions in `range`, newest first, stable only unless the range names a prerelease. */
  private candidates(packument: Packument, range: string): string[] {
    return Object.keys(packument.versions)
      .filter((v) => satisfies(v, range))
      .sort((a, b) => compare(b, a));
  }

  private async findSafeVersion(packument: Packument, range: string, rejected: string) {
    const latest = packument['dist-tags'].latest;
    const pool = this.candidates(packument, range).filter((v) => v !== rejected);
    if (latest && latest !== rejected && compare(latest, rejected) > 0) pool.unshift(latest);
    for (const v of pool.slice(0, 3)) {
      try {
        const r = await this.checkLive(packument, v);
        if (r.verdict === 'ALLOW') {
          return {
            version: v,
            reason: compare(v, rejected) > 0
              ? 'current latest release, which passes every check'
              : 'newest earlier release that passes every check',
          };
        }
      } catch {
        // Try the next one.
      }
    }
    return undefined;
  }

  private report(
    name: string,
    version: string,
    publishedAt: string | undefined,
    verdict: ReturnType<typeof decide>,
    checks: string[],
    advisories: AdvisoryLookup,
    replay: boolean,
  ): Report {
    const now = replay ? REPLAY_NOW(publishedAt) : new Date().toISOString();
    const age = publishedAt ? hoursBetween(publishedAt, now) : undefined;
    const vulns = advisories.advisories.filter((a) => !a.malicious).length;
    return {
      package: name,
      version,
      verdict: verdict.verdict,
      score: verdict.score,
      summary: summarize(name, version, verdict.verdict, verdict.findings),
      findings: verdict.findings,
      notes: verdict.notes.map((n) => n.title),
      otherTools: {
        osv: !advisories.available
          ? 'OSV unreachable right now'
          : advisories.advisories.length
            ? [...advisories.advisories]
                .sort((x, y) => Number(y.malicious) - Number(x.malicious))
                .map((a) => (a.malicious ? `${a.id} (malware)` : a.id))
                .slice(0, 5)
                .join(', ')
            : 'no advisory',
        npmAudit: advisories.available
          ? `would report ${vulns} vulnerabilit${vulns === 1 ? 'y' : 'ies'}`
          : 'unknown (OSV unreachable)',
        cooldown:
          age === undefined
            ? 'publish time unknown'
            : age < 24
              ? `published ${formatAge(age)} ago: a 24 h cooldown (pnpm 11 default) would hold it, and every urgent fix too`
              : `published ${formatAge(age)} ago: older than a 24 h cooldown`,
      },
      publishedAt,
      checks,
    };
  }

  private notFound(name: string): Report {
    const f = finding('existence', 'critical', `${name} does not exist on npm`, [
      'AI agents sometimes invent package names; attackers register them ("slopsquatting")',
    ]);
    const v = decide([f]);
    return this.report(name, '-', undefined, v, ['existence'], { available: true, advisories: [] }, false);
  }

  private removed(packument: Packument, version: string, advisories: AdvisoryLookup): Report {
    const f = finding('existence', 'critical', `${packument.name}@${version} was published and then removed from npm`, [
      `published ${packument.time[version]}`,
      'npm removes versions that turn out to be malware; never install it from a mirror or cache',
      ...advisories.advisories.filter((a) => a.malicious).map((a) => `${a.id}: ${a.summary ?? 'malicious package'}`),
    ]);
    const v = decide([f]);
    const report = this.report(packument.name, version, packument.time[version], v, ['existence'], advisories, false);
    report.safeVersion = undefined;
    return report;
  }
}

function summarize(name: string, version: string, verdict: Verdict, findings: Finding[]): string {
  const top = findings.slice(0, 3).map((f) => f.title);
  if (verdict === 'ALLOW') {
    return `${name}@${version} looks consistent with its own history. ${top.length ? `Minor notes: ${top.join('; ')}.` : 'No risk signals.'}`;
  }
  const action = verdict === 'BLOCK' ? 'Do not install it.' : 'Ask a human before installing it.';
  return `${verdict}: ${name}@${version}. ${top.join('; ')}. ${action}`;
}

function describeChange(a: VersionManifest, b: VersionManifest): string[] {
  const out: string[] = [];
  const depsA = { ...a.dependencies, ...a.optionalDependencies };
  const depsB = { ...b.dependencies, ...b.optionalDependencies };
  const added = Object.keys(depsB).filter((d) => !(d in depsA));
  const removed = Object.keys(depsA).filter((d) => !(d in depsB));
  if (added.length) out.push(`dependencies added: ${added.join(', ')}`);
  if (removed.length) out.push(`dependencies removed: ${removed.join(', ')}`);
  for (const hook of ['preinstall', 'install', 'postinstall']) {
    if (a.scripts?.[hook] !== b.scripts?.[hook]) {
      out.push(`${hook}: ${a.scripts?.[hook] ?? '(none)'} -> ${b.scripts?.[hook] ?? '(none)'}`);
    }
  }
  if (a._npmUser?.name !== b._npmUser?.name) {
    out.push(`publisher: ${a._npmUser?.name ?? '?'} -> ${b._npmUser?.name ?? '?'}`);
  }
  if (Boolean(a.dist.attestations) !== Boolean(b.dist.attestations)) {
    out.push(`provenance: ${a.dist.attestations ? 'yes' : 'no'} -> ${b.dist.attestations ? 'yes' : 'no'}`);
  }
  if (!out.length) out.push('no manifest-level changes (publisher, provenance, scripts, dependencies)');
  return out;
}
