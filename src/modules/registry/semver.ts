/**
 * Minimal semver helpers (no dependency): parse, compare, and match the range forms agents
 * actually pass (exact, ^, ~, x-ranges, >=, *).
 */

export interface SemVer {
  major: number;
  minor: number;
  patch: number;
  prerelease: string[];
  raw: string;
}

const SEMVER = /^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$/;

export function parse(version: string): SemVer | null {
  const m = SEMVER.exec(version.trim());
  if (!m) return null;
  return {
    major: Number(m[1]),
    minor: Number(m[2]),
    patch: Number(m[3]),
    prerelease: m[4] ? m[4].split('.') : [],
    raw: version,
  };
}

export function isPrerelease(version: string): boolean {
  return (parse(version)?.prerelease.length ?? 0) > 0;
}

export function compare(a: string, b: string): number {
  const x = parse(a);
  const y = parse(b);
  if (!x || !y) return a.localeCompare(b);
  for (const k of ['major', 'minor', 'patch'] as const) {
    if (x[k] !== y[k]) return x[k] - y[k];
  }
  if (!x.prerelease.length || !y.prerelease.length) {
    return y.prerelease.length - x.prerelease.length;
  }
  const n = Math.max(x.prerelease.length, y.prerelease.length);
  for (let i = 0; i < n; i++) {
    const p = x.prerelease[i];
    const q = y.prerelease[i];
    if (p === undefined) return -1;
    if (q === undefined) return 1;
    const pn = /^\d+$/.test(p);
    const qn = /^\d+$/.test(q);
    if (pn && qn && Number(p) !== Number(q)) return Number(p) - Number(q);
    if (pn !== qn) return pn ? -1 : 1;
    if (p !== q) return p < q ? -1 : 1;
  }
  return 0;
}

/**
 * True if `version` satisfies `range`. Supports: '*', '', 'x', exact, '^1.2.3', '~1.2.3',
 * '1', '1.2', '1.x', '1.2.x', '>=1.2.3', '>1.2.3', '<=1.2.3', '<1.2.3', and space-separated
 * conjunctions ('>=1.0.0 <2.0.0'). Prereleases only match ranges that name a prerelease.
 */
export function satisfies(version: string, range: string): boolean {
  const v = parse(version);
  if (!v) return false;
  const parts = range.trim().split(/\s+/).filter(Boolean);
  if (parts.length === 0) return v.prerelease.length === 0;
  if (v.prerelease.length && !/-/.test(range)) return false;
  return parts.every((part) => satisfiesOne(version, part));
}

function satisfiesOne(version: string, part: string): boolean {
  if (part === '*' || part === 'x' || part === 'X' || part === 'latest') return true;
  const op = /^(\^|~|>=|<=|>|<|=)?(.*)$/.exec(part)!;
  const operator = op[1] ?? '';
  const body = op[2];

  const wild = /^(\d+)(?:\.(\d+|x|X|\*))?(?:\.(\d+|x|X|\*))?$/.exec(body);
  if (wild && (wild[2] === undefined || wild[3] === undefined || /[xX*]/.test(body))) {
    const major = Number(wild[1]);
    const minor = wild[2] !== undefined && /^\d+$/.test(wild[2]) ? Number(wild[2]) : null;
    const lower = `${major}.${minor ?? 0}.0`;
    const upper =
      minor === null || (operator === '^' && major > 0)
        ? `${major + 1}.0.0-0`
        : `${major}.${minor + 1}.0-0`;
    if (operator === '' || operator === '=' || operator === '^' || operator === '~') {
      return compare(version, lower) >= 0 && compare(version, upper) < 0;
    }
    return satisfiesOne(version, `${operator}${lower}`);
  }

  const target = parse(body);
  if (!target) return false;
  const c = compare(version, body);
  switch (operator) {
    case '':
    case '=':
      return c === 0;
    case '>':
      return c > 0;
    case '>=':
      return c >= 0;
    case '<':
      return c < 0;
    case '<=':
      return c <= 0;
    case '~':
      return c >= 0 && compare(version, `${target.major}.${target.minor + 1}.0-0`) < 0;
    case '^': {
      const upper =
        target.major > 0
          ? `${target.major + 1}.0.0-0`
          : target.minor > 0
            ? `0.${target.minor + 1}.0-0`
            : `0.0.${target.patch + 1}-0`;
      return c >= 0 && compare(version, upper) < 0;
    }
  }
  return false;
}
