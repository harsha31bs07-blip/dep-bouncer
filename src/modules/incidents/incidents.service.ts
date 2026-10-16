import { Injectable } from '@nitrostack/core';
import { readFileSync } from 'node:fs';
import type { AnalysisContext, PackageInfo, VersionManifest } from '../analysis/signal.js';

export interface IncidentSummary {
  id: string;
  title: string;
  date: string;
  packageName: string;
  targetVersion: string;
  goodVersion: string;
  osvFirstAdvisory: { id: string; lagHours: number };
}

export interface Incident extends IncidentSummary {
  sources: { name: string; url: string }[];
  real: string[];
  reconstructed: string[];
  safeVersion: string;
  weeklyDownloads: number;
  baseline: VersionManifest[];
  target: VersionManifest;
  time: Record<string, string>;
  files: Record<string, Record<string, string>>;
  packages?: Record<string, PackageInfo>;
}

const fixtureDirectory = new URL('./fixtures/', import.meta.url);
const incidentIds = ['axios', 'keyv', 'nx', 'chalk', 'tinycolor'];

@Injectable()
export class IncidentsService {
  private readonly incidents = new Map<string, Incident>(incidentIds.map((id) => [
    id, JSON.parse(readFileSync(new URL(`${id}.json`, fixtureDirectory), 'utf8')) as Incident,
  ]));

  list(): IncidentSummary[] {
    return Array.from(this.incidents.values(), (incident) => {
      const { id, title, date, packageName, targetVersion, goodVersion, osvFirstAdvisory } = incident;
      return { id, title, date, packageName, targetVersion, goodVersion, osvFirstAdvisory: { ...osvFirstAdvisory } };
    });
  }

  get(id: string): Incident {
    const incident = this.incidents.get(id);
    if (!incident) throw new Error(`Unknown incident: ${id}`);
    return structuredClone(incident);
  }

  toContext(id: string): AnalysisContext {
    const incident = this.get(id);
    return {
      name: incident.packageName,
      target: incident.target,
      baseline: incident.baseline.sort((a, b) =>
        (Date.parse(incident.time[b.version]) || 0) - (Date.parse(incident.time[a.version]) || 0)).slice(0, 10),
      time: incident.time,
      weeklyDownloads: incident.weeklyDownloads,
      reconstructed: true,
      async loadFiles(version) {
        if (!Object.hasOwn(incident.files, version)) throw new Error(`Files unavailable for ${incident.packageName}@${version} in incident ${id}`);
        return new Map(Object.entries(incident.files[version]).map(([path, text]) => [path, new TextEncoder().encode(text)]));
      },
      async lookupPackage(name) {
        return incident.packages && Object.hasOwn(incident.packages, name)
          ? structuredClone(incident.packages[name]) : null;
      },
    };
  }
}
