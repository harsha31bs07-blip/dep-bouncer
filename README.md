# Dep Bouncer

**`npm install`, reimagined for AI agents.** An MCP server that an AI coding agent calls
*before* it installs or upgrades an npm package. It compares the release with the package's
own history (publisher, provenance, install scripts, new dependencies, code diff, name) and
returns **ALLOW / REVIEW / BLOCK** with evidence, plus a safe version to install instead.

Built with [NitroStack](https://nitrostack.ai) for the Heapify x NitroStack MCP Buildathon
(Developer Tools track). Work in progress: full README, live URL and demo video coming.

## Why

When axios (~100M weekly downloads) was hijacked on 31 March 2026, the free advisory
databases needed 2.9 hours to list it, and `npm audit` said "found 0 vulnerabilities" the
whole time. Agents install in seconds. Dep Bouncer judges the release itself.

## Tools

| Tool | What it does |
|---|---|
| `bouncer_check_package` | Vet a release before `npm install` |
| `bouncer_check_upgrade` | Vet a version bump and show what changed |
| `bouncer_safe_version` | Newest version in a range that passes every check |
| `bouncer_replay_incident` | Replay a real hijack (axios, keyv, chalk, nx, tinycolor) on a labelled reconstruction |

## Run locally

```bash
npm install
npm run build
npm test
npm run dev        # NitroStudio / stdio
```

## Safety

Dep Bouncer never executes package code: tarballs are downloaded from the npm registry only
and inspected in memory. The malicious versions of the replayed incidents were removed from
npm; the replays use real last-good releases plus **benign stand-in code** that only mimics
the structure of the attacks, and every stand-in file says so.

## License

MIT
