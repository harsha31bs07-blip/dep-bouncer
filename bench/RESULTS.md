# Benchmark results

5/5 replayed hijacks blocked; 60 popular releases: 53 ALLOW, 7 REVIEW, 0 BLOCK

Generated: 2026-10-16T14:47:19.358Z. Popular checks request the current npm latest tag; resolved versions and per-call timestamps are in results.json.

Replays use labelled reconstructions. Popular packages are a presumed-healthy sample, not independently verified ground truth; REVIEW and BLOCK counts are candidate false positives. Errors are excluded from verdict counts. Durations include any rate-limit wait and retry.

## Replayed hijacks

| ID / package | Version | Verdict | Score | Top 3 findings / error | Duration (ms) |
|---|---|---|---:|---|---:|
| axios | 1.14.1 | BLOCK | 100 | New dependency plain-crypto-js looks like a malware drop; Provenance dropped: previous release 1.14.0 was built and signed by CI, this one was not; Published by the personal account "jasonsaayman" instead of the package's CI (trusted publishing) | 67 |
| keyv | 6.0.0 | BLOCK | 100 | Suspicious exec in release code; Suspicious ai-agent-abuse in release code; Suspicious obfuscation in release code | 89 |
| chalk | 5.6.1 | BLOCK | 100 | Suspicious wallet in release code; Suspicious obfuscation in release code; New publisher "qix" has never released this package before | 6 |
| nx | 21.5.0 | BLOCK | 100 | Suspicious credentials in release code; Suspicious exfil in release code; Suspicious ai-agent-abuse in release code | 19 |
| tinycolor | 4.1.1 | BLOCK | 100 | Suspicious credentials in release code; Suspicious exfil in release code; Suspicious persistence in release code | 75 |

## Non-ALLOW popular releases

| ID / package | Version | Verdict | Score | Top 3 findings / error | Duration (ms) |
|---|---|---|---:|---|---:|
| typescript | 7.0.2 | REVIEW | 60 | New publisher "microsoft1es" has never released this package before; 10 new dependencies not examined; Suspicious exec in release code | 16865 |
| webpack | 5.112.0 | REVIEW | 45 | Published 16.3 h ago; Suspicious obfuscation in release code; Suspicious exec in release code | 4029 |
| vite | 8.3.4 | REVIEW | 30 | Suspicious exec in release code; Suspicious obfuscation in release code | 2959 |
| vitest | 5.0.5 | REVIEW | 35 | Suspicious credentials in release code | 1496 |
| next | 16.4.2 | REVIEW | 30 | Published 17.8 h ago; Code comparison incomplete: Compressed tarball exceeds 25 MB | 2405 |
| date-fns | 4.4.0 | REVIEW | 15 | Code comparison incomplete: Tarball exceeds 5000 files | 5021 |
| tsx | 4.23.15 | REVIEW | 30 | Suspicious obfuscation in release code; Suspicious exec in release code | 2878 |

## ALLOW popular releases

- react@19.3.1
- react-dom@19.3.1
- lodash@4.18.1
- express@5.3.0
- axios@1.20.0
- chalk@6.0.1
- debug@4.4.3
- commander@15.0.0
- eslint@10.13.0
- prettier@3.9.10
- rollup@4.64.7
- esbuild@0.28.2
- @babel/core@8.0.7
- jest@30.5.2
- mocha@12.0.3
- vue@3.5.44
- svelte@5.57.2
- zod@4.6.7
- yup@1.7.1
- dayjs@1.11.23
- moment@2.31.0
- uuid@14.0.3
- nanoid@6.0.2
- dotenv@18.0.8
- cors@2.8.6
- body-parser@2.3.0
- ws@8.22.0
- socket.io@4.8.4
- node-fetch@3.3.2
- undici@8.12.2
- got@16.1.0
- semver@7.8.5
- glob@13.0.6
- minimatch@10.2.6
- rimraf@6.1.3
- fs-extra@11.4.1
- yargs@18.2.0
- inquirer@14.2.3
- ora@9.4.1
- cross-env@10.1.0
- concurrently@10.0.6
- nodemon@3.1.14
- ts-node@10.9.2
- @types/node@26.6.5
- tslib@2.8.1
- rxjs@7.8.2
- immer@11.1.21
- redux@5.0.1
- @reduxjs/toolkit@2.13.0
- react-router@8.4.0
- tailwindcss@4.3.3
- postcss@8.5.30
- sharp@0.35.5
