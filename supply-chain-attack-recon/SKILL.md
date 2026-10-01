---
name: supply-chain-attack-recon
description: External, public-artifact-only reconnaissance for software supply-chain attack surface — dependency confusion via leaked internal package-scope names, GitHub Actions workflow injection (pull_request_target + untrusted interpolation, mutable-tag action pinning), SBOM/version mining for known-CVE cross-reference, and container-registry/image-layer secret exposure. Distinct from `vibe-coded-app-testing`'s hallucinated-package ("slopsquatting") entry — that's an AI-agent-invented package name an attacker pre-registered; dependency confusion here is a *real* internal/private package name leaked publicly (JS bundle, `.npmrc`, CI config) that an attacker republishes under the same name on a public registry, betting the target's own build system will pull the public (malicious) version instead of the intended private one. Use this during Phase 1/3 (Recon/Vulnerability Testing — Supply chain) of bughunting-workflow whenever a target has a public GitHub org, publishes SBOMs, or ships container images to a public registry (Docker Hub/GHCR/Quay). Also trigger on mentions of dependency confusion, typosquatting, GitHub Actions injection, pull_request_target, SBOM, CycloneDX, SPDX, container registry exposure, or supply chain attack.
---

# Supply-Chain Attack Reconnaissance

Technique library for identifying software supply-chain attack surface through public-artifact analysis only — this is explicitly a recon-and-report skill, not an exploitation one. Each dated entry below is pulled from a real source — extend this file (don't create a duplicate skill) when a new writeup covers a different supply-chain attack primitive than what's already recorded.

## Core theory

A supply chain attack doesn't target the application directly — it targets something *upstream* the application trusts implicitly: a package name its build resolves, a CI workflow that runs with real secrets, a container base image it pulls, or a maintainer's publishing credentials. The common thread across every technique below is **trust transference**: the target's build/deploy pipeline treats "resolves from the expected namespace/tag/registry" as equivalent to "safe," and every technique here is a way of inserting attacker content into that resolution path without ever touching the target's own infrastructure directly.

**Critical scope boundary — read before testing anything below:** this skill is reconnaissance only. Identifying that an internal package name is unclaimed on a public registry, or that a GitHub Actions workflow has an injectable pattern, is a reportable finding on its own (with supporting evidence) — actually *publishing* a same-named package, submitting a PR to trigger workflow injection, or touching a self-hosted runner requires explicit written authorization beyond standard bug bounty scope, since the blast radius extends to the whole package-registry ecosystem or the target's CI infrastructure, not just the application under test. Confirm with the program before taking any action beyond identification.

## Recorded techniques

### 1. Ten-step supply-chain recon methodology — dependency confusion, Actions injection, SBOM/CVE mining, registry secret exposure
Source: [Claude-BugHunter — supply-chain-attack-recon skill](https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/supply-chain-attack-recon/SKILL.md)

**Where:** any target with a public GitHub organization, published SBOM releases, or container images on a public registry (Docker Hub/GHCR/Quay) — the recon surface exists independent of whether the application itself has any obvious web-facing vulnerability.

**Step 1-2 — org/repo discovery:** enumerate the target's public GitHub orgs (direct URL guessing, `gh api orgs/<name>`), then mine repos for high-signal naming (`internal`, `infra`, `deploy`, `config`, `sdk`) and pull every `package.json`/`requirements.txt` found for references to internally-scoped packages — cross-reference `github-recon-testing`'s existing dorking/secret-scanning methodology for the discovery mechanics, this just points that same recon at dependency manifests specifically rather than hardcoded secrets.

**Step 3-4 — dependency confusion:**
```bash
# Parse JS bundles / manifests for a scoped internal package name
grep -roE '@[a-z0-9_-]+/[a-z0-9_-]+' bundle.js package.json | sort -u

# Check whether that exact name is already claimed on the public registry
curl -s "https://registry.npmjs.org/@target-internal%2futils" | jq .
curl -s "https://pypi.org/pypi/target-internal-utils/json"
```
A 404/"not found" response is the *candidate* signal, not the finding itself — dependency confusion is only exploitable when the target's build system can actually be coerced into resolving the public registry over an internal one for that name. Supporting evidence that upgrades this from informational to Critical: a leaked `.npmrc`/`pip.conf` showing scope-to-registry mapping that falls back to the public registry, or direct confirmation the package is an active build-time dependency (referenced in a lockfile, not just mentioned once in a comment or old branch).

**Step 5 — typosquat candidate generation (identification only, see scope boundary above):** generate transposition/deletion/homoglyph variants of the target's actual external dependencies and check which variant names are unclaimed across registries — report unclaimed high-value names as a defensive-registration recommendation ("register this name yourself before someone else does"), never register them yourself without explicit written authorization, since doing so affects the package-registry ecosystem beyond the engagement's own blast radius.

**Step 6 — GitHub Actions workflow injection scanning:**
```bash
# Flag workflows combining pull_request_target with untrusted-context interpolation
grep -rl "pull_request_target" .github/workflows/ | xargs grep -l '\${{ *github\.event\.'

# Flag third-party actions pinned to a mutable tag instead of a commit SHA
grep -rE 'uses: .+@(v[0-9]+|main|master)$' .github/workflows/*.yml
```
Automate with `zizmor` (GitHub Actions-specific injection/antipattern scanner) or `actionlint`. The dangerous pattern is `pull_request_target` (which runs with the *target* repo's secrets/permissions, unlike plain `pull_request`) combined with any `${{ github.event.* }}` value — a PR title, branch name, or issue comment — flowing unescaped into a `run:` shell block; an external contributor's PR title becomes attacker-controlled shell input executing with repo secrets available. Mutable action-tag pinning (`@v1`/`@main` instead of a commit SHA) is a separate but related risk: the action's maintainer (or anyone who compromises their account) can silently repoint that tag to malicious code that every consumer picks up on their next run with zero changes to the consuming repo — this is exactly the mechanism behind the tj-actions/changed-files CVE-2025-30066 incident (23K+ repos impacted, secrets leaked into build logs).

**Step 7-8 — container/artifact registry mining:**
```bash
# Enumerate images for an org across public registries
curl -s "https://hub.docker.com/v2/repositories/<org>/?page_size=100" | jq '.results[].name'

# Pull an image and scan its filesystem layers for secrets
docker pull <org>/<image>:<tag>
docker save <org>/<image>:<tag> -o image.tar
tar -xf image.tar -C extracted/
trufflehog filesystem extracted/
```
SBOM releases (SPDX/CycloneDX format, often attached to GitHub Releases or published alongside container images) give exact dependency version pinning — cross-reference every listed version against `osv.dev` (or `osv-scanner` for an automated pass) for known CVEs the target may not have patched yet, a much higher-signal starting point than blind version-fingerprinting.

**Step 9-10 — internal registry/credential leakage:**
```bash
# Target config files by convention — they carry registry URLs and sometimes live tokens
grep -rE '_authToken|registry=' .npmrc pip.conf gradle.properties 2>/dev/null
```
Cross-reference `github-recon-testing`'s existing `.npmrc`/`.pypirc`/`.aws/credentials` secret-hunting coverage — this step is the same discovery pass, specifically watching for an internal registry *hostname* (which itself maps the target's private infrastructure even without a credential attached) alongside any `_authToken` value.

**Severity calibration:**
- **Critical** — dependency confusion with confirmed build-system misconfiguration (leaked scope-to-registry config, or confirmed active dependency) OR a `pull_request_target` workflow with PR-controlled code execution and real secrets exposed.
- **High** — a container image with a leaked credential in a layer; a third-party Action pinned to a mutable tag in a security-sensitive workflow.
- **Low/Informational** — an unclaimed typosquat name with no further evidence; an internal registry URL disclosed with no accompanying credential.

**Twelve real-world anchors worth citing in a report's risk framing** (each a disclosed, high-impact incident of this exact vuln class): SolarWinds Orion 2020 (trojanized signed binary via build-pipeline compromise, 18K customers), 3CX 2023 (cascading supply chain, 600K orgs), MOVEit Transfer 2023 (pre-auth SQLi in shipped code, 95M PII records), Codecov bash-uploader 2021 (Docker build credential leak, 2-month undetected env-var exfil), ua-parser-js 2021 (npm account compromise on a 7M-weekly-download package, CISA alert), event-stream 2018 (maintainer-handover social engineering targeting a Bitcoin wallet), Log4Shell 2021 (transitive deep-dependency JNDI injection), tj-actions/changed-files 2025 (mutable-tag repoint, 23K repos), PyPI typosquats 2018-2024 (`colourama`/`jeIlyfish`-style post-install exfil hooks), **Alex Birsan's original dependency-confusion research (2021)** — leaked internal scope names published publicly under the same name, $130K+ in bounties across multiple companies, the technique this skill's steps 3-4 directly operationalize, and XZ Utils 2024 (multi-year social-engineering of a maintainer, caught pre-deployment).

**Deliverable requirements for any finding from this skill:** a concrete package/workflow/image name or path, the exact exploitation mechanism, proof the installation/execution path is actually active (not just theoretically possible), a calibrated severity per the table above, and specific remediation (e.g., "register the unclaimed scope defensively," "pin this action to a commit SHA," "add explicit registry-scope mapping to `.npmrc`").

**Generalize note:** cross-reference `vibe-coded-app-testing` entry 1i for the sibling-but-distinct "hallucinated package" (slopsquatting) technique — that's an AI-agent-invented name an attacker pre-registered speculatively; dependency confusion here is a *real* leaked internal name an attacker republishes publicly, betting on build-system namespace resolution rather than on an LLM hallucinating the same typo twice. Both exploit the same underlying trust-transference root cause (build system resolves a name from an untrusted source as if it were trusted) but via different discovery paths. Also cross-reference `github-recon-testing` for the general secret-hunting mechanics steps 1-2 and 9-10 reuse, `cloud-storage-bucket-testing` for the parallel "public bucket enumeration" pattern applied to container registries instead, and `rce-exploitation-testing`/`claude-code-burp-mcp-workflow` for what comes after a confirmed workflow-injection or dependency-confusion finding escalates into actual code execution on a CI runner (out of this skill's recon-only scope).

<!-- Add new recorded techniques below this line as new supply-chain-attack writeups are processed. Keep the same structure: Where / Root cause / Exploit steps / Impact framing / Generalize note. -->
