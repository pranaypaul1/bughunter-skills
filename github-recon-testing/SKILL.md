---
name: github-recon-testing
description: GitHub-based secret/credential recon — dorking GitHub's own search (and mirrors like grep.app/SourceGraph) for a target's leaked API keys, cloud credentials, database passwords, private keys, and internal URLs committed by developers (official org repos, forks, random personal repos referencing the target), plus automated bulk-scanning tools (GitGraber, TruffleHog), live-target `.git/` directory exposure+dumping, key-validation methodology before reporting, and a systematic local source-tree secret-scanning checklist (grep/regex sweeps, git history mining, gitleaks/detect-secrets/GitGuardian, dotfiles, comments, dependency/vendor trees, IaC files) for once you actually have code in hand. Use this during Phase 1/3 (Recon/Vulnerability Testing — Info disclosure) of bughunting-workflow on every target as a cheap, high-signal parallel track — secrets leak via developer mistakes independent of the target's own security posture. Also trigger on mentions of GitHub dorking, GitGraber, TruffleHog, git-dumper, GitTools, DotGit, Keyhacks, leaked API key/credential search, gitleaks, detect-secrets, GitGuardian, or secrets in source code.
---

# GitHub Recon for Secrets/Leaks

Technique library for finding a target's leaked secrets on GitHub — both official repos and the much larger surface of random developer repos that merely *reference* the target (a contractor's test script, a personal project hardcoding a client's key, a fork that never scrubbed history). Each dated entry below is a validated technique pulled from a real writeup/source — add new entries here (don't create a new skill) whenever a new writeup covers a *different* dork category, tool, or validation trick than what's already recorded.

## Core theory

Secrets leak on GitHub because commits are permanent by developer habit even when the *file* gets deleted later — a `.env` added then removed in a later commit is still sitting in the repo's history unless it was force-pushed away and garbage-collected (and even then, dangling objects can survive). GitHub's own search indexes code content, not just filenames/metadata, so a well-chosen keyword search surfaces secrets regardless of which specific repo/developer committed them — official org account, an employee's personal account, a contractor, or a random unaffiliated project that just happens to reference the target's API.

**Critical caveat before reporting anything found this way:** a matching credential is not automatically *the target's* — confirm it actually belongs to the target's live assets (test it against a known-safe, low-impact endpoint, or check the surrounding code/repo context for target-specific identifiers) before writing it up. Random developers commit secrets for unrelated services that merely mention the target's name in a comment or test fixture.

## Manual dorking on GitHub's own search

**Start broad, then narrow:**
```
"example.com" password
"example.com" "password":
```
The JSON/key-value form (`"password":`) is deliberately noisier-looking but higher-signal — it matches structured config/credential dumps (`"username": "admin", "password": "supersecret123"`) rather than incidental mentions of the word "password" in prose/comments.

**Scope to the target's official org:**
```
org:example "password":
```

**Comprehensive multi-keyword sweep in one query** (OR-chain every credential-shaped keyword instead of searching one at a time):
```
"domain" AND ("api_key" OR "secret" OR "password" OR "access_token" OR "client_secret" OR "private_key" OR "AWS_SECRET_ACCESS_KEY" OR "DB_PASSWORD" OR "slack_token" OR "github_token" OR "BEGIN RSA PRIVATE KEY")
```

**Search operators/filters to combine with the above:**
| Filter | Purpose | Example |
|---|---|---|
| `filename:` | Search specific filenames | `filename:.env "DB_PASSWORD"` |
| `extension:` | Filter by file type | `extension:json "access_token"` |
| `path:` | Search specific directories | `path:/config filename:database.php` |
| `repo:` | Target one specific repository | `repo:vercel/next.js filename:config.js` |
| `language:` | Filter by code language | `"domain" language:PHP password` |

**High-value `path:` targets specifically:**
```
path:/config
path:/wp-config.php
path:/src/secrets
path:/.ssh
path:/.git
path:**/.env        # nested .env at any depth, not just repo root
```

## Regex dorking, temporal/exclusion operators, and provider-prefix-specific queries

**Regex-pattern search** — GitHub's search supports `/pattern/` regex syntax directly in the query, letting you match a *key's actual shape* instead of just its variable name — higher-signal than a keyword match since it only fires on strings that look like real credentials:
```
org:"target" /"sk-[a-zA-Z0-9]{20,50}"/        # OpenAI-shaped secret key
org:"target" /https?:\/\//                     # any hard-coded URL, for endpoint/internal-host discovery
org:"target" /\/\/(.*\.)?amazonaws\.com/       # hard-coded AWS endpoint references
```

**Temporal and result-ordering operators** — narrow to what's likely still live/unrotated, or to a specific time window worth re-checking on a standing basis (pairs with `recon-scanning-toolkit`'s crtmon-style continuous-monitoring pattern):
```
org:"target" "api_key" created:>2024-01-01
org:"target" "api_key" pushed:>2024-01-01     # last-modified date, catches secrets re-touched even in an old repo
org:"target" "api_key" sort:indexed-asc        # oldest-indexed first — long-forgotten leaks
org:"target" "api_key" sort:indexed-desc       # most-recent first — freshest, most likely still-valid leaks
```

**`NOT`/exclusion and `user:` operators:**
```
org:"target" "api_key" NOT filename:test.js    # drop test/fixture noise
user:"specific-developer" "target.com"         # pivot from an org search to a specific employee/contractor account once one turns up
```

**Provider-prefix-specific dorks worth adding to the standing sweep** (exact literal string prefixes each vendor's key format uses, higher-signal than a generic `api_key` keyword match):
```
org:"target" ("sk_live_" OR "pk_live_")                          # Stripe (live-mode keys specifically — sk_test_/pk_test_ are lower value)
org:"target" (ANTHROPIC_API_KEY OR anthropic_api_key)
org:"target" (SENDGRID_API_KEY OR sendgrid_api_key)
org:"target" ("mongodb://" OR "mongodb+srv://" OR "mysql://")     # full DB connection strings, not just a password keyword
org:"target" (filename:.env OR filename:.env.local OR filename:travis.yml)
org:"target" (extension:pem OR extension:key OR extension:p12 OR extension:pfx)   # certificates/private-key files by extension, complements the BEGIN-*-PRIVATE-KEY string dork above
```

## Beyond GitHub: other public dev-tooling/collaboration platforms

The same "developers leak by habit, permanently, on whatever platform they're using" logic extends past GitHub itself — sweep these as a cheap parallel track once the GitHub pass is done:
- **Jenkins** — search for the target's CI instance and check whether open/anonymous signup or anonymous read access is enabled (`<jenkins-url>/manage`, or just browsing job configs unauthenticated) — job configs and build logs routinely embed credentials, internal hostnames, and deploy scripts.
- **Jira / Trello** — public-facing boards (misconfigured project visibility) can expose internal ticket details, infrastructure notes, and sometimes credentials pasted into a ticket description or comment during troubleshooting.
- **Public Google Docs/Sheets** — search `site:docs.google.com "<target-name>"` (and equivalent for Sheets/Slides) for internal documentation, runbooks, or credential sheets a team member left shared-by-link instead of restricted.

Treat a hit on any of these exactly like a GitHub hit: confirm it actually belongs to the target before reporting, and validate any found credential per the Key validation section below rather than assuming it's live.

## Secret-category keyword taxonomy

Sweep each category — different apps/teams name their env vars completely differently, so breadth matters more than any single "best" keyword:

- **Auth/tokens:** `api_key`, `access_token`, `client_secret`, `auth_token`, `authorizationToken`, `x-api-key`, `SECRET_KEY`, `secret_token`, `credentials`, `token`, `secure`
- **Cloud providers:** `AWS_SECRET_ACCESS_KEY`, `AWS_ACCESS_KEY_ID`, `aws_access_key_id`, `aws_secret_key`, `aws_token`, `GCP_SECRET`, `gcloud_api_key`, `firebase_url`, `shodan_api_key`
- **Database credentials:** `DB_PASSWORD`, `DATABASE_URL`, `db_password`, `db_pass`, `MYSQL_PASSWORD`, `POSTGRES_PASSWORD`, `mongo_uri`, `mongodb_password`
- **SSH/private keys:** `BEGIN RSA PRIVATE KEY`, `BEGIN OPENSSH PRIVATE KEY`, `BEGIN PGP PRIVATE KEY BLOCK`, `id_rsa`, `private_key`, `pem private`
- **Service-specific tokens:** `slack_token`, `discord_token`, `github_token`, `gitlab_token`, `twilio_auth_token`, `mailgun`, `stripe_secret`, `SF_USERNAME salesforce`
- **Password spelling variants** (don't assume one spelling): `password`, `passwd`, `pwd`, `pass`

(This taxonomy generalizes the narrower `org:target "amazonaws"`/`"aws_access_key"`/`"aws_secret_key"`/`"S3_BUCKET"` dork set already recorded in `cloud-storage-bucket-testing` — that skill's list is the AWS/S3-specific subset of this fuller category taxonomy; use this skill's full sweep, not just the S3-scoped one, for general secret hunting.)

## Automated bulk-scanning tools

**GitGraber** — scrapes GitHub search results at scale against a keyword wordlist, returns direct URLs/timestamps/JSON previews instead of manual browsing:
```bash
python3 gitGraber.py -k wordlists/keywords.txt -q nasa.gov -s
python3 gitGraber.py -k wordlists/keywords.txt -q "nasa.gov" -s
```

**TruffleHog** — scans a repo (local clone, remote URL, or an entire GitHub org) for verified/high-confidence secrets using entropy + pattern detection:
```bash
trufflehog git file:///home/user/my-repo
trufflehog git https://github.com/username/repo.git
trufflehog git [url] --results=verified,unknown
trufflehog git [url] --results=verified,unknown --json | jq
trufflehog github --repo=[url] --issue-comments --pr-comments
trufflehog github --org=nasa --token=yourgithubtoken
```
`--results=verified,unknown` filters out TruffleHog's low-confidence noise; `--issue-comments --pr-comments` extends scanning beyond code into issue/PR discussion text, where secrets get pasted accidentally almost as often as into files. Scanning by `--org` sweeps every repo in the org in one pass instead of cloning each individually.

## Live-target `.git/` directory exposure (separate from GitHub.com recon, same underlying leak class)

This targets an exposed `.git` directory left reachable on the *target's own live web server* (not github.com) — the deployment process copied the repo including its `.git` folder into the public webroot. See `recon-scanning-toolkit`'s Git-repository-disclosure section for the base detection commands (`httpx-toolkit -path /.git/config -mc 200 -ms "[core]"`, `nuclei -t gitExposed.yaml`) and Git Dumper usage — this section adds the details specific to actually working with what you find:

```bash
# Bulk detection across many hosts at once
httpx-toolkit -l subs.txt -path /.git/ -mc 200
cat domains.txt | httpx-toolkit -sc -server -cl -path "/.git/" -mc 200 -location -ms "Index of" -probe

# Extraction (multiple tool options — try another if one fails on a given target)
./gitdumper.sh https://domain.com/.git/ outputdir
git-dumper https://domain.com/.git/ outputdir
```
Tool family: **GitTools**, **git-dumper**, **git-extractor** — functionally similar, keep more than one on hand since directory-listing-dependent vs. object-enumeration-dependent extraction methods don't all work against every misconfigured server the same way. **DotGit** (Chrome extension) passively alerts whenever a visited site exposes `.git`, useful while browsing a target manually rather than only during a scripted sweep.

**Restoring the repository after dumping:**
```bash
cd output_dir
git status
git restore .
git checkout .
```
This recovers files and — critically — lets you walk commit history (`git log`, `git diff` between commits) to find secrets that were committed and later *deleted* from the live tree but still exist in history, which is often higher-value than whatever's in the current checkout.

**403 on `/.git/` doesn't mean game over:** directory listing being blocked (403) only stops the *listing* — the individual object files under `.git/objects/` are frequently still directly fetchable by path even when the index is blocked, so extraction tools that enumerate/guess object hashes rather than relying on directory listing can still pull partial-to-complete repo data.

## Local source-tree secret scanning (once you have code in hand)

Everything above finds *where* to get source code (GitHub dorking, `.git` dumping). This section is the next step: once you actually have a directory of code sitting on disk — a dumped/restored `.git` repo, a cloned public repo, a leaked archive, a decompiled mobile app (see `mobile-app-testing`), an unpacked npm/pip package — sweep it systematically rather than eyeballing files. Run all of these; secrets hide in different corners depending on developer habit, not just in obvious config files.

**1. Broad + targeted grep sweeps:**
```bash
grep -Ri 'password' .
grep -RniE 'password|pass|secret|token|key|api|client|auth' .
grep --exclude-dir={.git,node_modules,venv} -RniE 'password|secret|token' .   # cut noise from vendored/dependency trees first
```

**2. Git history mining — the current checkout is not the whole story:**
```bash
git log -p | grep -i 'password\|secret\|token'
trufflehog filesystem .
```
A secret added then deleted in a later commit is still sitting in history unless force-pushed away and garbage-collected — always check `git log -p`/full history, not just `grep` on the working tree, on any repo you've cloned or restored from a `.git` dump.

**3. Regex patterns for specific credential formats** (higher-signal than plain keyword grep since they match the credential's actual shape, not just a nearby word):
```
AKIA[0-9A-Z]{16}                                          # AWS Access Key ID
AIza[0-9A-Za-z\-_]{35}                                    # Google API Key
(?i)aws(.{0,20})?(?:['\"][A-Za-z0-9/+=]{40}['\"])         # AWS Secret Key (heuristic)
-----BEGIN(.*?)PRIVATE KEY-----                           # any private key block
eyJ[a-zA-Z0-9-_]+?\.[a-zA-Z0-9-_]+?\.[a-zA-Z0-9-_]+       # JWT
```
```bash
grep -Poz '(?s)-----BEGIN(.*?)PRIVATE KEY-----(.*?)-----END(.*?)PRIVATE KEY-----' .
```

**4. Automated scanners beyond TruffleHog** — run more than one, since each uses a different detection strategy (entropy vs. regex vs. verified-provider callback) and catches different false-negatives:
```bash
brew install gitleaks
gitleaks detect --source .
```
Also worth having: **detect-secrets** (Yelp — plugin-based entropy+pattern detection, good for pre-commit-hook-style baseline diffing) and **GitGuardian CLI** (ggshield — validates many secret types live against their issuing provider, reducing false positives vs. pure pattern matching).

**5. Dotfile discovery** — dotfiles are invisible to a casual `ls`/file browser and get skipped by hunters who only check "normal" files:
```bash
find . -type f -name ".*"
grep -ai 'secret\|key\|password\|token' $(find . -type f -name ".*")
```
Target specifically: `.env`, `.docker-compose.env`, `.aws/credentials`, `.pypirc`, `.npmrc` — each is a credential file by convention, not just a place a secret might incidentally appear.

**6. Comment scanning** — developers leave credentials in comments during debugging and forget to strip them before commit:
```bash
grep -R '^ *#' .                                              # Python-style comments
grep -R '//.*' .                                               # JS/C-style comments
grep -RniE 'password|secret|token|auth' --include=*.js --include=*.py .
```

**7. Dependency/vendor tree inspection** — `node_modules`/`vendor` are usually excluded from manual review (correctly, for code-quality purposes) but sample configs and test fixtures bundled inside third-party packages sometimes ship real-looking or even real credentials:
```bash
grep -RniE 'password|token|secret' ./node_modules
grep -RniE 'password|token|secret' ./vendor
```

**8. Infrastructure-as-Code scanning** — Terraform/CloudFormation/Docker Compose files frequently hardcode credentials as variable defaults rather than referencing a secrets manager:
```bash
grep -RniE 'password|secret|token|access[_]?key' .
```
A hardcoded cloud credential in IaC is disproportionately high-impact — it's not just app-data access, it's often infra-provisioning access for the account that ran `terraform apply`.

**9. IDE-assisted search** — for a smaller codebase, VS Code's `Ctrl+Shift+F` project-wide search with the same keyword list (`token`, `secret`, `AWS`, `BEGIN PRIVATE KEY`, `password`, `.env`) is a fast manual complement to the scripted sweeps above, especially useful for spotting context (surrounding code) that tells you whether a match is a real secret or just a variable *named* `password` with no value.

**Quick-reference pattern list to keep on hand for any of the above:**
```
password= | api_key= | secret= | access_token=
Authorization: | -----BEGIN PRIVATE KEY-----
AKIA[0-9A-Z]{16} | AIza[0-9A-Za-z\-_]{35} | slack.com/api/
```

## Key validation before reporting

Use the **Keyhacks** repository (community-maintained) — it documents the exact command-line test for 50+ different API key/token types (a specific curl call or CLI command per provider) to confirm a discovered key is live and functional before including it in a report. Always validate this way rather than reporting a found-looking string as-is; an expired/rotated/already-revoked key found in old commit history is not a valid finding.

**Before either step, confirm the key type is actually meant to be secret at all** — check the provider's own API documentation for that key/token format first. Some key-shaped strings are *designed* to be public (Stripe's `pk_live_`/`pk_test_` publishable keys, a Google Maps browser API key restricted by HTTP referrer, a Firebase client `apiKey` — the client SDK config is meant to ship to the browser). Finding one of these isn't a vulnerability on its own; the reportable version is the corresponding *secret*-scoped counterpart (Stripe's `sk_live_`, an unrestricted/server-scoped key) or a public key that grants more than its documented public scope should (a Firebase `apiKey` with no matching Firestore/Storage security rules, covered in `vibe-coded-app-testing`).

**Concrete worked example — GitHub token, escalating validation to prove write access (the difference between "found a token" and a $50,000 bug):** don't stop at confirming a `ghp_...` token is merely *live* — the actual severity is determined by what it's authorized to do, so escalate the checks in order of increasing specificity:
```bash
# 1. Confirm the token is live at all
curl -H "Authorization: token ghp_..." https://api.github.com/user

# 2. Check organization membership/access
curl -H "Authorization: token ghp_..." https://api.github.com/user/orgs

# 3. Check write (push) permission on a specific target repo — this is the finding that matters
curl -H "Authorization: token ghp_..." \
  https://api.github.com/repos/ORG/REPO | jq '.permissions.push'
```
A `"push": true` result is what turns a found string into a fundable finding — it proves the token grants unauthorized *write* access to a real repository (supply-chain risk: the attacker could push malicious commits), not just read access to something already semi-public. Source: [Extract-Grep-Curl: A $50,000 Bug POC Methodology](https://infosecwriteups.com/extract-grep-curl-a-50000-bug-poc-methodology-16365489de92) — this exact chain was used to validate the source's headline $50,000 GitHub-token finding, extracted from a client application (see `mobile-app-testing`'s iOS entry and `desktop-client-secret-extraction-testing` for the extraction half of that same source).

## Recorded techniques

### 1. Full GitHub dorking + tooling + .git-exposure methodology (baseline)
Source: [GitHub Recon: The Underrated Technique to Discover High-Impact Leaks in Bug Bounty](https://infosecwriteups.com/github-recon-the-underrated-technique-to-discover-high-impact-leaks-in-bug-bounty-c4069894389a)

**Where:** every target, run in parallel with live-app testing — this is recon against developer behavior, not the target's own defenses, so it's uncorrelated with how hardened the live app is.

**Root cause:** developers commit secrets to version control (directly, in a since-reverted commit, or in an unrelated personal/contractor repo referencing the target) and GitHub's code search indexes that content indefinitely unless the offending commit is actually purged from history.

**Exploit steps:** run the manual dork categories above (broad → org-scoped → multi-keyword OR-chain → filtered by `filename:`/`extension:`/`path:`/`language:`) across the full secret-category taxonomy; run GitGraber/TruffleHog for scale beyond what manual dorking covers; separately sweep the target's live hosts for exposed `.git/` and dump+restore any hit; validate every candidate key via Keyhacks before reporting, and confirm target ownership for anything found outside the official org.

**Impact framing for report:** severity scales with what the validated key/credential grants access to — a live cloud provider key (AWS/GCP) or database credential is Critical (direct data/infra access); a validated-but-scoped service token (Slack, Mailgun) is High; an expired/already-rotated key is not reportable at all. Always attach the validation step's output (Keyhacks command + result) as PoC, not just the raw string found.

**Generalize note:** treat this as a standing parallel recon track for every engagement, not a one-time check — new commits (and new leaks) can appear on a target's dependent repos at any point during a long-running engagement, so a periodic re-sweep (especially after a program announces a new feature/product, which often means new contractor/vendor repos referencing the target) is worth the low cost of re-running these dorks.

### 2. Systematic 10-method local source-tree secret sweep
Source: [Secrets in Source Code: 10 Ways to Find Them](https://medium.verylazytech.com/secrets-in-source-code-10-ways-to-find-them-step-by-step-master-guide-f071a796a653)

**Where:** any point in an engagement where you end up holding an actual source tree — a `.git` dump restored via the technique above, a cloned public repo, a leaked/backup archive found on a live host, or an unpacked mobile app/npm/pip package.

**Root cause:** the same one as the rest of this skill (developers commit/leave secrets in places they don't expect anyone to look), but the exploitation gap here is methodological rather than a discovery-vector gap — hunters who already have the code in hand often only skim obvious config files and miss the higher-yield, less-obvious corners (deleted-but-still-in-history commits, dotfiles, comments, vendored dependencies, IaC variable defaults).

**Exploit steps:** run the full "Local source-tree secret scanning" checklist above end-to-end against any source tree obtained during the engagement — plain keyword grep, `git log -p` history mining (never assume the current checkout is the whole story), format-specific regexes (AWS key IDs, private key blocks, JWTs), gitleaks/detect-secrets/GitGuardian CLI as automated cross-checks against each other, dotfile discovery, comment scanning, dependency/vendor-tree inspection, and IaC variable-default scanning. Validate every hit via Keyhacks (see below) before reporting, same as any GitHub-sourced finding.

**Impact framing for report:** identical scaling to the rest of this skill — a live cloud/database credential found this way is just as Critical as one found via GitHub dorking; the source is different, the reporting bar isn't. Call out explicitly *where* in the source tree the secret was found (current file vs. deleted-but-in-history vs. a vendored dependency's sample config) since that affects how the target should remediate (rotate + purge history vs. just delete a file).

**Generalize note:** treat this as the standing "what do I do with source code once I have it" checklist — apply it every time any other technique (mobile app decompilation via `mobile-app-testing`, a `.git` dump, a discovered backup archive, a leaked internal repo) hands you a directory of code to review, rather than re-deriving an ad-hoc grep each time.

<!-- Add new recorded techniques below this line as new GitHub-recon writeups are processed. Keep the same structure: Where / Root cause / Exploit steps / Impact framing / Generalize note. -->
