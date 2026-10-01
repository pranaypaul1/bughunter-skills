---
name: cloud-storage-bucket-testing
description: Cloud object-storage bucket recon and exploitation — finding exposed AWS S3, Azure Blob, GCS, Alibaba OSS, and DigitalOcean Spaces buckets tied to a target and testing them for public-listing, read, write, and delete misconfigurations. Covers Google dorking, subdomain/JS-file S3 URL extraction, bucket-name brute-forcing/permutation, in-scope-seeded scoped wordlists, GitHub secret search, public bucket databases, nuclei-tagged mass verification, and unauthenticated AWS CLI exploitation. Use this during Phase 1/3 (Recon/Vulnerability Testing — Info disclosure/Access control) of bughunting-workflow whenever the target's stack includes any cloud object storage (S3/Azure/GCS/OSS/Spaces buckets referenced in JS/HTML, Wappalyzer flags a cloud provider) or the hunter is doing general asset discovery. Also trigger on mentions of S3 bucket, s3.amazonaws.com, bucket misconfiguration, `--no-sign-request`, LazyS3, S3Scanner, GrayhatWarfare, Alibaba OSS, or DigitalOcean Spaces.
---

# Cloud Storage Bucket (S3) Testing

Technique library for finding and exploiting misconfigured cloud object-storage buckets. Each dated entry below is a validated technique pulled from a real writeup/source — add new entries here (don't create a new skill) whenever a new writeup covers a *different* cloud provider, detection method, or exploitation angle than what's already recorded.

## Core theory

Object storage (S3, Azure Blob, GCS) is opt-in private by default at the *service* level, but individual buckets are routinely misconfigured by whoever created them — public ACLs left on, overly permissive bucket policies, no CloudTrail/monitoring. The bug isn't in AWS's platform; it's in a human decision made once during setup and never revisited. Because buckets are addressed by a predictable, human-chosen name (usually `company`, `company-prod`, `company-backups`, `company-assets`, etc.) rather than a random ID, they're brute-forceable, and because apps routinely reference them directly from client-side JS/HTML, they're also discoverable by just reading the target's own source.

Three independent misconfiguration axes to test once a bucket is found, in order of how commonly they're actually open:
1. **List** — can you enumerate bucket contents? (public read of the object list itself)
2. **Read** — can you download objects? (public read of object bodies)
3. **Write/Delete** — can you upload or remove objects? (public write — much rarer, much higher severity: stored XSS via uploaded HTML, defacement, or destructive data loss)

## Recon technique: multi-vector bucket discovery

Don't rely on one discovery method — buckets get referenced in different places depending on how the dev team wired them up. Run all of these against a target, not just one:

- **Manual/browser**: type `%c0` in the URL bar on a suspected AWS-hosted page to force an XML error response that confirms AWS hosting; view page source and search for `s3`; run the Wappalyzer extension to confirm AWS in the stack.
- **Google dorking**:
  ```
  site:s3.amazonaws.com "target.com"
  site:*.s3.amazonaws.com "target.com"
  site:s3.amazonaws.com intitle:"index of"
  (site:*.s3.amazonaws.com OR site:*.s3-external-1.amazonaws.com ...)
  ```
- **Subdomain + tech-detect pivot**:
  ```bash
  subfinder -d target.com -all -silent | httpx-toolkit -sc -title -td | grep "Amazon S3"
  subfinder -d target.com -all -silent | nuclei -t /nuclei-templates/http/technologies/s3-detect.yaml
  ```
- **JS-file URL extraction** (same katana crawl already run for `recon-scanning-toolkit`'s JS-secret hunting — just grep it for S3 URLs too instead of running a separate crawl):
  ```bash
  katana -u https://site.com/ -d 5 -jc | grep '\.js$' | tee alljs.txt
  cat alljs.txt | xargs -I {} curl -s {} | grep -oE 'http[s]?://[^"]*\.s3\.amazonaws\.com[^" ]*'
  ```
- **java2s3** — purpose-built JS parser for S3 references, including regional endpoints (`s3.ap-*.amazonaws.com`) that the plain grep above misses:
  ```bash
  subfinder -d target.com -all -silent | httpx-toolkit -o file.txt
  cat file.txt | grep -oP '(?<=https?:\/\/).*' > input.txt
  python java2s3.py input.txt target.com output.txt
  cat output.txt | grep -oP 'https?://[a-zA-Z0-9.-]*s3(\.dualstack)?\.ap-[a-z0-9-]+\.amazonaws\.com/[^\s"<>]+'
  ```
- **Bucket-name brute-force/permutation** (LazyS3 generates common naming variants of the company/target name):
  ```bash
  ruby lazys3.rb <COMPANY>
  ```
- **Custom wordlist from the target's own content** — Cewl crawls the site to build a target-specific wordlist (catches internal naming conventions generic wordlists miss), then S3Scanner tests each candidate name and reports its ACL:
  ```bash
  cewl https://site.com/ -d 3 -w file.txt
  s3scanner -bucket-file file.txt -enumerate -threads 10 | grep -aE 'AllUsers: \[.*(READ|WRITE|FULL).*]'
  ```
- **GitHub secret search** — org/repo search for hardcoded bucket names and credentials committed by mistake:
  ```
  org:target "amazonaws"
  org:target "aws_access_key"
  org:target "aws_secret_key"
  org:target "S3_BUCKET"
  ```
  See `github-recon-testing` for the much fuller dorking methodology (filename:/extension:/path:/language: operators, the full secret-category keyword taxonomy beyond just AWS, GitGraber/TruffleHog automation, and key-validation via Keyhacks) — this AWS-scoped list is a narrow subset worth keeping here for quick reference, but run the fuller sweep too.
- **Public pre-indexed bucket databases** — free, zero-effort pass across already-known-open buckets: `buckets.grayhatwarfare.com`, `https://osint.sh/buckets/`.
- **Chrome extension S3BucketList** — passively flags S3 URLs seen in network requests while you browse the target normally, no active step needed.
- **Cloudflare R2's `r2.dev` public-dev-URL feature** — R2 buckets (S3-API-compatible) support a one-click "Allow Access" toggle that exposes the bucket at a public `<bucket-id>.r2.dev` URL, meant only for quick local testing during development; teams routinely forget to disable it before shipping to production, leaving the bucket publicly readable via a guessable/leaked `r2.dev` subdomain indefinitely. Check any Cloudflare-fronted target's JS/HTML for a `.r2.dev` reference the same way you'd grep for `.s3.amazonaws.com`, and treat a hit exactly like an open S3 bucket for exploitation purposes below.

## Exploitation: unauthenticated AWS CLI against a discovered bucket name

Once you have a candidate bucket name (from any method above), test all three axes with the unauthenticated CLI (`--no-sign-request` skips needing your own AWS creds — it just sends the request as an anonymous principal, exactly what a real attacker would have):

```bash
# 1. LIST — "Access Denied" = private; a file listing back = public listing enabled
aws s3 ls s3://[bucketname] --no-sign-request

# Targeted sensitive-file search once listing works
aws s3 ls s3://[bucketname] --no-sign-request --recursive \
  | grep -E '\.env|\.pem|\.key|\.json|\.sql|\.db|id_rsa|\.passwd|\.csv|\.xlsx'

# 2. READ — pull everything down for offline triage
aws s3 cp s3://[bucketname]/ ./ --recursive --no-sign-request
# Scope discipline: a full recursive pull is fine for a small bucket, but on anything
# large treat it the same as a DB dump — pull ONE representative sensitive object first
# to prove impact, then decide whether a fuller pull is actually necessary/in-scope.
# Bulk-downloading a stranger's entire production bucket is itself a program-scope risk.

# 3. WRITE/DELETE — only test with explicit authorization (bug bounty scope must
#    cover destructive testing); an upload/delete that succeeds anonymously is a
#    much higher-severity finding than list/read alone
aws s3 cp file.txt s3://[bucketname] --no-sign-request
aws s3 rm s3://[bucketname]/file.txt --no-sign-request
```

**Impact framing for report:** list-only exposure of non-sensitive assets is typically Low/Info; list+read of files matching the sensitive-file grep above (credentials, DB dumps, PII exports) is High; any anonymous **write** capability is Critical regardless of what's currently stored — it means an attacker can plant a webshell/malicious file served from the target's own trusted domain, or defacement, or (if the bucket backs a CDN/static site) stored XSS served to every visitor. Always confirm CloudTrail/logging status is absent before concluding no detection would occur — that strengthens the report but isn't required to prove the vuln.

## Recorded techniques

### 1. Multi-source S3 bucket recon + unauthenticated CLI exploitation (baseline)
Source: [S3 Bucket Recon: Finding Exposed AWS Buckets Like a Pro](https://medium.com/bugbountywriteup/s3-bucket-recon-finding-exposed-aws-buckets-like-a-pro-106be5ab9e1d)

**Where:** any target with an AWS-backed stack — static asset hosting, user uploads, backups, log exports, or internal tooling that happens to reference S3 in client-side JS/HTML.

**Root cause:** bucket creator left public ACLs enabled or wrote an overly permissive bucket policy (e.g. `Principal: "*"` with `s3:GetObject`/`s3:ListBucket`/`s3:PutObject`), with no CloudTrail logging to catch the resulting access.

**Exploit steps:** run the full multi-vector discovery list above (manual, dorking, subdomain/tech-detect, JS extraction, java2s3, LazyS3, Cewl+S3Scanner, GitHub search, GrayhatWarfare/osint.sh, S3BucketList extension) to build a candidate bucket-name list, then run the unauthenticated AWS CLI exploitation steps (list → targeted grep for sensitive extensions → recursive download → write/delete test only if in scope) against each candidate.

**Impact framing for report:** see "Exploitation" section above — severity scales with what's exposed (list < read-sensitive-data < anonymous-write).

**Generalize beyond S3:** the same "predictable name + client-side reference + opt-in-private-but-often-misconfigured" pattern applies to Azure Blob Storage (`*.blob.core.windows.net`, tested with `az storage blob list --auth-mode login` or anonymous HTTP GET on a guessed container name) and Google Cloud Storage (`storage.googleapis.com/<bucket>`, tested with `gsutil ls -r gs://<bucket>` or a plain unauthenticated HTTP GET). Swap the discovery grep patterns (`blob.core.windows.net`, `storage.googleapis.com`) and the CLI tool, keep the same list→read→write escalation logic. Also cross-reference `recon-scanning-toolkit`'s subdomain-takeover technique (`subzy`) — a dangling CNAME pointing at a deprovisioned S3 bucket is a *different* bug (subdomain takeover via bucket re-registration) from the public-ACL misconfiguration covered here, but both start from the same "find S3 references" recon step.

### 2. Scoped-wordlist discipline + Alibaba OSS/DigitalOcean Spaces/Firebase RTDB coverage + nuclei-tagged mass scan + report structure
Source: [Cloud Misconfig Bounty Hunting 2026](https://securitycipher.com/2026/09/08/cloud-misconfig-bounty-hunting-2026/)

**Where:** any target's storage footprint, tested across the full multi-cloud provider list, not just AWS — Alibaba OSS and DigitalOcean Spaces are two S3-API-adjacent providers not otherwise named in this skill's generalize note, plus Firebase Realtime Database rules as a non-bucket sibling misconfiguration (full RTDB enumeration methodology already lives in `vibe-coded-app-testing`'s Firebase section — don't duplicate it here, just recognize `.json`-suffixed endpoints as the same "open storage" family when they turn up during a bucket sweep).

**Root cause:** same core theory as entry #1 — human-chosen, predictable resource names plus opt-in-private-but-often-misconfigured defaults — but this source adds an explicit recon-discipline point worth calling out on its own: "you do not start by spraying the entire internet, you start from in-scope roots." Generate candidate names only from company-name + common-suffix combinations (`backup`, `prod`, `assets`, `uploads`, `dev`, `staging`) actually seeded from the *target's own* passively-collected JS/mobile-config/subdomain data, rather than running a generic wordlist against the open internet — keeps a bucket-name brute-force sweep unambiguously inside program scope.

**Exploit steps:** probe each candidate name against the provider-specific unauthenticated URL pattern —
```bash
curl -s "https://{name}.s3.amazonaws.com/"
curl -s "https://storage.googleapis.com/{name}/"
curl -s "https://{name}.blob.core.windows.net/<container>?restype=container&comp=list"
```
(extend the same pattern to `{name}.oss-<region>.aliyuncs.com` for Alibaba OSS and `{name}.<region>.digitaloceanspaces.com` for DigitalOcean Spaces) — a bare `200` with an `<ListBucketResult>` (S3/GCS) or `<EnumerationResults>` (Azure) XML body in the response confirms unauthenticated listing access without needing the AWS CLI at all. Once a hit is confirmed, run `nuclei -l live-storage.txt -tags exposure,misconfig,firebase,s3` across the full list of confirmed-live storage endpoints for a fast automated second pass (cross-reference `recon-scanning-toolkit`'s custom-Nuclei-template section for writing a bespoke tag/template if a provider isn't covered by stock templates), then `gitleaks detect --source bucket-dump --no-git --no-banner -v` on whatever sample objects were pulled.

**Impact framing:** the source's recommended report structure is a good checklist to lift wholesale: title naming the exact asset + data type, the exact hostname/bucket/Firebase URL, reproduction steps using a plain unauthenticated GET with a *redacted* XML/JSON sample (never a raw unredacted dump pasted into a report), explicit data classification (PII/credentials/backups), and remediation phrased as block-public-ACLs + deny-by-default rules + secret rotation (not just "make it private"). Severity swings hard on two factors: confidentiality impact of what's exposed, and whether a *scope change* applies — i.e. whether the exposed data itself contains live credentials (Stripe/Slack/cloud keys in a `.env.production`) that grant access beyond the storage bucket itself, which is the detail most likely to push a finding from High to Critical.

**Generalize note:** extends entry #1's S3/Azure/GCS generalize note with two more S3-API-compatible providers (Alibaba OSS, DigitalOcean Spaces) — same discovery grep pattern, swap only the hostname suffix. The "pull one sample object, then scan it — never the whole bucket" discipline reinforces the scope-discipline caveat now added to the Exploitation section above.

<!-- Add new recorded techniques below this line as new cloud-storage-bucket writeups are processed. Keep the same structure: Where / Root cause / Exploit steps / Impact framing / Generalize note. -->
