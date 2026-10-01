---
name: vibe-coded-app-testing
description: Security testing methodology for "vibe-coded" apps — products built largely by AI coding agents/platforms (Lovable, Bolt.new, Replit Agent, Cursor, v0, base44, etc.) that ship fast, working UIs while skipping backend security fundamentals. Covers finding these targets at scale (platform-specific dorking/Shodan), the recurring root-cause pattern (AI optimizes for "it works" not "it's secure," so authorization logic that should live server-side gets left client-side or in a BaaS's default-open config), and the specific high-yield checks: hardcoded API keys in JS bundles, Supabase Row-Level-Security (RLS) misconfiguration via anon/service_role keys, Firebase Realtime DB/Storage public read-write, client-side-only auth, exposed .env/debug endpoints, and hallucinated-package supply-chain squatting. Use this during Phase 1/3 (Recon/Vulnerability Testing) of bughunting-workflow the moment a target fingerprints as AI-generated (Lovable/Bolt/Replit/v0 branding or URL pattern, `.supabase.co`/`firebaseConfig` calls visible in DevTools, suspiciously fast/generic UI). Also trigger on mentions of vibe coding, vibe-coded app, Lovable, Bolt.new, Replit Agent, Supabase RLS, Firebase misconfiguration, service_role key, or slopsquatting/hallucinated package.
---

# Vibe-Coded App Testing

Technique library for hunting on apps built primarily by AI coding agents rather than human engineering teams. Each dated entry below is a validated technique pulled from a real writeup/source — add new entries here (don't create a new skill) whenever a new vibe-coding-focused writeup covers a *different* platform, BaaS, or bypass than what's already recorded. This skill is a **target-category** lens, not a new vuln class per se — where a check below overlaps an existing vuln-class skill (IDOR, XSS, SQLi, GitHub secrets, cloud storage), it says so and defers to that skill for the deep technique; this skill holds what's genuinely specific to AI-generated apps and their default BaaS backends (Supabase/Firebase).

## Core theory

AI coding agents (Lovable, Bolt.new, Replit Agent, Cursor, v0, base44, and similar "prompt → deployed app" platforms) are trained/optimized to produce a working, demoable product fast. That objective function systematically drops security work that has no visible effect on "does the app function":

1. **Authorization gets left in the frontend.** The agent writes `if (user.role === 'admin') showAdminButton()` because that's what makes the demo look right, and never adds the matching server-side check — because nothing in the prompt or the visible UI surfaces the absence of one.
2. **BaaS defaults get shipped as-is.** Supabase/Firebase ship with permissive-by-default or empty-by-default access rules; setting them up correctly requires knowing to do it. An agent wiring up a working CRUD app has no incentive to also write Row-Level-Security policies unless explicitly told to — and the resulting anon key + no-RLS combination is functionally a fully public database.
3. **Secrets get placed for convenience, not security.** Client-side code needs *some* key to talk to the BaaS; the path of least resistance (and least prompt-engineering) is to hardcode it directly in the bundle rather than route it through a proper backend proxy.
4. **The agent invents packages that don't exist.** LLMs hallucinate plausible-sounding package names; attackers watch for this pattern and pre-register those exact names on NPM/PyPI with malicious payloads ("slopsquatting") so the next agent (or a retry of the same one) that hallucinates the same name pulls in attacker code.

**Recon signal:** the app "feels" AI-generated — generic/templated UI, built in an unusually short time per the company's own marketing, or the URL/branding directly names one of the platforms above. Confirm via tech fingerprinting (below) rather than vibes alone.

## Trigger technique: finding & fingerprinting targets

**Platform dorking (Google):**
```
site:lovable.app
site:bolt.new
site:replit.app inurl:app
"built with lovable"
"built with bolt.new"
```

**Shodan:**
```
shodan search "lovable" http.title
shodan search "built with cursor" http.html
```

**GitHub dorking for leaked BaaS keys tied to a target** (cross-reference `github-recon-testing` for the full dorking/tooling playbook — this is the vibe-coding-specific query set):
```
"SUPABASE_SERVICE_ROLE_KEY" language:javascript
"NEXT_PUBLIC_SUPABASE_KEY" path:.env
"sk-proj-" site:github.com
site:github.com "[target-company]" ".env" OR "SUPABASE_KEY" OR "DATABASE_URL"
```

**Tech-stack fingerprinting on a specific target:**
1. Open DevTools → Network tab, reload, filter for `.supabase.co` or `firebaseio.com`/`firebasestorage` requests.
2. DevTools → Sources, pretty-print (`{}`) any minified JS bundle, then search the bundle text for: `supabase.co`, `apikey`, `NEXT_PUBLIC`, `eyJhbGciO` (JWT prefix), `sk-` (OpenAI-style key), `firebaseConfig`, `stripe`.
3. Check response headers for platform fingerprints: `curl -I https://target-app.com` — look at `X-Powered-By`, `Server`, `via`.

## Recorded techniques

### 1. Full vibe-coded-app vuln sweep (secrets, BaaS misconfig, client-only auth, supply chain)
Source: [Hacking Vibe-Coded Apps: The Bug Bounty Hunter's Complete Guide](https://systemweakness.com/hacking-vibe-coded-apps-the-bug-bounty-hunters-complete-guide-to-finding-security-issues-in-60953aa5947e)

**Where:** any target that fingerprints as built on Lovable/Bolt.new/Replit Agent/Cursor/v0/similar, or that exposes a Supabase/Firebase backend directly to the client.

#### 1a. Exposed API keys in JS bundles
**Root cause:** agent hardcodes API keys directly in frontend code with no sanitization pass.
**Detection:** grep bundle text (see fingerprinting above) for `sk-` (OpenAI), `AIza` (Google), `eyJhbGci` (JWT), `service_role` (Supabase — critical, this key bypasses RLS entirely).
**Validate a found key:**
```bash
curl -X GET "https://[project-id].supabase.co/rest/v1/" \
  -H "apikey: [FOUND_KEY]" \
  -H "Authorization: Bearer [FOUND_KEY]"
```
**Impact:** direct database access if it's a `service_role` key; billing/quota abuse for third-party AI/cloud API keys.

#### 1b. Supabase RLS misconfiguration
**Root cause:** table has no Row-Level-Security policy at all, or the policy checks `auth.role()` (just "is this any authenticated user") instead of `auth.uid()` (is this *this* user's own row) — both leave every row readable/writable by anyone holding the (often client-exposed) anon key.
**Testing:**
```bash
# Unauthenticated/anon-key access to a table that should require ownership
curl -X GET "https://[project].supabase.co/rest/v1/users?limit=5" \
  -H "apikey: [ANON_KEY]" \
  -H "Authorization: Bearer [ANON_KEY]"

# Enumerate every table exposed via the auto-generated OpenAPI schema
curl -X GET "https://[project].supabase.co/rest/v1/" \
  -H "apikey: [ANON_KEY]" \
  -H "Authorization: Bearer [ANON_KEY]"
```
**IDOR variant** (cross-reference `advanced-access-control-testing` for the general methodology): create `user_a`/`user_b` test accounts, log in as A, capture the API request for A's own resource, replay it as B's session with A's resource ID in the URL/body — a 200 with A's data back confirms broken RLS/IDOR.
**Impact:** this class was CVE-2025-48757 — reportedly affected 170+ Lovable-built apps, exposing full database dumps including medical records and bank account numbers. This is the single highest-yield check on any Supabase-backed vibe-coded app; run it first.

#### 1c. Firebase misconfiguration
**Root cause:** Realtime Database/Firestore/Storage security rules left at `true`/public (the default for a quick prototype), or written to check *authentication* without checking *authorization* (any logged-in user, not just the right one).
**Detection:** search JS bundle for a `firebaseConfig` object (`projectId`, `databaseURL`, `storageBucket` fields); also try Google dorking (`site:*.firebaseio.com "<target>"`, `site:*.firebasestorage.app "<target>"`) and GitHub code search for an exposed config committed by mistake — same discovery angle as `github-recon-testing`. For a mobile client specifically, the equivalent discovery pass is `mobile-app-testing`'s strings-grep/jadx APK extraction (`strings app.apk | grep firebaseio.com`, or grep `res/values/strings.xml` in a full decompile) — same "hardcoded config URL leaking from a compiled client artifact" pattern, just the APK's compiled strings instead of a JS bundle.
**Testing — Realtime Database:**
```bash
# Read
curl "https://[project]-default-rtdb.firebaseio.com/.json"

# Write (use an obviously-scoped test key, never overwrite real data)
curl -X PUT "https://[project]-default-rtdb.firebaseio.com/test_hunter.json" \
  -d '{"test": "security_check"}'
```
**Testing — Firestore** (the newer, document-based Firebase DB — separate REST API and separate security-rules language from Realtime DB, test both when a project uses either):
```bash
# Read a collection, anonymous (no Authorization header at all)
curl "https://firestore.googleapis.com/v1/projects/<PROJECT_ID>/databases/(default)/documents/<collection>"

# Create a document (POST) — repeat with and without a valid user ID token to separate anonymous-open from authenticated-but-unauthorized
curl -X POST "https://firestore.googleapis.com/v1/projects/<PROJECT_ID>/databases/(default)/documents/<collection>" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <USER_ID_TOKEN>" \
  -d '{"fields": {"fieldName": {"stringValue": "value"}}}'

# Update an existing document (PATCH) — test whether you can modify a document you don't own
curl -X PATCH "https://firestore.googleapis.com/v1/projects/<PROJECT_ID>/databases/(default)/documents/<collection>/<docID>" \
  -H "Authorization: Bearer <USER_ID_TOKEN>"
```
**Four security-rules misconfiguration patterns worth recognizing** (if you get read access to a project's `firestore.rules`/`database.rules.json` via a leaked config/GitHub search, or are inferring behavior from REST responses):
```
// 1. Unrestricted read/write — the "quick prototype" default, never tightened before shipping
match /contact-form-data/{document=**} {
  allow read, write;
}

// 2. Authentication checked, authorization not — any logged-in user can do admin-level operations
allow write: if request.auth != null;   // missing a role/claim check (e.g. request.auth.token.admin == true)

// 3. No field-level validation on create/write — lets an attacker inject arbitrary field values/types
allow create: if request.auth != null;  // no validation the submitted 'fields' match expected shape/values

// 4. Flawed ownership check — looks correct but the ownership field was attacker-set at creation time
allow delete: if resource.data.userId == request.auth.uid;
// ^ only safe if 'userId' was set server-side on create; if the client sets it, an attacker
//   just writes their own uid into someone else's intended-victim document at creation, or
//   creates a decoy document with a victim's uid to test the check's actual enforcement point.
```
**Storage CORS misconfiguration** — check the bucket's CORS config (or infer it from browser preflight responses) for an overly-permissive policy:
```json
{ "origin": ["*"], "method": ["GET", "POST", "DELETE"], "responseHeader": ["*"] }
```
A wildcard `origin` combined with `DELETE`/`POST` methods lets any attacker-hosted page perform authenticated file operations against the bucket cross-origin if a victim's session/token can be leveraged — cross-reference `cors-misconfig-testing` for the general exploitation pattern once this is confirmed.
**Testing methodology — test in this order, don't stop at the first result:** (1) anonymous — no credentials at all, to find pure public-access rules; (2) authenticated with a valid but low-privilege user token, to find authentication-without-authorization gaps; (3) per-collection/per-document-path — Firebase rules are granular per path, so a locked-down `users/{uid}` collection tells you nothing about whether `orders/{orderId}` or `admin-config/{doc}` are equally locked down; (4) all four CRUD operations separately (read/create/update/delete) on each path, since it's common for a rule to correctly gate `write` but forget `delete`, or vice versa.
**Real-world reference point:** a dating app's Firebase backend left storage/database rules permissive enough that ~72,000 user-uploaded images were scraped and leaked — cited as the scale this class of misconfiguration can reach when it's Storage (media) rather than just Firestore/Realtime DB (structured data) that's exposed.
**Impact:** unauthenticated/under-authorized read → PII/business-data exfiltration; write → data injection (fake records, tampered prices/discounts) or privilege escalation (self-assigning an admin role/claim if the rules let a client set that field); delete → mass-deletion DoS.

#### 1d. Broken authentication (client-side only)
**Root cause:** the agent wired an `if (isAdmin)` UI check but never added the matching server-side authorization on the API route it gates.
**Testing:** replay the admin/gated API call directly, stripped of any session/auth header or with a low-privilege session's token, against paths like `/admin`, `/api/admin/*`, `/dashboard`:
```bash
curl -X GET "https://target-app.com/api/admin/users" -H "Authorization: Bearer [LOW_PRIV_TOKEN]"
```
**Impact:** direct access to admin operations/data with no privilege check at all.

#### 1e. XSS via dangerouslySetInnerHTML
**Root cause:** React/Next component renders user input through `dangerouslySetInnerHTML` with no DOMPurify/sanitization — a very common agent-generated pattern for "rich text" features.
**Detection:** grep bundle for `dangerouslySetInnerHTML`.
**Payloads** (cross-reference `blind-xss-testing`/`csp-misconfig-xss-testing` for broader XSS methodology):
```html
<img src=x onerror=alert(document.domain)>
<svg/onload=alert(1)>
"><script>alert(document.domain)</script>
```
**Impact:** stored XSS → session hijacking/credential theft.

#### 1f. SQL injection
**Root cause:** rare on Supabase/Firebase apps (their client SDKs are parameterized by default), but shows up when the agent adds a custom raw-SQL backend route (Postgres function, custom Express/FastAPI layer) with string concatenation.
Cross-reference `sqli-waf-bypass-testing` for full technique depth; quick triage inputs: `' OR '1'='1`, `'; SELECT sleep(5)--`, `1 UNION SELECT null,null,null--` against search/filter/sort parameters.

#### 1g. Exposed environment variables / debug endpoints
**Root cause:** `.env` committed to a public repo, or framework debug routes left enabled in production.
**Endpoints to sweep:**
```bash
curl https://target.com/.env
curl https://target.com/.env.production
curl https://target.com/api/debug
curl https://target.com/api/config
curl https://target.com/__nextjs_original-stack-frames
```
Cross-reference `github-recon-testing` for the repo-side leak hunt (TruffleHog/gitleaks/GitGraber) once a `.env` or key pattern is confirmed live:
```bash
trufflehog github --repo [URL]
gitleaks detect --source [path] -v
```

#### 1h. Open cloud storage buckets
Cross-reference `cloud-storage-bucket-testing` for the general S3/GCS methodology. Supabase Storage-specific check:
```bash
curl "https://[project].supabase.co/storage/v1/object/list/[bucket-name]" \
  -H "apikey: [ANON_KEY]"
```
**Impact framing from source:** one documented case exposed 70,000+ images including driver's licenses and passports via a public Supabase Storage bucket.

#### 1i. Hallucinated package dependencies ("slopsquatting")
**Root cause:** the AI agent's suggested `package.json`/`requirements.txt` entry doesn't exist on the real registry; an attacker has pre-registered that exact hallucinated name with a malicious payload, betting that other agents/retries will hallucinate the same name and pull it in.
**Detection:** for every dependency in `package.json`, check `npmjs.com/package/[name]` (or PyPI equivalent). Red flags: zero downloads, no README, no version history, suspiciously recent publish date relative to when the name would plausibly have been "invented."
**Impact:** supply-chain compromise → arbitrary code execution in the app's build or runtime.
**Distinct from real dependency confusion:** cross-reference `supply-chain-attack-recon` for the sibling-but-different technique where the leaked package name is *real* (a genuine internal/private package an attacker discovers via a leaked `.npmrc`/JS bundle/CI config and republishes publicly), rather than an LLM-hallucinated name an attacker pre-registered speculatively — different discovery path, same underlying trust-transference root cause.

**Impact/report framing:** Critical = RCE or full unauthenticated database access (RLS bypass, service_role key, Firebase public write). High = auth bypass, IDOR/cross-tenant read. Medium = XSS, SQLi. Low = pure info disclosure (exposed non-privileged key/config). Always demonstrate with the *minimum* access needed (one record, not a full dump) — this class of bug makes it trivially easy to over-collect, and doing so turns a clean report into a scope violation.

**Generalize beyond this article:** any BaaS-first stack (Supabase, Firebase, Appwrite, PocketBase, Convex) shipped by a low-code/AI-agent builder should get this same sweep — hardcoded key → validate key scope → enumerate schema via the BaaS's own auto-generated API → test both horizontal (cross-user) and vertical (role) authorization on every table/collection the schema reveals.

<!-- Add new recorded techniques below this line as new vibe-coding-focused writeups are processed. Keep the same structure: Where / Root cause / Exploit steps / Impact framing / Generalize note. -->
