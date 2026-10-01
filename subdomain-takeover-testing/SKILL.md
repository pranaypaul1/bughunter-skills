---
name: subdomain-takeover-testing
description: Subdomain takeover hunting — finding a target's DNS records (CNAME primarily, also NS/MX) still pointing at a third-party service (S3, Heroku, GitHub Pages, Azure, etc.) the target has since deprovisioned/deleted, then claiming that same resource name on the provider to serve content on the target's own trusted subdomain. Covers detection (Subzy/Subjack automated scanning against the "Can I Take Over XYZ?" vendor fingerprint database), safe non-destructive verification/proof-of-control methodology, which providers are actually vulnerable vs. hardened (domain-verification requirement is the deciding factor), and the full post-takeover exploitation escalation surface once a claim succeeds — OAuth/SSO redirect-token theft, cross-subdomain cookie-domain-scope theft, CSRF via SameSite=Lax subdomain trust, and CORS/CSP allowlist bypass via the newly-controlled subdomain. Use this during Phase 1/3 (Recon/Vulnerability Testing — Info disclosure/Access control) of bughunting-workflow against the full subdomain list from Phase 1 enumeration, on every target — it's cheap, high-confidence, and costs nothing extra once the subdomain list already exists. Also trigger on mentions of subdomain takeover, dangling CNAME, Subzy, Subjack, Can I Take Over XYZ, or abandoned cloud resource.
---

# Subdomain Takeover Testing

Technique library for subdomain takeover. Each dated entry below is a validated technique pulled from a real writeup — add new entries here (don't create a new skill) whenever a new writeup covers a different provider, verification trick, or post-takeover escalation than what's already recorded.

## Core theory

A subdomain takeover happens because two independent facts drift out of sync: the target's DNS still has a record (usually a `CNAME`) pointing at a third-party service's hostname, but the target's *account/resource* on that service has since been deleted, renamed, or never claimed in the first place. The vulnerability only exists on providers that let a customer choose their own resource name/subdomain **and don't verify that the customer actually controls the DNS pointing at it before activating that name** — an attacker who notices the dangling DNS record can simply register the *same* resource name on the provider, and because the provider never checked domain ownership, the target's DNS now serves the attacker's content on the target's own trusted subdomain.

This single fact — **does the provider require domain verification before letting you claim a name?** — is the entire dividing line between vulnerable and hardened providers:
- **Vulnerable pattern** (e.g. AWS S3 static-site hosting): create a bucket named exactly `subdomain.target.com`, no proof you own `target.com`'s DNS required — if the target's CNAME still points there and nobody else has claimed that bucket name, you're served.
- **Hardened pattern** (e.g. HubSpot, Atlassian StatusPage): the provider requires a DNS TXT record (or auto-generates an opaque hostname you can't choose) to prove domain control *before* activating the custom hostname — dangling DNS alone isn't enough to claim it.

## Detection

**Automated scanning against the full Phase 1 subdomain list:**
```bash
subzy run --targets subdomains.txt --concurrency 100 --hide_fails --verify_ssl
subjack -w subdomains.txt -t 100 -timeout 30 -ssl -c fingerprints.json -v
```
Both tools check every subdomain's CNAME/response fingerprint against a database of known vulnerable-provider signatures. **"Can I Take Over XYZ?"** (community-maintained GitHub repo) is the canonical fingerprint reference both tools' databases are built from — worth checking directly when a hit looks provider-specific/unusual, since the repo tracks provider-behavior changes (a provider that used to be vulnerable and later added domain verification) more current than a tool's bundled fingerprint list might be.

**Manual confirmation of a flagged hit:**
1. `dig CNAME <subdomain>` to see exactly what third-party hostname it points at.
2. Visit the subdomain directly — a provider-specific "not found"/"no such app"/"repository not found" error page (rather than a generic DNS failure or the target's own branded 404) is the signature that the *provider* is reachable and has no resource claimed under that name, i.e. the dangling condition is real and current, not a stale scan result.
3. Check whether that specific provider requires domain verification (via the "Can I Take Over XYZ?" reference) before spending any further effort — if it does, this is a false positive regardless of what the automated scanner flagged.

## Safe, non-destructive proof-of-control methodology

Once a takeover looks claimable, **don't** serve a defacement page or anything resembling real target content — the standard, program-accepted PoC is minimal and reversible:
1. Register the abandoned resource name on the provider (bucket, app, repo — whatever the dangling CNAME points at).
2. Publish a bare, harmless page containing a **non-guessable random key** in a hidden HTML comment (e.g. `<!-- intigriti-poc-<random-token> -->`) — proves you control what the subdomain now serves without publishing anything that could be mistaken for a real defacement or a phishing page.
3. Screenshot/curl the live subdomain showing your content + the random key, and include that exact key value in the report as proof it wasn't fabricated after the fact.
4. **Most programs expect you to immediately relinquish/delete the claimed resource once the report is filed** — state in the report that you've done so (or will on request), since holding a claimed subdomain open longer than necessary to prove the bug is itself a residual risk the program will want closed fast.

## Post-takeover exploitation — the escalation surface once a claim succeeds

A bare takeover PoC (a hidden-comment page) is often accepted as its own finding, but the *real* severity ceiling depends on what the trusted subdomain is actually used for — walk this checklist before finalizing severity:

**1. OAuth/SSO redirect-token theft** — if the takeover-able subdomain was ever registered as a valid OAuth `redirect_uri`/callback URL for any app the target integrates with, an attacker now controls that callback and can capture authorization codes/tokens sent to it in the URL (query string or fragment) — cross-reference `oauth-redirect-uri-bypass-testing` for the exploitation mechanics once this specific chain is confirmed.

**2. Cross-subdomain cookie theft via domain-scoped cookies** — when the target sets cookies with `Domain=.example.com` (or `*.example.com`) rather than scoping to the exact hostname, those cookies are automatically sent to *every* subdomain, including the one an attacker just took over — the attacker's page on the claimed subdomain receives the victim's session cookie on their very next visit to *anything* under that domain, no XSS required at all, purely from the browser's own cookie-scoping rules.

**3. CSRF via `SameSite=Lax` cross-subdomain trust** — `SameSite=Lax` (the browser default when unset) still allows a cookie to ride along on top-level cross-subdomain navigation; a takeover-controlled subdomain can host a CSRF PoC that submits a state-changing request to the real app, with the victim's cookies attached, purely because both are technically the "same site" under the `SameSite` definition.

**4. CORS allowlist bypass** — if the target's CORS policy trusts `*.example.com` (see `cors-misconfig-testing`'s wildcard-subdomain-trust entry), a takeover of *any* subdomain under that wildcard becomes a valid CORS-bypass origin — chain directly into that skill's credentialed-read exploitation once confirmed.

**5. CSP allowlist bypass / supply-chain risk** — if the target's `Content-Security-Policy` allowlists the takeover-able subdomain as a trusted script/resource source (or, independent of CSP, if the main app actually *loads* a JS/CSS resource directly from that subdomain in production), taking it over lets the attacker serve **arbitrary attacker-controlled JavaScript directly into the main application's trusted context** — this is the single highest-severity escalation in this list, since it's not "read some data cross-origin," it's full script execution on the real app for every visitor, a genuine supply-chain compromise rather than an isolated subdomain defacement.

**Severity framing:** always check all five before writing up — the bare takeover (an unused, unlinked subdomain with none of the above) is a real but modest finding; any of #1-5 confirmed turns it into account-takeover/supply-chain-severity, and #5 specifically deserves explicit supply-chain-risk language in the report (make the point that any visitor to the *main* app, not just the subdomain, is affected).

## Recorded techniques

### 1. Detection/verification methodology + vendor-vulnerability decision rule + full post-takeover escalation checklist (baseline)
Source: [Hunting Down Subdomain Takeover Vulnerabilities](https://www.intigriti.com/researchers/blog/hacking-tools/hunting-down-subdomain-takeover-vulnerabilities)

**Where:** every target's full subdomain list, as a standing Phase 1 parallel check — dangling DNS costs nothing extra to test for once the subdomain enumeration list already exists.

**Root cause:** see Core theory above — the vulnerable/hardened split is entirely about whether the third-party provider requires domain-ownership verification before activating a custom-named resource.

**Exploit steps:** run Subzy/Subjack against the full subdomain list; manually confirm each hit against the "Can I Take Over XYZ?" reference and a live provider-error-page check; claim the resource and publish the minimal non-guessable-key PoC page; walk the 5-point post-takeover escalation checklist above before finalizing severity; relinquish the claimed resource promptly once the report is filed.

**Impact framing:** see the Severity framing note above — don't stop at "I claimed the subdomain," always test whether the trusted-domain status the subdomain inherits (cookies, CORS, CSP, OAuth redirect trust) turns it into a much larger chain.

**Generalize note:** this replaces what was previously just a single `subzy` command with no verification or escalation methodology in `recon-scanning-toolkit` — that skill's subdomain-takeover line now points here for the full technique; keep using its `subzy` command as the Phase 1 detection step, and bring the rest of this skill's methodology in from the moment a hit is confirmed.

### 2. Heroku dangling-CNAME takeover — worked HackerOne example with exact CLI chain + severity-downgrade caveat
Source: [How Did I Find a Subdomain Takeover in a HackerOne Program](https://freedium-mirror.cfd/https://medium.com/@jakalalokesh07/how-did-i-find-a-subdomain-takeover-in-a-hackerone-program-2f2ba3b3adf6)

**Where:** a HackerOne program's subdomain whose CNAME still pointed at a Heroku app hostname (`*.herokuapp.com`) after the underlying Heroku application had been deleted — found by DNS enumeration during general recon rather than a mass Subzy/Subjack sweep, with the researcher's framing being "don't just look at the website, look at what the website depends on" (i.e. deliberately check every third-party service a target's DNS references, not just the rendered site).

**Root cause:** same dangling-CNAME/deprovisioned-resource pattern as Core theory — Heroku app names are attacker-claimable (`heroku create <name>`) with no domain-ownership verification, so once the original app is deleted the name is free for anyone to register.

**Exploit steps:**
1. `dig target.example.com +short` to resolve the CNAME target and confirm it points at a Heroku hostname.
2. `curl -I http://target.example.com` to check the live HTTP response/headers for a Heroku-specific "no such app"-style error, confirming the app-name slot is actually empty right now (not a stale scan result).
3. `heroku login` (CLI already installed/verified via `heroku --version`), then `heroku create <application-name>` using the exact orphaned app name from the CNAME — this alone is the proof-of-claim step; the create succeeding confirms the takeover is real.
4. `heroku buildpacks:set heroku/static` + git-based deploy to prepare a minimal HTML PoC page — deployment was blocked by Heroku's own account-verification gate, so the researcher stopped there rather than pushing further, explicitly noting: "I didn't want to exaggerate the finding... I documented exactly what I could prove."

**Impact framing:** reported attack vectors were phishing under the trusted domain, brand impersonation, malicious content hosting, and subdomain-reputation abuse — no deeper chain (no OAuth-redirect/cookie-domain/CORS/CSP escalation per the 5-point checklist above) was demonstrated or claimed. Submitted with DNS evidence, CNAME details, and remediation guidance; H1 triage set initial severity **High (7.5)**, then downgraded to **Low (2.6)** at resolution, paying a **$100** bounty — a concrete data point that a bare, unescalated takeover PoC (no chain into #1-5 above) tends to get triaged down hard from whatever CVSS-style severity the initial CNAME-hijack template suggests, even when the claim itself is fully proven.

**Generalize note:** reinforces the existing methodology's "always test the 5-point escalation checklist before finalizing severity" guidance from entry #1 — this is the negative case showing what happens (severity crushed to Low, $100) when that escalation work *isn't* done. Also a second worked example of the "provider CLI `create`-equivalent command IS the proof-of-claim" pattern for PaaS-style providers (Heroku here) alongside S3/bucket-style providers already covered in Core theory.

<!-- Add new recorded techniques below this line as new subdomain-takeover writeups are processed. Keep the same structure: Where / Root cause / Exploit steps / Impact framing / Generalize note. -->
