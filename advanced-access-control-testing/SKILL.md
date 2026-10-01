---
name: advanced-access-control-testing
description: Advanced Broken Access Control / IDOR techniques for targets that already use unpredictable IDs (GUIDs/UUIDs) instead of sequential integers — GUID leakage side-channels, cross-tenant BOLA, blind IDOR detection via timing/state-change side channels, WAF/access-control-filter bypass via parameter pollution and JSON type juggling, and discovering missing server-side authorization by unhiding client-side-disabled/hidden DOM elements. Use this during Phase 2/3 (Enumeration/Vulnerability Testing — Access Control) of bughunting-workflow whenever a target uses GUIDs/UUIDs for object IDs (so naive `id=1`→`id=2` IDOR testing won't work), has multi-tenant/B2B architecture, returns ambiguous responses (200 with empty body, no visible state change) to an ID-swap attempt, or has visibly disabled/grayed-out/hidden UI elements. Also trigger on mentions of IDOR, BOLA, broken access control, cross-tenant, blind IDOR, parameter pollution, type juggling, GUID/UUID leakage, disabled/hidden elements, or unhide bookmarklet.
---

# Advanced Broken Access Control / IDOR Testing

General technique library for finding access-control bugs on modern applications where simple ID-guessing (`user_id=100` → `101`) no longer works because IDs are unpredictable GUIDs. Each dated entry below is a validated technique pulled from a real writeup/source — add new entries here (don't create a new skill) whenever a new BAC/IDOR writeup covers a *different* leakage vector, bypass method, or side channel than what's already recorded.

## Core theory

Unpredictable IDs (GUIDs/UUIDs) are **not** an access control — they're obscurity. If the authorization check on the object-fetch endpoint is missing or wrong, the vulnerability is identical to a classic IDOR; the only extra step is *obtaining* a valid ID for an object you don't own, since you can no longer brute-force it. So advanced BAC hunting splits into two problems:

1. **Get a valid foreign-object ID** — via a leak somewhere the developer forgot to scrub it (mobile traffic, exports, error messages).
2. **Prove the access-control check is missing/broken** — via direct swap, cross-tenant fetch, blind side channels when the response gives no visible signal, or bypassing an access-control filter that does exist.

Maps to OWASP API1:2023 (BOLA) and Bugcrowd VRT categories "Cross-Tenant PII Leakage/Exposure" and "Modify/View Sensitive Information (Complex Object Identifiers)" — both are typically P1/P2.

## Trigger technique: don't guess IDs, harvest them

Before testing any authorization logic, actively hunt for leaked GUIDs rather than assuming an endpoint is unreachable because the ID is unpredictable:

- **Mobile API traffic** — proxy the mobile app; it often fetches full JSON objects (team members, org roster) and only renders a subset in the UI. The unrendered fields carry "cousin" object GUIDs (same org/group/team).
- **Export features** — trigger "Export to CSV/PDF" style features; the export payload/metadata frequently contains every user/object GUID in the org, not just the current user's.
- **Error messages** — trigger duplicate-registration or similar validation errors (e.g. register with an email that already exists); a poor implementation echoes the target's ID back: `{"error": "User already exists", "existing_user_id": "771e8400-..."}`.
- **Tooling:** Burp Suite BChecks can be scripted to auto-highlight regex matches for UUID/GUID patterns across all proxied HTTP responses, instead of manually scanning traffic.

## Methodology: baseline-then-single-variable testing + evidence export for reports
Source: [Part 2 — A Real-World Recon Workflow, One Command, Clean Results](https://medium.com/bug-bounty-hunting-a-comprehensive-guide-in/part-2-a-real-world-recon-workflow-one-command-clean-results-989d73ffe14a)

Applies across every technique in this skill, not tied to one specific entry — a discipline for running the actual test cleanly once a candidate object-reference parameter is found (via any recon pipeline: subfinder→httpx→katana/waymore-style URL collection, or manual browsing):

1. **Identify object references** — any ID appearing in a URL path segment, query parameter, or JSON body field.
2. **Establish a baseline** — record the *authorized* request's status code, response length, and response data before touching anything.
3. **Modify exactly one variable** — swap or increment only the object-reference ID, leaving every other request detail (headers, cookies, other parameters) untouched. Changing more than one thing at a time makes it ambiguous which change caused a behavior difference.
4. **Confirm unauthorized access** — a response containing another user's/tenant's actual data (not just a 200 with generic/empty content — see this skill's blind-IDOR entry above for that ambiguous case) confirms the bug.
5. **Validate across authentication contexts** — repeat as a different authenticated user, and unauthenticated if the endpoint might allow it, to establish the full scope of who's affected.
6. **Stop once capability is proven** — don't continue modifying/deleting other users' data once unauthorized access is demonstrated; a single clean before/after pair is sufficient evidence.

**Evidence-export convention for the report itself:** save the exact four artifacts as separate files rather than only screenshotting or describing the result — `request-original.txt`, `request-modified.txt`, `response-original.txt`, `response-modified.txt`. This gives a triager a complete, independently-reproducible record without needing to trust a description of what changed, and is the same underlying discipline Burp's own "save item" feature is built around.

**Framing worth reusing directly in a report or when explaining a finding:** "Automation finds surface area. [Burp/manual testing] proves impact." — the recon pipeline (subfinder/httpx/katana/nuclei/ffuf) is what surfaces the *candidate* endpoint and parameter; only the manual baseline-vs-modified comparison above actually proves the authorization bug exists. Don't report "found via automated scan" as if the scanner itself confirmed impact — the confirmation step is always this manual one.

## Recorded techniques

### 1. Cross-tenant BOLA via missing tenant-scoping on GUID lookup
Source: [Beyond IDOR: The Guide to Advanced Broken Access Control](https://medium.com/@Aacle/beyond-idor-the-guide-to-advanced-broken-access-control-85b7a201baa7)

**Where:** B2B/SaaS apps with a "Tenant" concept (Slack/Jira/Salesforce-style) — any object endpoint scoped to the current org/workspace, e.g. `GET /api/v1/labels/{id}`.

**Root cause:** the backend query filters only on object ID, not also on tenant:
```sql
-- vulnerable
SELECT * FROM labels WHERE id = :input_id
-- correct
SELECT * FROM labels WHERE id = :input_id AND tenant_id = :current_user.tenant_id
```
This is especially common around "global"/shared objects (system tags, default categories) that developers accidentally implement using the same table/endpoint as private per-tenant objects.

**Exploit steps:**
1. Find any object-fetch/edit endpoint keyed by GUID (labels, tags, categories, shared resources).
2. Harvest a foreign-tenant object ID using the leakage vectors above, or fuzz IDs if the app exposes any listing that touches cross-tenant "global" objects.
3. Request the object as an authenticated user of a *different* tenant; a 200 with real (non-default) data confirms missing tenant scoping.

**Impact framing:** Cross-Tenant PII Leakage/Exposure — Bugcrowd VRT Priority 1, maps to OWASP API1:2023 BOLA. Frame report around business impact (Tenant A reading Tenant B's data), not just "IDOR."

### 2. Blind IDOR detection via timing and state-change side channels
Source: [Beyond IDOR: The Guide to Advanced Broken Access Control](https://medium.com/@Aacle/beyond-idor-the-guide-to-advanced-broken-access-control-85b7a201baa7)

**Where:** any endpoint that returns `200 OK` with an empty/ambiguous body when you swap in a victim's ID — the naive "no visible leak = not vulnerable" read is wrong.

**Exploit steps:**
1. **Timing side channel:** compare response time for a valid-but-unauthorized ID vs a genuinely invalid one. `GET /users/VALID_ID` taking measurably longer (e.g. 200ms) than `GET /users/INVALID_ID` (e.g. 50ms) indicates the server did real work (fetch + processing) before the authorization check silently discarded the result — the check exists but fires too late, and other operations on that path may not be gated at all.
2. **State-change side channel:** for write/delete verbs, don't trust an empty `200 OK` — verify out-of-band. E.g. `DELETE /users/VICTIM_ID` returns `200` with no body → log in as (or otherwise check) the victim account to see if it was actually deleted/locked. A destructive action can succeed silently even when the read path looks safe.
3. Practice ground: PortSwigger's free IDOR lab is explicitly called out as a place to rehearse tracking invisible changes.

**Generalize:** treat any ambiguous 200/empty-body response to an ID swap as "unproven," not "safe" — always pair it with a timing comparison or an out-of-band check before ruling it out.

### 3. Bypassing access-control filters: parameter pollution
Source: [Beyond IDOR: The Guide to Advanced Broken Access Control](https://medium.com/@Aacle/beyond-idor-the-guide-to-advanced-broken-access-control-85b7a201baa7)

**Where:** endpoints where an access-control/WAF layer validates an ID parameter separately from the business logic that acts on it, and the framework accepts duplicate query params.

**Exploit steps:**
1. Send the target parameter twice with different values: `GET /api/messages?user_id=VICTIM&user_id=ATTACKER`.
2. Different frameworks pick different duplicates for different layers (e.g. the auth/security check reads the *last* value → sees attacker's own ID → passes; the business logic reads the *first* value → fetches the victim's data). This split creates the bypass.
3. Confirm which language/server stack is in play (PHP vs Python vs Node/Express handle duplicate params differently — check OWASP's HTTP Parameter Pollution guide for the specific first/last-wins behavior per stack) before relying on this, since the direction of the split determines which duplicate to put the victim ID in.

**Generalize:** see also `http-parameter-pollution-testing` for the broader HPP technique family (WAF bypass, cache poisoning, etc.) — this is the access-control-specific application of the same root cause (different layers disagreeing on which duplicate value wins).

### 4. Bypassing access-control filters: JSON type juggling
Source: [Beyond IDOR: The Guide to Advanced Broken Access Control](https://medium.com/@Aacle/beyond-idor-the-guide-to-advanced-broken-access-control-85b7a201baa7)

**Where:** JSON API endpoints where an ID field is checked against a deny-list/allow-list before being used in business logic, in loosely-typed backend languages (JS/Node.js especially).

**Exploit steps:**
1. Instead of sending the expected scalar (`{"id": 123}`), wrap it in an array or object: `{"id": [123]}`.
2. In JavaScript, loose equality can make `[123] == 123` evaluate `true`, so downstream business logic that does a loose comparison still resolves to the same object — but a strict-comparison access-control/deny-list check earlier in the pipeline (e.g. `Array.includes()` or a strict `===` against denied IDs) fails to match the array-wrapped value and lets the request through.
3. Try common wrapper variants (`[id]`, `{"id": {"$ne": null}}`-style NoSQL-flavored payloads if the backend is Mongo-adjacent, nested objects) against any endpoint that filters by ID before use.

**Generalize:** whenever an access-control check and the actual business-logic consumer of a value are implemented in different code paths (common with middleware-based deny-lists), suspect a type-confusion gap between how each path coerces the input.

### 5. UUIDv1 time-based prediction → IDOR
Source: [My Complete Bug Bounty Hunting Workflow — Every Command I Use, Step by Step](https://medium.com/bugbountywriteup/my-complete-bug-bounty-hunting-workflow-every-command-i-use-step-by-step-68484276471f)

**Where:** any object endpoint keyed by a UUID that a developer assumed was "unguessable" — check the UUID version before trusting it as an access control.

**Root cause:** not every UUID is random. UUIDv1 is time-based and sequential (derived from timestamp + MAC address, not entropy), so given one valid UUIDv1 you can predict/generate neighboring values that were likely issued around the same time — collapsing it to the same risk as a sequential integer ID. Only UUIDv4 (random) resists this.

**Exploit steps:**
```bash
# Generate a batch of time-based UUIDs around the current window
for i in {1..100}; do uuidgen -t; done > uuids.txt
# Test them against the target API
curl -s "https://target.com/api/user/$(sed -n 1p uuids.txt)"
```
1. Confirm the target's IDs are UUIDv1 (version nibble `1` in the third group, e.g. `xxxxxxxx-xxxx-1xxx-...`) rather than v4.
2. Generate a batch of candidate UUIDs in the timestamp neighborhood of a known-valid one (own account's ID, or one obtained via the leakage vectors in the Trigger technique above).
3. Sweep them against the object endpoint; a batch of `200` responses on other users' objects confirms the bypass.

**Generalize:** always check the UUID version before ruling out ID-guessing entirely — "it's a UUID" is not by itself proof against this class of attack.

### 6. Unhiding client-side-disabled/hidden elements to discover missing server-side authorization
Source: [My 5-Minute Workflow to Find Bugs on Any Website](https://infosecwriteups.com/my-5-minute-workflow-to-find-bugs-on-any-website-c20075320c96)

**Where:** any page with grayed-out/disabled form fields, hidden buttons, or premium/admin-only-looking sections that are visually present but not interactable — a strong signal the restriction is enforced only in the DOM/JS, not by the backend.

**Root cause:** the frontend hides or disables an element to *discourage* interaction, but the endpoint that element would call is still live and still processes the request if you send it directly — the access-control decision was made once, client-side, and never re-checked server-side.

**Exploit steps:**
1. Run a bookmarklet to strip client-side restrictions and reveal hidden elements in the live DOM:
   ```javascript
   javascript:(function(){document.querySelectorAll('[disabled],[readonly]').forEach(el=>{el.removeAttribute('disabled');el.removeAttribute('readonly');});document.querySelectorAll('[style*="display: none"]').forEach(el=>{el.style.display='block';});document.querySelectorAll('[style*="pointer-events: none"]').forEach(el=>{el.style.pointerEvents='auto';el.style.opacity='1';});alert('Disabled, readonly, and hidden elements are now active!');})();
   ```
2. Interact with the now-enabled field/button/section as a normal user would, and observe whether the resulting request succeeds — a 200/success response confirms the backend never actually gated this functionality.
3. For a fuller sweep on a single page, **Lost Uncover** (a floating in-page panel bookmarklet) additionally regex-harvests every endpoint referenced in page elements, attributes, and linked JS in real time — useful for finding the underlying API call a re-enabled button targets, before you even click it.

**Impact framing for report:** severity depends entirely on what the unlocked functionality does — an unlocked "export all users" button or an unlocked admin-only settings form is a straightforward broken-access-control finding (map it to OWASP API1/API5 depending on whether it's object- or function-level); an unlocked premium-only UI element with no real backend consequence (e.g. it just renders content that was already downloaded to the page but CSS-hidden) is not a vulnerability at all — confirm an actual privileged *action* or *data* is reachable before reporting, not just that a button became clickable.

**Generalize:** this is a recon/discovery technique, not a distinct vuln class — treat it as a cheap first pass on every new page during Phase 2 enumeration (`bughunting-workflow`) to surface hidden attack surface before deciding which endpoints are worth deeper IDOR/BOLA testing from the rest of this skill.

### 7. Unauthenticated list endpoint hands out every ID for the IDOR — no guessing, no leak-hunting needed
Source: HackerOne report [#4020767 — Unauthenticated API allows reading, writing to and deleting any user's private chat history](https://hackerone.com/reports/4020767), program: Essity. Reported by agusnicco, 2026-09-11. Severity: **Critical, CVSS v4.0 9.3** (`AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N`). Bounty: none paid, but Critical-rated and publicly disclosed. Weakness tag: Misconfiguration.

**Where:** an internal AI chatbot's HTTP API (Teams bot backed by Azure OpenAI/RAG) exposed a full REST surface — `GET /api/sessions` (list), `GET /api/sessions/{id}/history` (read), `DELETE /api/sessions/{id}` (delete), `POST /api/chat` (write/create) — alongside a correctly-authenticated `/api/messages` Bot Framework webhook. Only the webhook checked auth; every data route had none.

**Root cause:** the trigger technique this skill already teaches ("don't guess IDs, harvest them") is normally needed because IDs are unpredictable GUIDs you have to find leaked somewhere. Here that step was unnecessary: the app shipped its *own* unauthenticated enumeration endpoint (`GET /api/sessions`) that lists every object ID (`session_id`) on the host in one response, no auth, no pagination limit mentioned. Each `session_id` for a Teams-originated conversation was not an opaque handle either — it was literally the victim's Teams user identifier (`29:<opaque-id>` namespace, distinguishing individual users from group/channel IDs), so the leaked ID was itself PII.

**Exploit steps (the reporter's, generalizable to any app with a similar list+object-by-id pair):**
1. Enumerate the full API surface (this app had only 7 routes) and check *every* route for auth independently — don't assume a working object-by-id endpoint sits behind the same auth as the one authenticated entry point (the Teams bot webhook here); each route enforces (or fails to enforce) auth on its own.
2. If a "list all objects" endpoint exists (`GET /api/sessions`), hit it unauthenticated first — if it succeeds, it just handed you the target-ID list for every other endpoint's IDOR test in one request, skipping the entire "harvest a valid foreign ID" problem this skill's core theory otherwise requires solving.
3. Confirm read (`GET .../{id}/history`), write (`POST` with an arbitrary caller-chosen `session_id` — note: **create-with-attacker-chosen-ID is also an IDOR shape**, not just read/delete of existing IDs), and delete (`DELETE .../{id}`) each independently against IDs pulled from step 2 — a target can be vulnerable on some verbs and not others (here `/api/chat` had a WAF rule the others lacked, see cross-reference below).
4. **Test whether "delete" actually deletes:** after `DELETE /api/sessions/{id}` returned 200 and the object vanished from the list endpoint, the reporter re-requested `GET .../{id}/history` directly by the now-"deleted" ID — it still returned the full data. The delete only removed the list-index entry, not the underlying record. Always re-fetch a resource by direct ID after deleting it via a list-scoped delete operation before concluding data is actually gone — soft-delete/index-only-removal is a distinct, separately-reportable finding (the report scored this as no availability impact precisely *because* the data isn't actually destroyed, just orphaned).
5. A negative control matters for the incomplete-deletion finding specifically: request the history of an ID that *never existed* (`never-existed-zz9`) and confirm it returns an empty result rather than the same shape as orphaned data — this rules out the endpoint just always echoing the requested ID back regardless of state.

**Cross-reference:** the one route that *did* have a control (`POST /api/chat`, blocked by a WAF rule matching the JSON key `session_id`) was bypassed via a duplicate-`Content-Type`-header trick — see `http-parameter-pollution-testing`'s newly added recorded technique for the exact mechanism; the point generalizable back to this skill is that a single WAF rule on one route is not a substitute for authentication and doesn't protect the sibling routes at all.

**Impact framing:** confidentiality (read every user's private conversation + their identity via the session_id itself), integrity (inject attacker-controlled messages into a real employee's Teams conversation that the LLM then responds to in-context — a stored-content-injection style impact layered on top of the BOLA), and a secondary incomplete-erasure/data-retention finding on top of the core BOLA. CVSS v4 scored this Critical (9.3) on confidentiality+integrity alone with zero privileges/UI required — frame reports this way when read+write BOLA co-occur rather than reporting them as two separate Mediums.

**Generalize:** whenever you find one authenticated-looking entry point (a webhook, an SSO callback, a primary login route) on an API, explicitly enumerate and test every *other* route on the same host/base-path independently — "the app has auth" is not a fact about the whole surface, it's a fact about whichever single route you happened to check. A list/enumerate endpoint sitting next to an object-by-id endpoint is now a standing thing to check for on every BOLA/IDOR engagement, before falling back to this skill's GUID-harvesting techniques.

### 8. IDOR via exposed internal microservice path parameter (public param vs hidden backend param mismatch)
Source: [Bug Bounty Recon & Vulnerability Cheat Sheet](https://medium.com/@t4nv1/bug-bounty-recon-vulnerability-cheat-sheet-12d9db390d7f)

**Where:** internal rendering/processing microservices fronted by a "clean" public API — a thumbnail generator, document previewer, or PDF renderer that the public-facing app calls internally, e.g. `POST /api/v2/render/thumbnail`.

**Root cause:** the public-facing endpoint that a normal user interacts with takes an opaque, authorization-checked object reference (a document ID scoped to the requesting user), but the *internal* microservice it calls behind the scenes accepts a raw storage path or object identifier directly — and that raw parameter is either passed through unchanged from client input, or discoverable/guessable by anyone who inspects the request the front-end actually sends:
```http
POST /api/v2/render/thumbnail HTTP/1.1
Content-Type: application/json

{
  "document_path": "s3://hr-private-docs-prod/contracts/2026/DOC-000001-PDF.pdf",
  "page": 1
}
```
Whoever built the thumbnail service trusted that only the "legitimate" front-end would ever call it with a path it already validated — but nothing on the microservice side re-checks that the requesting user actually owns/has access to `document_path`, and the path itself follows a predictable naming scheme (`DOC-000001-PDF.pdf`, `DOC-000002-PDF.pdf`, ...) once one example leaks.

**Exploit steps:**
1. Proxy any feature that generates a preview/thumbnail/rendered-page of a document you legitimately own and inspect the actual backend request — look for a raw path/URI parameter (not just an opaque ID) being sent to a `/render`, `/thumbnail`, `/preview`, or similarly-named internal-sounding endpoint.
2. Note the naming convention of the path (sequential `DOC-NNNNNN`, date-bucketed folders, bucket name) — this is the same "predictable resource name" problem as `cloud-storage-bucket-testing`, just applied to object paths inside a bucket rather than the bucket name itself.
3. Increment/guess neighboring document paths and resend the identical request with the swapped `document_path` — a 200 with another user's/tenant's rendered document confirms the microservice performs zero authorization on the path it's handed, only the outer public API (which you've now bypassed by calling the render endpoint's own contract directly) was ever gated.
4. Treat this like the "harvest a valid foreign ID" problem from this skill's Trigger technique — check export features, error messages, and other rendered documents for more leaked path examples to confirm the naming pattern before reporting.

**Impact framing:** Broken Object-Level Authorization (OWASP API1:2023) with an info-disclosure angle specific to "internal microservice trusted the caller" — frame the report around the architectural gap (public API validates, internal render service doesn't re-validate) rather than just "IDOR on a path parameter," since it generalizes to every other internal service reachable the same way, not just this one endpoint.

**Generalize note:** whenever a feature's *visible* request uses a safe, scoped identifier but proxies to (or is itself, once you look at the raw traffic) a call into a lower-level service that takes a raw path/storage-key/file-handle, always test swapping that raw value directly — internal microservices are frequently built assuming "only our own front-end calls this, so it's already been checked," which is not authorization, it's an assumption. Cross-reference `cloud-storage-bucket-testing` for the predictable-naming-convention angle once the leaked path reveals a bucket/prefix worth enumerating further.

### 9. Role confusion / Broken Function-Level Authorization (BFLA) — admin action replayed by a standard user
Source: [Authorization Bugs Beyond IDOR: What Most Hackers Miss](https://medium.com/bug-bounty-hunting-a-comprehensive-guide-in/authorization-bugs-beyond-idor-what-most-hackers-miss-c1cde8adf51d)

**Where:** any admin/privileged action endpoint (`POST /api/admin/users/disable`, ban/promote/delete-user, feature-flag toggles) discovered via crawling admin UI JS, API docs, or simply guessing the low-priv equivalent's admin-shaped sibling.

**Root cause:** the frontend hides the admin action from non-admin users (button never renders, route never linked), but the backend endpoint itself never re-checks the caller's role — authorization was implemented as "don't show the button," not "reject the request."

**Exploit steps:**
1. Log in as a standard/low-privilege user, capture their session token/cookie.
2. Directly call the known-or-guessed admin endpoint using the low-priv session, via Burp Repeater — don't rely on the UI ever exposing it: `POST /api/admin/users/disable {"user_id": "<any-id>"}`.
3. A `200`/success response (rather than `401`/`403`) with the action actually taking effect (the target user's account actually gets disabled) confirms the bug — silent success is the tell, distinct from IDOR's "I could read this" in that here "I could *do* this."

**Impact framing:** frame as Broken Function-Level Authorization (OWASP API5:2023), typically Critical — full administrative capability from a standard account is a different severity tier than a read-only IDOR, since it enables account takeover/deletion/privilege changes at scale, not just data exposure.

**Generalize note:** enumerate every admin/staff-only action referenced anywhere in the app's JS bundles (see `recon-scanning-toolkit`'s JS-secret/endpoint-hunting section — the same LinkFinder/endpoint-extraction pass that finds secrets also surfaces exactly these admin route strings) and replay each one under a low-priv session as a standing checklist item, not just the ones you happen to stumble into via the UI.

### 10. Feature/entitlement-level authorization bypass — premium/paid feature reachable without a valid subscription
Source: same as above.

**Where:** any feature gated by subscription tier/plan (`POST /api/export`, `/api/invite`, `/api/upgrade`, bulk-action endpoints, API-rate-tier-gated routes).

**Root cause:** the backend checks *that a plan field exists* on the request/account rather than independently verifying the account's actual paid entitlement against a billing/subscription record — so the check is satisfiable by whatever the client claims rather than by what was actually purchased.

**Exploit steps:**
1. Identify a feature visibly gated behind a paid/enterprise plan in the UI.
2. Capture the request that invokes it and look for any plan/tier-shaped field: `{"plan": "enterprise", ...}`.
3. Submit the request from a free-tier account with that field manually set to the premium value, without ever completing an upgrade/payment — a successful response indicates the backend trusts the client-supplied plan value rather than looking up the account's real entitlement server-side.

**Impact framing:** direct revenue loss (unauthorized access to a paid feature) — quantify by the feature's list price/tier cost in the report rather than a generic severity label. Overlaps with `mass-assignment-testing` (the injected field is often literally `plan`/`role`/`tier`) and `business-logic-abuse-testing`'s workflow-bypass entry (skipping the actual payment step) — treat all three as the same root cause applied to slightly different fields/endpoints, and check whichever skill's checklist you reach first rather than assuming only one applies.

### 11. Cross-account actions via non-numeric identifiers (username/role/system-account targets)
Source: same as above.

**Where:** any action endpoint that targets another account by username, role name, or account-type string rather than a numeric/GUID ID — messaging, sharing, permission-granting, or admin-assignment endpoints (`POST /api/messages/send {"recipient": "admin", ...}`).

**Root cause:** this skill's core IDOR techniques (entries #1-8) already cover swapping a numeric/GUID object reference for another user's — this is the same underlying bug (missing ownership/authorization check on the target of an action) but the object reference is a *string* (username, role name, `"system"`, `"admin"`) rather than an ID, so naive testing that only tries swapping numeric IDs misses it entirely.

**Exploit steps:**
1. On any action endpoint that names a target account by string rather than ID, try substituting: other known usernames, internal role names (`admin`, `support`, `billing`), and literal system-account strings (`system`, `root`, `service-account`) as the target value.
2. Check whether the backend validates that the *caller* is authorized to target that specific account/role, or only validates that the target string is syntactically a valid username.
3. A successful action against an account you have no relationship to (not a contact, not in the same org/tenant) confirms the gap.

**Impact framing:** lateral privilege escalation or cross-account action — same severity logic as IDOR/BOLA but frame it explicitly as "non-numeric object reference" so a triager doesn't dismiss it as "just try changing the ID, already covered" when the actual bug is that ID-shaped testing alone wouldn't have found it.

**Generalize note:** whenever this skill's Trigger technique ("don't guess IDs, harvest them") is applied, also harvest username/role-name-shaped values, not just numeric/GUID ones — the same side channels (error messages, exports, autocomplete/search-suggest endpoints) leak usernames just as often as they leak IDs.

### 12. State-based authorization — permission tied to workflow stage rather than a fixed role/permission check
Source: same as above.

**Where:** any multi-stage approval/review/closure workflow (expense approval, ticket/case management, order-fulfillment stages, content-moderation review queues) where an action is *supposed* to only be valid during one stage.

**Root cause:** the backend's authorization decision for an action is (correctly, in the honest flow) tied to the object's current workflow state — e.g. "only the assigned approver can act, and only while `status == pending_approval`" — but the *state* half of that check is missing or stale: the action handler still accepts a request that matches an *earlier*, already-captured state even after the object has moved past that stage.

**Exploit steps:**
1. Capture the exact request used for an in-workflow action (e.g. "approve") while the object is genuinely in the state that action requires (`pending_approval`).
2. Let/force the object move past that stage (approve it via the normal flow, or wait for it to close/expire).
3. Replay the *exact same captured request* (same object ID, same action) after the state has changed — if it's accepted and reprocesses the action (double-approval, reopening a closed case, re-triggering fulfillment) rather than being rejected for being stale, the authorization check never actually re-validated current state before acting.

**Impact framing:** business-logic circumvention via stale-state replay — distinguish from `race-condition-testing` in the report: this doesn't need concurrency/timing at all, a single replayed request works whenever the state check is simply absent, not merely racy. If concurrent requests are *also* needed to win the race (state check exists but has a TOCTOU gap), that's `race-condition-testing`'s territory instead — test both the simple-replay and the concurrent-race variants independently before concluding which (or both) apply.

**Generalize note:** map every workflow's valid state-transition diagram first (which actions are valid in which states, who can trigger them), then specifically target the *edges* — actions attempted from a state one step before or after where they're supposed to be valid — rather than only testing the "happy path" states.

**Cross-reference — method-based authorization bypass:** the same source article also covers trying `POST`/`PATCH`/`DELETE` on an endpoint that returns `403`/`Forbidden` for `GET` — that's the identical HTTP-method-tampering technique already recorded in full in `403-bypass-testing` (its Technique #1). Don't duplicate the payload catalog here; the only nuance worth noting is that the *root cause* framing differs slightly depending on where the block happens — `403-bypass-testing` frames it as an edge proxy/WAF vs. backend disagreement, while here it's a backend authorization-per-verb inconsistency (the same backend route handler applies different/no authorization logic depending on HTTP method) — both are worth checking on any endpoint that blocks one verb but not others, regardless of which framing turns out to be true once you dig into *why* it's blocked.

### 13. Endpoint-path recombination — synthesizing an unlinked, unauthorized route from two known REST path fragments
Source: [$500 for a UUID Swap — I Almost Gave Up on This IDOR](https://medium.com/@tinopreter/500-for-a-uuid-swap-i-almost-gave-up-on-this-idor-ae7a0adb518d)

**Where:** any REST API with nested-resource-style paths (`/api/vX/<resource>/<id>/<sub-resource>/...`) — here, a password manager with trusted-device-based OTP bypass.

**Root cause:** two separate, individually-correct endpoints existed side by side:
- `GET /api/v3/trusted-devices/<UUID>` — properly authorized, returned `403` when the tester substituted another user's UUID.
- `GET /api/v3/members/<UUID>/account/info` — also properly authorized, but scoped to return only limited fields (name, role) for a legitimate cross-user case (viewing a credential-sharing recipient's basic info).

Splicing the *nesting pattern* of the second endpoint onto the *resource name* of the first produced a route the developers apparently never explicitly reasoned about: `GET /api/v3/members/<UUID>/trusted-devices/info`. The backend's routing framework resolved this hybrid path to a real handler — almost certainly because the nested-resource convention (`members/<UUID>/<anything>`) was implemented generically enough to match `trusted-devices` too — but that handler carried neither the first endpoint's strict authorization check nor the second endpoint's field-scoping, returning full trusted-device details (User-Agent, external IP, cryptographic keys) for *any* member UUID.

**Exploit steps:**
1. When a direct object-fetch endpoint (`/api/v3/<resource>/<id>`) correctly rejects cross-user access, don't stop — inventory every *other* endpoint pattern the same API exposes, especially ones discovered incidentally (here, via JS-file analysis while hunting for unrelated `/api/v3/admin/*` paths — cross-reference `recon-scanning-toolkit`'s JS-analysis section for that discovery step).
2. Look specifically for a *different* resource nested under the same ID type (`/api/vX/<other-resource>/<id>/<sub-path>`) that legitimately allows cross-user access to *some* scoped data about that ID.
3. Try recombining: take the sub-path/resource-name segment from the blocked endpoint and graft it onto the nesting pattern of the permitted one (`/<permitted-resource>/<id>/<blocked-endpoint's-resource-name>` or `.../info`-style suffix variants). Test several plausible splice points, not just one — the exact combination that resolves to a live route is rarely obvious in advance.
4. Any response that returns the *blocked* endpoint's full data through the *recombined* path confirms the authorization gap — the object ID here doesn't even need to be secret or hard to obtain: UUIDs were already exposed throughout the app's own UI (in credential-sharing links), so no separate leak-hunting step was even required once the request shape itself was found.

**Impact framing for report:** leakage of another user's device fingerprint data (User-Agent), external IP address, and cryptographic keys via a completely unauthenticated-feeling cross-user request — reported as High, accepted as Medium, **$500 bounty**. The gap between reported/accepted severity is worth noting when framing similar findings: triagers may downgrade a pure info-disclosure IDOR (no direct account-takeover chain demonstrated) even when the specific data class (crypto keys, IP) feels serious — pushing the report toward a concrete follow-on chain (e.g., what the leaked cryptographic key actually unlocks) is worth attempting before submitting if time allows.

**Generalize note:** this is a distinct discovery method from every other technique in this skill — instead of harvesting a leaked ID (the Trigger technique above) or bypassing a filter on a *known* endpoint (entries #3/#4), this synthesizes a previously-*unknown*, unlinked endpoint by mixing and matching path fragments observed on two *different*, individually-working endpoints. Whenever a direct IDOR attempt gets a clean `403`, treat that as a reason to map every other endpoint pattern the API exposes and start recombining nesting prefixes/suffixes across them, rather than concluding the resource is simply protected — the persistence framing in the source's own title ("I almost gave up") is the actual point: the first blocked attempt is not the end of testing an object type, it's the point where you widen the search to sibling route shapes.

### 14. Static-keyword substitution — replacing `me`/`current`/`my` with a victim's real identifier
Source: [Exploiting Broken Access Control Vulnerabilities](https://www.intigriti.com/researchers/blog/hacking-tools/exploiting-broken-access-control-vulnerabilities)

**Where:** any API that exposes a convenience "current user/tenant" route alias (`/api/workspaces/my/details`, `/api/users/me`, `/api/account/current`) alongside — or as a shortcut for — the equivalent explicit-ID route.

**Root cause:** the backend resolves the keyword (`my`/`me`/`current`) server-side from the authenticated session, so that specific route is inherently safe — but if the same handler (or a sibling route) also accepts a literal ID in the same path position (`/api/workspaces/{tenantId}/details`), the developer's mental model of "this route is safe because it always resolves to the caller" doesn't transfer to the ID-accepting variant, which frequently ends up with weaker or missing authorization since it was tested/reasoned about less than the "safe-by-construction" keyword route.

**Exploit steps:**
1. Find every endpoint that accepts a static self-referential keyword in place of an ID (`my`, `me`, `current`, `self`).
2. Probe whether the *same path shape* also accepts a literal ID value instead of the keyword — try substituting a guessed/harvested victim tenant/user ID directly into that position.
3. If the ID-accepting variant returns victim data without the same authorization check the keyword route implicitly gets, you've confirmed cross-tenant/cross-user access via a route the developers likely never load-tested with a *foreign* ID, only ever with the keyword.

**Impact framing:** cross-tenant data access in multi-tenant SaaS — same severity class as entry #1's cross-tenant BOLA, but a distinct discovery vector (finding the keyword-vs-ID sibling pair) rather than harvesting a leaked GUID.

**Generalize note:** treat every "convenience alias" route (`/me`, `/my`, `/current`, `/self`) as a signpost pointing at a sibling route that takes an explicit ID in the same slot — go looking for that sibling specifically, since it's the one actually worth attacking.

### 15. Second-order path traversal through a middleware layer using a privileged shared token
Source: [Exploiting Broken Access Control Vulnerabilities](https://www.intigriti.com/researchers/blog/hacking-tools/exploiting-broken-access-control-vulnerabilities)

**Where:** architectures where a public-facing API gateway/BFF forwards requests to an internal backend service using its *own* shared/service-level credential (an internal admin token, a service-to-service API key) rather than passing through the original user's identity — common in microservice setups where the internal service trusts "anything the gateway sends me" as already-authorized.

**Root cause:** the public API does weak path normalization on a parameter it forwards into the internal request path, and the internal service itself has *no* per-request access control of its own — it was designed under the assumption that only the trusted gateway would ever call it, so it never re-validates that the forwarded ID actually belongs to the caller.

**Exploit steps:**
1. Identify a parameter that ends up interpolated into a path segment on an internal call the public API makes on your behalf (often visible via response-time differences, error messages leaking internal paths, or simply because the parameter's name/shape mirrors a path-like structure).
2. Inject a path-traversal sequence into that parameter targeting a different (victim) ID: `/api/users/..//1337/billing` — the double-slash/traversal survives the public API's normalization but resolves cleanly once it reaches the internal service.
3. Because the internal service trusts the gateway's shared privileged token rather than checking whether *your* session is entitled to ID `1337`, the traversed path resolves and returns the victim's billing data.

**Impact framing:** full cross-user data access, and because the request is authenticated at the *service* level rather than the *user* level, this class of bug is easy to miss with normal IDOR testing (which usually just swaps the visible ID, not the encoding/traversal shape of the parameter carrying it) — treat any parameter that looks like it might get forwarded internally as worth a path-traversal-in-parameter pass, not just a direct ID swap.

**Generalize note:** this is a second-order variant of `path-traversal-testing`'s core technique, applied specifically to an internal-service-trust boundary rather than a filesystem — whenever a public API is known (or suspected, via response-time/error-message recon) to proxy into an internal service using its own credentials, test every forwarded parameter for traversal/injection, since the internal hop is where the actual authorization gap lives, not the public-facing endpoint itself.

### 16. Session poisoning via a reused session variable across unrelated features
Source: [Exploiting Broken Access Control Vulnerabilities](https://www.intigriti.com/researchers/blog/hacking-tools/exploiting-broken-access-control-vulnerabilities)

**Where:** any application where a session-scoped variable (`session.email`, `session.active_org`, `session.current_user_id`) gets written by more than one feature, and at least one of those features accepts attacker-influenced input for that variable temporarily (a "forgot password" flow, an org-switcher, an impersonation/support-view feature).

**Root cause:** developers reuse the same session key across features without re-validating on every read that the value still actually corresponds to the logged-in identity — a feature that legitimately needs to *temporarily* hold a different value in that session key (e.g. staging a victim's email during a password-reset flow before the reset is confirmed) doesn't revalidate/reset it, leaving a window where a completely unrelated feature reads the same key back and treats it as authoritative.

**Exploit steps:**
1. Log in as yourself (attacker account).
2. Trigger a feature known to temporarily write a session variable using attacker-supplied or attacker-referenced input — e.g. initiate "forgot password" using the *victim's* email address while still logged in as yourself, if the flow sets `session.email = <submitted email>` before the reset link is actually clicked/confirmed.
3. Without logging out, immediately hit a *different* feature that reads that same session variable to decide whose data to show (e.g. the account/profile page reading `session.email`).
4. If that page now renders the victim's profile/data instead of your own, the session-poisoning window is real and exploitable — no password reset was ever completed, the mere act of *initiating* it corrupted the session state a sibling feature trusted.

**Impact framing:** full account view/takeover of the victim's session-scoped data, triggered purely by knowing the victim's email/identifier and without needing to complete any actual authentication step — report the sequencing precisely (exact feature that stages the session variable, exact feature that reads it back unrevalidated) since this bug is invisible to any single-feature test in isolation.

**Generalize note:** treat any session-scoped variable that gets *written* by more than one feature as suspect — enumerate every write-site for a given session key, not just its "intended" one, and test whether a sibling feature reads that key back without confirming it still matches the actual authenticated identity. This is the session-state analogue of entry #4's type-confusion pattern: two different code paths trusting the same piece of state without agreeing on when it's safe to trust.

### 17. Multi-step workflow logic flaw — ownership transfer as a side effect of an unrelated action
Source: [Exploiting Broken Access Control Vulnerabilities](https://www.intigriti.com/researchers/blog/hacking-tools/exploiting-broken-access-control-vulnerabilities)

**Where:** any multi-step or "administrative housekeeping" feature (archive, transfer, deactivate, merge) that changes a resource's ownership or permission model as a side effect, where the application's authorization logic assumes only the current legitimate owner would ever reach that step.

**Root cause:** the application validates authorization for *starting* the workflow but doesn't re-validate at each subsequent step that the actor performing it is still authorized for the specific resource in play — e.g. an "archive workspace" feature that, as part of archiving, reassigns ownership to whoever initiated the archive action, on the unstated assumption that only an existing owner would ever call it.

**Exploit steps:**
1. Map out every multi-step/workflow-style feature that changes resource state, not just simple CRUD endpoints — archive, restore, transfer, merge, and deactivate flows are the highest-value targets since they often touch ownership/permission fields as a side effect of their "real" purpose.
2. For each step in the workflow, test whether it re-validates that you're authorized for *that specific resource*, or only checks that you're authorized to call the endpoint at all.
3. If archiving (or an equivalent step) on a victim's resource silently grants *you* read/write ownership as a side effect, you've found a privilege-escalation path that doesn't look like a classic IDOR at all — the vulnerable request doesn't even need to reference the victim's ID directly in a way that looks suspicious; it looks like a normal "archive my thing" call that happens to accept the victim's resource ID.

**Impact framing:** full ownership takeover of another user's resource via a feature that superficially looks like housekeeping, not access — worth reporting as a distinct BAC class from IDOR because it wasn't a raw data leak, it's an authorization gap in a *state transition*, similar in spirit to entry #12's workflow-stage-based authorization but focused specifically on ownership/permission changes as the side effect rather than access to a document mid-workflow.

**Generalize note:** whenever a feature's name suggests it only manipulates metadata/lifecycle state (archive, restore, deactivate) rather than content, don't assume it's lower-risk than a direct data-access endpoint — lifecycle-management endpoints are exactly where ownership/permission fields get silently touched without the same authorization scrutiny as the "real" CRUD paths.

### 18. Extended single-parameter mutation catalog for access-control-filter bypass
Source: [Exploiting Broken Access Control Vulnerabilities](https://www.intigriti.com/researchers/blog/hacking-tools/exploiting-broken-access-control-vulnerabilities)

**Where:** complements entry #3's *duplicate*-parameter HPP bypass — this is the single-parameter *value-mutation* variant, worth trying even on endpoints that don't accept duplicate params at all, wherever a validation layer parses the ID differently than the consuming business logic does.

**Payload variants to try against a single `id`/`userId`-style parameter:**
```
userId=1234,1337        # comma-separated — some parsers take the first token for validation, the whole string (or last token) for the query
userId=%31%33%33%37     # full URL-encoding of the digits — a regex-based validator matching on literal digit characters can miss this while the framework still decodes it before use
userId=1337%00          # null byte — some older/native-string-handling stacks truncate at the null for the validation compare but not for the downstream lookup
userId=1337%0A          # CR/LF — can break a single-line regex validator (`^\d+$` anchored without multiline awareness) while the value still parses cleanly downstream
userId=*                # wildcard — worth trying against any backend that might interpret it as a SQL/NoSQL/glob wildcard rather than a literal ID
userId=true             # boolean — worth trying where the backend's type coercion might resolve a boolean to an unexpected numeric/existing record
```
Also fuzz **HTTP method** on any endpoint returning 401/403 — the same access-control gap frequently exists only for some methods (`GET /admin/users` → 403, `POST /admin/users` → 200) because a middleware/route-guard was wired up per-method rather than per-route; sweep GET/POST/PUT/PATCH/DELETE plus content-type variations before concluding a blocked endpoint is actually protected.

**Automation:** Burp Suite's **Autorize** extension automates the core BAC-detection loop across an entire crawled site map — replay every request captured under a low-privilege session and flag any that still return the high-privilege response, rather than manually re-testing each endpoint by hand. **Firefox Multi-Account Containers** makes running parallel low-priv/high-priv sessions side by side for this kind of manual differential testing far less error-prone than constantly logging in/out of one browser profile.

**Reporting discipline — the valid/invalid line for this whole skill, not just this entry:** "not all missing access control validations represent a security concern" — a finding needs concrete CIA-triad impact (confidentiality: PII/account data exposed; integrity: unauthorized state change benefiting the attacker; availability: unauthorized deletion/disruption) to be reportable. Explicitly **not** reportable on their own: swapping sessions between two accounts *you* control (expected, not a bypass), reaching data that's already public via a different route, or a theoretical chain requiring a non-guessable ID with no actual leak path demonstrated for it.

**Generalize note:** the comma/encoding/null-byte/CRLF variants above generalize the same "parser disagreement" root cause as entry #3/#4 to the *value* space instead of the *duplication* or *type* space — whenever a validator and a consumer parse the same string, assume they might tokenize, decode, or coerce it differently, and sweep the standard string-mutation catalog (encoding, null byte, CRLF, wildcard, boolean) against any ID parameter before concluding server-side validation is airtight.

<!-- Add new recorded techniques below this line as new BAC/IDOR writeups are processed. Keep the same structure: Where / Root cause / Exploit steps / Impact framing / Generalize note. -->
