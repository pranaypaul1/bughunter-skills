---
name: mass-assignment-testing
description: Mass-assignment vulnerability testing — injecting extra, unauthorized JSON fields (isAdmin, role, plan, org_id, email_verified, provider) into registration/profile/update endpoints to get the backend's auto-binding deserializer to set privileged internal fields the UI never exposes. Covers payload variants (casing, type confusion, nested/dot-notation, prototype pollution, array wrapping, NoSQL operators, Content-Type/charset tricks, string-encoded nested JSON) and which business-logic categories to target (privilege, subscription, verification, multi-tenant, OAuth linking, workflow state). Use this during Phase 3 (Vulnerability Testing — Access control/Business logic) of bughunting-workflow on any signup, registration, profile-update, or account-creation endpoint that accepts JSON. Also trigger on mentions of mass assignment, auto-binding, isAdmin, over-posting, or unauthorized field injection.
---

# Mass Assignment Testing

Technique library for probing JSON-accepting write endpoints (signup above all, but any create/update endpoint) for fields the backend silently binds to internal model attributes without an allowlist. Add new entries here as new payload categories or a different endpoint type get validated from future writeups.

## Core theory

Root cause: the backend deserializes the raw request body directly into an internal model/struct (`User.from_json(request.body)` style auto-binding) instead of explicitly mapping only the fields the UI is supposed to send. Every internal field the model has — `isAdmin`, `role`, `plan`, `org_id`, `email_verified` — becomes attacker-writable the moment it exists on that model, regardless of whether the front-end form ever shows it. This is functionally the same bug whether it's called "mass assignment," "over-posting," or an IDOR on your own object during creation.

**Methodology, in order:**
1. **Baseline** — send a clean, minimal registration/update request; note exactly which fields are accepted and echoed back (response body field names reveal internal naming conventions — e.g. `is_admin` vs `isAdmin` vs `ADMIN`).
2. **Guess internal field names** from the response schema, any exposed Swagger/OpenAPI docs, JS bundle strings (see `recon-scanning-toolkit`'s JS-secrets grep), or common conventions per category below.
3. **Inject one field at a time** alongside the legitimate registration fields, across the payload-variant categories below — casing/type variants matter because a strict allowlist that blocks `isAdmin` might still accept `IsAdmin` or `is_admin` if the check is case-sensitive or the allowlist misses a synonym.
4. **Confirm via a follow-up authenticated request** (not just a 200 on the POST) — check `GET /me` or equivalent to see whether the injected field actually landed and took effect.

## Recorded technique: payload catalog by category
Source: [Uncovering Invisible Privileges: The Ultimate Guide to Mass Assignment in Registration Flows](https://infosecwriteups.com/uncovering-invisible-privileges-the-ultimate-guide-to-mass-assignment-in-registration-flows-9ecd5ff40512)

### Privilege escalation — admin/role flags, cast and casing variants
```json
{"isAdmin": true}
{"admin": "true"}
{"ADMIN": 1}
{"is_admin": 1}
{"role":"admin"}
{"role":"superuser"}
{"role_id":0}
{"user_priv":"administrator"}
```
Try every plausible casing/synonym (`isAdmin`/`is_admin`/`ADMIN`/`admin`) and every plausible type for the same field (`true`/`"true"`/`1`) — a filter that strips one exact key/type combo often misses the others.

### Multi-tenant bypass — org/tenant fields
```json
{"org":"CompanyA"}
{"organization_id":1}
{"org_slug":"internal-team"}
```
On any B2B/multi-tenant app (see also `advanced-access-control-testing` for the tenant-scoping angle post-creation), try injecting a target org's identifier at signup time to land inside their workspace directly, bypassing invite-only or domain-verification flows.

### Prototype pollution (JavaScript/Node.js backends)
```json
{"__proto__": {"isAdmin": true}}
```
If the backend does a naive recursive merge of the request body into a JS object (common in Node/Express apps using `lodash.merge` or similar without sanitization), `__proto__` pollution can set the attribute globally on the object prototype, not just the current instance — check `hunt-nodejs`-style prototype-pollution chains if this lands.

### Dot-notation / nested-object injection
```json
{"account.role":"admin"}
{"account": {"meta": {"role":"admin"}}}
```
Targets ORMs/frameworks that flatten dotted keys or deep-merge nested objects onto the model — useful when a flat `role` key is filtered but a nested path into the same underlying field isn't.

### Type confusion
```json
{"admin": "false"}
{"admin": 0}
{"admin": null}
```
Some allowlist/validation logic checks truthiness or exact-value equality rather than the field name itself — sending an unexpected type (string `"false"` instead of boolean, `null`, a bare `0`) can slip past a check written for one specific type while a loosely-typed backend still coerces it to something usable.

### Array-based tampering
```json
{"username":["array_user"]}
{"roles":["user","admin"]}
```
If a field is normally scalar, wrapping it in an array can bypass a strict-equality deny-list check while a loosely-typed consumer downstream still accepts/flattens the array (same root cause as the JSON-type-juggling technique in `advanced-access-control-testing`).

### NoSQL operator injection (MongoDB-style backends)
```json
{"isAdmin": {"$ne": null}}
{"username": {"$gt": ""}}
```
If field values get passed into a MongoDB query/filter without sanitization, operator objects can both bypass a "must equal X" check and function as a NoSQL injection primitive in its own right. See `nosql-injection-testing` for the full methodology beyond this field-injection angle — auth-bypass payloads on login/reset flows, `$where`-clause server-side JS code injection, and time-based blind extraction.

### Query-string bracket-notation injection (Express/`qs`-parser specific, distinct from JSON-body array-wrapping above)
Source: [The 5 Node.js Input Mistakes Attackers Love (and How to Fix Them)](https://freedium-mirror.cfd/https://medium.com/@Krutik090/the-5-node-js-input-mistakes-attackers-love-and-how-to-fix-them-cc42474e8a1d)

Express's default query-string parser (`qs`) auto-expands bracket notation in the URL itself — no JSON body needed — so the same array-wrapping and `__proto__` tricks above work purely via query params against any route relying on `req.query`'s implicit typing:
```
GET /api/user?id[]=1                    # array injection — id becomes ["1"] instead of "1"
GET /api/user?id[__proto__][polluted]=1 # query-string prototype pollution — no request body at all
```
Test this specifically on any endpoint reading `req.query.<field>` and comparing/converting it without an explicit `typeof`/`Number()` check first — the `id[]=1` shape passes a naive `if (req.query.id)` truthiness check while silently becoming an array, and code downstream that expects a scalar (e.g. `SELECT * WHERE id = ${req.query.id}`) may serialize the array in a way that changes query semantics.

### Numeric-overflow type coercion
```json
{"age": "99999999999999999999999"}
```
An oversized numeric string passed to `Number()`/implicit coercion in JS overflows to `Infinity` rather than throwing — worth testing on any numeric field used in comparisons (`age < maxAge`, `quantity * price`) where the field is coerced rather than explicitly parsed and range-checked, since `Infinity` can trivially satisfy or break an upper-bound check depending on which side of the comparison it lands on.

### Content-Type / parser-fallback manipulation
- Send the JSON payload with `Content-Type: text/plain` or `application/x-www-form-urlencoded` instead of `application/json` — some frameworks fall back to a more permissive parser (or skip JSON-schema validation entirely) when the declared content type doesn't match, while still deserializing the body.
- Malformed charset parameter: `Content-Type: application/json; charset=garbage` — can trigger the same fallback-parser behavior.

### String-encoded nested JSON
```json
{"profile":"{\"isAdmin\":true}"}
```
If a field like `profile` is stored as a free-text/JSON-blob column and later re-parsed elsewhere in the app (a report generator, an admin panel, a webhook), a string-encoded JSON payload smuggled through validation for the outer field can get interpreted as structured data downstream.

### Verification / workflow-state bypass
```json
{"email_verified": true}
{"verification_expires":"1970-01-01T00:00:00Z"}
{"status": "active"}
{"state": "verified"}
```
Skip the confirmation-email step entirely by setting the verified flag or forcing an already-expired verification window at registration time; same idea for any explicit account/workflow `status`/`state` field.

### Subscription/billing manipulation
```json
{"plan": "pro"}
{"is_premium": true}
{"subscription_id": 9999}
{"trial_ends_at": "2050-01-01T00:00:00Z"}
```
Gives free access to paid tiers by setting the plan/premium flag directly, or referencing an arbitrary `subscription_id` that may belong to another tenant's billing record, or extending a trial far into the future.

### OAuth provider spoofing / account linking
```json
{"provider": "google"}
{"provider_id": "100234234234..."}
{"auth_strategy": "ldap"}
```
If the registration endpoint accepts provider/provider-ID fields directly rather than deriving them server-side from a verified OAuth callback, an attacker can register a local account pre-linked to a victim's `provider_id`, potentially hijacking the identity binding when the victim later signs in via that OAuth provider ("OAuth Account Hijacking" — closely related to the OAuth account-linking race in `race-condition-testing`, but here the bug is the link isn't validated at all rather than a timing race).

### Combined high-value probe
```json
{
  "__proto__": {"isAdmin": true},
  "profile": {"role":"admin"},
  "metadata": "{\"elevate\":true}"
}
```
Once individual categories are mapped, a combined payload stacking multiple vectors in one request efficiently tests several hypotheses (prototype pollution + nested-object injection + string-encoded JSON) in a single call before narrowing down which one actually landed.

## Impact framing for report

- **Privilege escalation** — attacker registers as (or is promoted to) admin/superuser from a public signup form.
- **Subscription fraud** — free access to paid tiers by injecting plan/premium fields.
- **Email verification bypass** — account activates without ever confirming ownership of the email.
- **Multi-tenant breach** — attacker lands inside a restricted org/workspace at signup.
- **OAuth account hijacking** — attacker pre-links a local account to a victim's OAuth identity.
- **Workflow/state-machine bypass** — account or object skips required intermediate states (e.g. "pending" → "active" with no approval step).

Frame severity around the specific business-logic consequence reached (admin access > subscription fraud > verification bypass), not just "mass assignment was possible."

## Defensive pattern to check for (informs which fields are worth trying)

Apps vulnerable to this rely on automatic model binding rather than an explicit allowlist. If you see a framework known for convenience auto-binding (Rails `strong_parameters` *disabled or misconfigured*, Django REST Framework serializers with `fields = '__all__'`, raw `Object.assign(user, req.body)` in Node/Express, or any ORM's `.update(**request.json)` pattern), treat every write endpoint on that stack as a mass-assignment candidate by default.

<!-- Add new recorded techniques below this line as new mass-assignment writeups are processed. -->
