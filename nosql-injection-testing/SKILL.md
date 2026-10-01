---
name: nosql-injection-testing
description: NoSQL injection testing — exploiting direct concatenation of unsanitized user input into a NoSQL database query (MongoDB primarily, also Redis/Elasticsearch/CouchDB/DynamoDB/Cloudflare KV). Covers operator-injection authentication bypass (`$ne`/`$gt`/`$regex`/`$exists` in JSON bodies and bracket-notation query params), server-side JavaScript code execution via unsafe `$where`-clause string concatenation, time-based blind boolean data extraction via `$where` + `sleep()`, and second-order NoSQL injection (stored payload detonating in a later query). Distinct from `mass-assignment-testing`'s brief NoSQL-operator note (that skill covers the field-injection angle on registration/profile endpoints specifically; this skill is the full injection methodology on any query-building code path). Use this during Phase 3 (Vulnerability Testing — Injection) of bughunting-workflow on any target fingerprinted as using MongoDB/a NoSQL backend, or any login/search/filter/password-reset endpoint that accepts a JSON body. Also trigger on mentions of NoSQL injection, MongoDB injection, $ne, $gt, $where, $regex operator injection, or NoSQL auth bypass.
---

# NoSQL Injection Testing

Technique library for NoSQL database injection, primarily MongoDB. Each dated entry below is a validated technique pulled from a real writeup — add new entries here (don't create a new skill) whenever a new writeup covers a different operator, database engine, or exploitation primitive than what's already recorded.

## Core theory

NoSQL databases don't parse a query *language* the way SQL does — a MongoDB query is just a JSON/BSON document, and query operators (`$ne`, `$gt`, `$where`, etc.) are themselves just JSON keys. This means the injection surface isn't "break out of a string with a quote" the way SQLi is — it's "get the application to pass an *object* where it expected a *scalar*." Any endpoint that takes a JSON body (or a query-string library that parses bracket notation into nested objects, like Express's `qs`) and drops a field value directly into a MongoDB filter without type-checking it first is injectable, because the attacker can send `{"$ne": null}` instead of a plain string and MongoDB happily interprets that as "match anything not equal to null" — turning an equality check into a tautology.

The `$where` operator is a special, higher-severity case: it lets a MongoDB query embed and execute **arbitrary server-side JavaScript** as part of query evaluation — if application code builds a `$where` clause via string concatenation (rather than a safe query object), it's not just an operator-confusion bug, it's a direct code-injection point into the database engine's own JS evaluator.

## Recon: identifying NoSQL injection candidates

1. Fingerprint the backend — MongoDB is the primary target for everything in this skill; also worth testing on Redis/Elasticsearch/CouchDB/DynamoDB/Cloudflare KV-backed endpoints if the stack fingerprints as one of those, though the operator syntax differs per engine.
2. Probe every login, search, filter, and password-reset/token-validation parameter with syntax-breaking characters and watch for a response change (content length, status code, headers, error message):
   ```
   $  {  }  \  "  `  ;  %00
   ```
3. Try submitting a JSON **object** where the app expects a plain string/number — the simplest possible test, and the one that immediately confirms whether the backend does any type validation on that field at all:
   ```json
   { "field": {"$ne": null} }
   ```

## Attack techniques

### 1. Authentication bypass via operator injection

**JSON-body variant** — swap a credential field for an operator object that's always true:
```json
{
    "customer_email": "customer@example.com",
    "password": { "$gt": "" }
}
```
`$gt: ""` matches any password string that's lexically greater than an empty string — i.e., any non-empty password value — so the query effectively becomes "find this email with *any* password," bypassing the check entirely.

**Bracket-notation query-param variant** — the same attack works even without a raw JSON body, wherever a query-string parser (Express's `qs`, PHP's native array-parsing) turns bracket syntax into a nested object server-side:
```
email=admin@example.com&token[$ne]=null&newPassword=hunter2
```
This is especially dangerous on password-reset/token-validation endpoints — `token[$ne]=null` matches any record where the reset token isn't literally `null`, i.e. any record with a token set at all, letting an attacker reset an arbitrary account's password without ever knowing its real token.

### 2. MongoDB operators worth sweeping systematically

| Operator | Effect |
|---|---|
| `$ne` | matches anything **not** equal to the given value — the standard "make an equality check always true" primitive |
| `$gt` | matches anything greater than the given value — useful against string/numeric comparisons (`$gt: ""` matches any non-empty string) |
| `$regex` | matches a field against a regex — can be abused for blind boolean extraction (see below) or, on some drivers, ReDoS |
| `$where` | evaluates an arbitrary JavaScript expression against each document — full code-execution primitive, see technique #4 |
| `$exists` | matches documents that do/don't have a given field at all — useful for confirming field names during blind recon |
| `$eq` | explicit equality — worth testing whether wrapping the *intended* value in `$eq` itself bypasses a naive string-based input filter that blocks the raw value but not an object-wrapped version of it |

### 3. Time-based blind boolean extraction via `$where` + `sleep()`

When the response gives no direct signal (no reflected data, no boolean-visible difference) but a `$where` clause is reachable, use MongoDB's server-side JS `sleep()` the same way SQLi uses `SLEEP()` — a deliberate delay is the oracle:
```json
{
  "email": "admin@example.com",
  "token": {
      "$where": "if(this.token.startsWith('a')) {sleep(5000); return true;} else {return true;}"
  }
}
```
Iterate the character/prefix being tested (`startsWith('a')`, `startsWith('b')`, ...) the same binary-search-style discipline as manual boolean-blind SQLi extraction (cross-reference `sqli-waf-bypass-testing`'s canonical extraction recipe for the general technique) — a 5-second delay confirms the guessed prefix is correct, an immediate response means it's wrong.

### 4. Server-side JavaScript code execution via unsafe `$where` string concatenation

The highest-severity NoSQL injection primitive — when application code builds the `$where` clause itself via string concatenation instead of passing safe parameters:
```javascript
// Vulnerable server-side code pattern
$where: 'this.email == ' + email + ' && this.unsubscribeToken == ' + unsubscribeToken
```
An attacker-supplied `email` value can break out of the intended comparison and inject arbitrary JS logic into the evaluated expression:
```
email=user@example.com'+||+TRUE;//&token=
```
This constructs the evaluated JS as:
```javascript
this.email == 'user@example.com' || TRUE; // && this.unsubscribeToken ==
```
The trailing `//` comments out the rest of the original clause (same discipline as a SQLi comment-out breakout), and `|| TRUE` makes the whole condition always match — full authentication/authorization bypass via server-side code injection rather than mere operator confusion. Depending on what JS execution context MongoDB's `$where` evaluator exposes, this can escalate beyond a boolean bypass into broader code execution — treat any confirmed `$where`-string-concatenation bug as a candidate for further JS-injection escalation testing, not just the specific bypass shown here.

### 5. Second-order NoSQL injection

Same discovery discipline as second-order SQLi (cross-reference `sqli-waf-bypass-testing`'s second-order entry) — unsanitized input gets stored (in a queue, a document field, a cache) during one request, then later read back and concatenated into a *different* NoSQL query during a separate, asynchronous operation (a background job, a queue consumer, a scheduled task). Harder to detect because the injection point and the detonation point are decoupled in both time and code path — a scanner or manual tester probing only the original submission endpoint's *immediate* response sees nothing; look specifically for any feature that reads back previously-submitted data into a fresh query (notifications, digests, exports, retry queues).

## Impact framing for report

Severity scales with what the bypass actually reaches: authentication bypass on a password-reset/login flow → High/Critical (account takeover); confirmed `$where` JS-injection → treat as a code-execution-adjacent finding even if the demonstrated PoC is "only" a boolean bypass, since the underlying primitive is arbitrary server-side JS evaluation, not just query-logic confusion; blind time-based extraction of PII/tokens → High, scaled by data sensitivity; a bare operator-confusion response-difference with no further chaining is a lower-severity finding on its own, same discipline as any other injection class in this hunting workflow — always push to a concrete auth-bypass or data-extraction demonstration before reporting.

## Recorded techniques

### 1. Full NoSQL injection methodology — auth bypass, operator taxonomy, blind time-based extraction, $where RCE, second-order (baseline)
Source: [Exploiting NoSQL Injection (NoSQLi) Vulnerabilities](https://www.intigriti.com/researchers/blog/hacking-tools/exploiting-nosql-injection-nosqli-vulnerabilities)

**Where:** any MongoDB-backed (or other NoSQL-backed) endpoint accepting a JSON body or bracket-notation query parameters — login, search/filter, password-reset/token-validation, and unsubscribe/preference-update endpoints are the highest-yield targets since they gate access/state based on a single comparison an operator object can trivially satisfy.

**Root cause:** see Core theory above — the injection surface is type confusion (object where a scalar was expected) rather than string-breakout, and it's compounded by a common developer misconception that NoSQL databases are inherently injection-resistant since they don't parse a SQL-like query language — that false assumption is cited as the primary reason this class remains under-tested relative to SQLi despite being mechanically just as exploitable.

**Exploit steps:** run the recon syntax-breaking sweep above against every candidate parameter; test the JSON-object-substitution primitive first (cheapest, immediately confirms/denies type validation); escalate to `$ne`/`$gt` auth-bypass payloads on login/reset flows; test `$where` specifically for string-concatenation code-injection if any endpoint's behavior suggests JS evaluation is in play (differing error messages, unusually flexible query logic); fall back to `$where`+`sleep()` time-based blind extraction when no other channel is observable; separately check any read-back-later feature (notifications, exports, queues) for second-order injection.

**Impact framing:** see Impact framing section above.

**Generalize note:** cross-reference `mass-assignment-testing`'s brief `$ne`/`$gt` note (the *field-injection* application of this same operator-confusion primitive on registration/profile endpoints specifically) — this skill is the fuller, dedicated home for the injection methodology itself, applicable to any NoSQL-backed query-building code path, not just mass-assignment-shaped endpoints. Also cross-reference `sqli-waf-bypass-testing` throughout — nearly every technique here (comment-out breakout, boolean-blind binary search, time-based sleep oracle, second-order detonation) is the direct NoSQL-flavored analogue of an existing SQLi technique, so a hunter already fluent in SQLi extraction discipline can transfer that mental model almost directly, just swapping SQL syntax for MongoDB operator/JS syntax.

<!-- Add new recorded techniques below this line as new NoSQL-injection writeups are processed. Keep the same structure: Where / Root cause / Exploit steps / Impact framing / Generalize note. -->
