---
name: http-parameter-pollution-testing
description: HTTP Parameter Pollution (HPP) — sending the same parameter name more than once (in URL query, POST body, JSON, cookies, or headers) to exploit the fact that different layers of a request pipeline (WAF, CDN/cache, load balancer, backend framework) disagree on which duplicate value "wins". Use this during Phase 3 (Vulnerability Testing) of bughunting-workflow as a bypass technique layered on top of WAF-blocked payloads (SQLi, XSS), CSRF token validation, IP allowlists, OAuth redirect_uri validation, price/role validation, and cache poisoning. Also trigger on mentions of parameter pollution, HPP, duplicate parameters, Param Miner, Arjun, or "WAF blocks this payload".
---

# HTTP Parameter Pollution (HPP) Testing

The deep insight (quoted from source, and the thing to internalize before using this skill): **"It's not about duplicates. It's about parser confusion."** Whenever two components in a request pipeline (WAF, CDN cache, load balancer, backend framework, validation layer vs. business logic) interpret the same request differently, security controls break. HPP is one instance of this pattern — the same root idea also shows up as HTTP Request Smuggling, Cache Poisoning, and Desync attacks. Treat "does layer A agree with layer B on what this parameter means" as the general question, and HPP (duplicate parameter names) as the cheapest way to test it.

Add new dated entries below as more HPP writeups are processed.

## Core theory

No HTTP spec says what to do when a request has `?id=1&id=2`. In practice, each implementation picks one of:
- Use the **first** occurrence
- Use the **last** occurrence
- **Concatenate** the values (with or without a separator)
- Build an **array** of all values

Different layers in the same pipeline (Client → CDN/WAF → Load Balancer → Backend Framework → Application Logic) often pick differently, and each layer parses independently. If a WAF reads the first value and the backend reads the last (or vice versa), you can put a safe-looking value where the WAF looks and the real payload where the backend looks.

**Known per-technology defaults** (verify per-target, these vary by version/config — don't trust this table blindly):

| Technology | Duplicate-param behavior |
|---|---|
| PHP | last value |
| ASP.NET | comma-joined (`safe,evil`) |
| Java Servlet | first value |
| Node.js | array (`["safe","evil"]`) |
| Python Flask | first value |
| Java Jackson (JSON) | last key wins |
| Java Gson (JSON) | first key wins |
| Python `json.loads` / JS `JSON.parse` | last key wins |

## Where to inject duplicates

Parameters live in more places than the URL query string — test all of them:
- **URL query string**: `?id=100&id=999`
- **POST body** (form-encoded): `username=pavan&username=admin`
- **JSON body**: `{"role":"user","role":"admin"}` (undefined by JSON spec — parser-dependent, see table above)
- **Headers**: `X-Forwarded-For`, `Authorization`, custom role/permission headers — headers can be duplicated too, e.g. sending `X-Forwarded-For: 127.0.0.1` then `X-Forwarded-For: <attacker-ip>` to test IP-allowlist bypass
- **Cookies**: `Cookie: role=user; role=admin` — some frameworks use the last cookie value
- **Hidden form fields** (`<input type="hidden">`): not HPP by itself, but the classic price/role tampering target — intercept in Burp before submit and change the value

## The core technique (works the same everywhere)

1. Find a parameter/value that's either (a) blocked/filtered by a WAF or app-level filter, or (b) validated by one code path but consumed by a different one (validation-layer vs. business-logic split).
2. Send it twice: a safe value in the position the filter/validator checks, the real payload in the position the backend/business-logic actually uses.
3. Order depends on which layer reads first vs. last for that target — try both orders if the backend tech is unknown:
   ```
   param=safe_value&param=malicious_value      # for last-value backends (PHP)
   param=malicious_value&param=safe_value      # for first-value backends (Java/Flask)
   param=safe&param=safe&param=malicious        # triple injection, useful against index-based checks
   ```

## Concrete attack patterns (test these against any target)

- **WAF-blocked SQLi bypass**: `id=1&id=1 OR 1=1` — WAF pattern-matches the first `id=1` (clean), backend concatenates/uses the second. Try with `sqlmap --hpp` for automation.
- **Price/business-logic override**: `price=999&price=0` (or reversed depending on backend) — WAF/validation sees the listed price, backend charges the polluted one.
- **Role/privilege escalation**: `role=user&role=admin` in query, form body, or JSON (`{"role":"user","role":"admin"}`) — validation checks the first `role=user`, backend registration logic binds the last.
- **XSS filter bypass**: `q=hello&q=<script>alert(1)</script>` — filter checks first value (clean), backend reflects the second.
- **IP-restriction / admin-panel bypass**: duplicate `X-Forwarded-For` header — `127.0.0.1` then `<attacker-ip>`, or reversed, depending on which the backend trusts for IP-based access checks.
- **OAuth `redirect_uri` hijack**: `redirect_uri=https://trusted.com/callback&redirect_uri=https://evil.com/steal` — allowlist validation checks the first (registered) URI, backend redirects using the second, leaking the authorization code to the attacker's server.
- **CSRF token bypass**: `csrf_token=VALID_TOKEN&csrf_token=ATTACKER_TOKEN` — if the CSRF-validation code path and the business-logic code path read the parameter via different mechanisms (e.g. Java `getParameter()` vs `getParameterValues()`), one sees the valid token and passes, while the other executes the actual attacker-controlled request. Build the CSRF PoC HTML form with both token fields; a logged-in victim who submits it has their token validated but their action executed under the attacker's control.
- **Mass assignment**: send extra JSON fields beyond what the UI exposes, e.g. `{"name":"pavan","role":"user"}` → add `"role":"admin"` as a second/overriding key, or as an entirely separate top-level field if the API auto-binds all JSON fields to a model.
- **Cache poisoning via parameter-key mismatch**: `GET /search?q=phone&q=<script>alert(1)</script>` — if the CDN builds its cache key from the first occurrence (`q=phone`) but the backend renders a response using the second (`q=<script>...`), the CDN caches the XSS payload under the clean-looking key. Any subsequent visitor to `/search?q=phone` gets served the poisoned cached response. Check `X-Cache`, `CF-Cache-Status`, `Age` response headers to confirm cache involvement.

## Encoding and structural variants (use when plain duplication is filtered/normalized away)

- **URL encoding of the payload itself**: `id=1&id=1%20OR%201%3D1`; double-encode (`%2520`) to survive a layer that decodes twice; mixed/partial encoding to evade signature matching.
- **Array notation**: `id[]=1&id[]=1 OR 1=1` (PHP/Node/Express auto-arrays this), `id[0]=1&id[1]=evil` (indexed), or mixing a plain param with an array-notation one (`id=1&id[]=evil`) to confuse a WAF that only inspects one form.
- **Null byte injection** (`%00`): older/C-based parsers may truncate a parameter *name* at the null byte, so `id%00=evil` might get read by the WAF as an unrecognized parameter (skipped) while the backend truncates it back to `id=evil`. Mostly relevant on legacy stacks — same caveat as null-byte tricks in `path-traversal-testing`.
- **Fragment-identifier (client-side) HPP**: the `#` fragment never reaches the server, but client-side JS (SPA routers, OAuth implicit flow) may read `window.location.href` and see it anyway. `https://app.com/page?param=safe#&param=evil` — server only sees `param=safe`, but client-side code parsing the full URL sees both. Especially relevant for OAuth implicit-flow token handling (`#access_token=legit&access_token=stolen`) and SPA client-side routing (`/#/dashboard?role=user&role=admin`).
- **Delimiter abuse**: some parsers accept `;` or other characters as an alternate parameter separator instead of `&` — `?id=1;id=evil` (older PHP/IIS configs), or an encoded `%26` in place of `&` to slip past a parser that only inspects before decoding.

## Recon: finding parameters worth polluting

Don't just test parameters visible in the UI — hidden/undocumented ones are often where HPP matters most, since they're less likely to have consistent validation across layers.

- **Param Miner** (Burp extension): right-click → guess hidden/undocumented parameters against a target.
- **Arjun**: `arjun -u https://target.com/api -m POST` — automated hidden parameter discovery.
- **ffuf**: `ffuf -u https://target.com/?FUZZ=test -w params.txt` — wordlist-based parameter fuzzing.
- Once found, test both the discovered parameter's own duplication behavior and whether it interacts with a known validated parameter (e.g. finding `admin=true` or `debug=true` alongside normal params).

## Tools

| Tool | Purpose |
|---|---|
| Burp Suite Repeater | manual duplicate-parameter injection and response comparison |
| Param Miner (Burp ext) | hidden/undocumented parameter discovery |
| Arjun | automated hidden parameter discovery (CLI) |
| ffuf | wordlist-based parameter fuzzing |
| curl | quick manual HPP testing (`curl 'https://target.com/?id=1&id=evil'`) |
| sqlmap | `--hpp` flag automates HPP-based WAF-bypass SQLi testing |

## Remediation notes (for reports / retesting a fix)

- Reject requests containing duplicate parameter names outright, rather than silently picking one.
- Normalize/validate parameters *after* all parsing layers agree on a single canonical value — validation must happen on the same value the business logic actually uses, not on a value a different layer/function extracted.
- Use strict parameter mapping (one name → one expected value/type), not permissive auto-binding (relevant to the mass-assignment variant).

## Chaining

Apply during **Phase 3 (Vulnerability Testing)** of `bughunting-workflow` as a cross-cutting bypass technique, not a standalone vuln class — pair it with whatever you're already testing: if a SQLi/XSS payload gets WAF-blocked, retry it as an HPP pair before giving up; if a CSRF/auth/OAuth/access-control test fails cleanly, retry with a duplicated token/role/redirect_uri parameter before concluding the endpoint is safe. Also worth a dedicated pass on any caching layer identified in Phase 1/2 recon (`X-Cache`/`CF-Cache-Status` headers present) — HPP-based cache poisoning affects every visitor, not just the tester.

## Source

[HTTP Parameter Pollution (HPP)](https://medium.com/@pavankumarck684/http-parameter-pollution-hpp-78197aef60b7) by Lost_hacker, Medium — processed 2026-09-22 (WebFetch 403'd, fetched via Chrome fallback). Author notes several follow-up topics not yet covered in this piece (HPP in GraphQL/SOAP, HPP+SSRF chaining, mobile API HPP) — check for and process follow-up articles in this series if shared.

## Recorded technique: duplicate `Content-Type` header — WAF parses last, backend parses first
Source: HackerOne report [#4020767 — Unauthenticated API allows reading, writing to and deleting any user's private chat history](https://hackerone.com/reports/4020767), program: Essity. Reported by agusnicco, 2026-09-11. Severity: Critical, CVSS v4.0 9.3. Weakness tag: Misconfiguration.

**The technique:** send the *same header name twice* with different values, instead of a duplicate body/query parameter. Confirmed live case: a WAF rule blocked any JSON request body containing the key `session_id`. Sending two `Content-Type` headers bypassed it entirely:
```bash
curl -sk -X POST \
  -H 'Content-Type: application/json' -H 'Content-Type: text/plain' \
  --data-binary '{"message":"hello","session_id":"poc-h1-1789092836"}' \
  "https://target/api/chat"
```
The Azure Application Gateway WAF evaluated the **last** `Content-Type` value (`text/plain`) and concluded the body wasn't JSON, so it skipped JSON-body inspection (and therefore never saw the blocked key). The FastAPI backend evaluated the **first** `Content-Type` value (`application/json`) and parsed the body as JSON normally, executing the request the WAF thought it had blocked. Reversing the header order (`text/plain` then `application/json`) was tested as a control and still got blocked — confirming order, not just presence of both values, is what matters.

**Why this is a different variant from the header-duplication already in this file's "Where to inject duplicates" section:** the `X-Forwarded-For`/`Authorization` examples above are about which duplicate *value* a layer trusts for an IP/auth decision. This is about which duplicate value a layer uses to choose its **parsing mode** entirely (JSON vs. not) — the WAF doesn't just misjudge a value, it stops looking at the body at all once it settles on `text/plain`. Any WAF rule that keys off a declared `Content-Type` to decide *whether to inspect the body* (not just what to look for in it) is a candidate for this bypass, independent of what the actual blocked payload/keyword is.

**Generalize — test this against any body-inspecting WAF rule:**
1. Identify a WAF-blocked request where the block is on the request *body content* (not the URL/headers/method).
2. Duplicate the `Content-Type` header: real value first, a value that makes the WAF skip body inspection (`text/plain`, `application/octet-stream`, `multipart/form-data` with no matching boundary) second.
3. Confirm the backend still parses the body as intended (its content-type handling reads the *first* occurrence — verify this per-stack, don't assume; the table in this file's Core theory section is a starting point, not a guarantee for header-parsing specifically since it was built from body/query-parameter duplication behavior, not header duplication).
4. If first-wins doesn't work against the backend, try the reverse order — the same "try both orders" rule from the core technique above applies to headers exactly as it does to params.

**Impact framing:** this bypass alone doesn't create a vulnerability — it exists to route around a WAF rule that was the *only* control on an otherwise completely unauthenticated endpoint. Report it as what unlocked the underlying finding (BOLA/missing auth, in this case — see `advanced-access-control-testing` entry #7 for the full chain), not as a standalone WAF-bypass bug; a WAF rule is not authentication, and demonstrating you can route around it is most valuable as the connective step in a larger PoC.

<!-- Add new recorded techniques below this line as new HPP writeups are processed. -->
