---
name: jwt-attack-testing
description: JSON Web Token (JWT) attack technique library — the full attack surface beyond a bare `alg:none` check. Covers algorithm-confusion (RS256→HS256 key-confusion) attacks, JWK/`jwk`-header key injection (CVE-2018-0114-style type confusion), `kid`-header injection (path traversal to a predictable file, SQL injection into an unparameterized key lookup), weak-HMAC-secret brute-forcing (John the Ripper, jwt_tool), hardcoded-secret reconnaissance in JS bundles/GitHub, `jku`/`x5u`-header SSRF (fetching a signing key from an attacker-controlled URL), and missing/conditional signature verification. Use this during Phase 3 (Vulnerability Testing — Auth/Server-side) of bughunting-workflow on any target issuing JWTs for session/auth state, API authentication, or password-reset/email-verification tokens. Also trigger on mentions of JWT, jwt_tool, alg confusion, kid header, jwk header, jku, x5u, JWT secret brute-force, or JSON Web Token vulnerability.
---

# JWT Attack Testing

Technique library for JSON Web Token implementation flaws. Each dated entry below is a validated technique pulled from a real writeup — add new entries here (don't create a new skill) whenever a new writeup covers a different JWT attack primitive than what's already recorded. `403-bypass-testing`'s JWT `alg:none`/claim-tampering entry is the narrow path-gating-bypass application of technique #1 below — this skill is the fuller attack surface that entry points back to.

## Core theory

A JWT's security rests entirely on the *verifier* correctly and unconditionally checking a signature that only the *issuer* could have produced — every attack in this skill is a different way of getting the verifier to accept a token it never actually validated correctly, or to trick it into validating against a key the attacker controls. The recurring pattern: JWT libraries expose a lot of flexibility (multiple algorithms, multiple ways to specify which key to use) that was designed for legitimate key-rotation/multi-tenant use cases, and that same flexibility becomes an attacker's menu of "which validation path did the developer forget to lock down" options.

## Recon: identifying JWT usage and its signing mode

1. Any `Authorization: Bearer <token>` header, or a cookie/localStorage value matching the `xxxxx.yyyyy.zzzzz` three-part base64url structure, is a JWT — decode header + payload at [jwt.io](https://jwt.io) or with `jwt_tool <token>` to inspect the `alg` claim and payload structure before choosing an attack.
2. **Hardcoded-secret reconnaissance** — if the signing is HMAC-based (`HS256`/`HS384`/`HS512`), search for the actual secret string before resorting to brute-force: grep JS bundles (cross-reference `recon-scanning-toolkit`'s JS-secret-hunting section), GitHub dorking (cross-reference `github-recon-testing`), and config files. **Finding JWT signing/verification logic in client-side JavaScript is itself a strong signal the token is validated client-side** — a much bigger problem than a weak secret, since it means the server may not be independently re-validating at all.
3. Confirm which claims actually gate authorization (`role`, `admin`, `scope`, `tenant_id`) before spending time on any attack below — a JWT with tamperable claims that the backend never actually reads for an authz decision isn't exploitable via this route.

## Attack techniques

### 1. `alg: none` / missing signature verification
Some JWT libraries support a `none` algorithm (intended for internal testing/debugging) that produces an unsigned token — if the verifier doesn't explicitly reject it, an attacker can issue a token with arbitrary claims and no valid signature at all:
```
1. Base64url-decode the header and payload.
2. Set the header's "alg" to "none".
3. Modify any claim you want (e.g. "role": "user" → "role": "owner").
4. Re-encode header.payload, and send the token as header.payload. (trailing dot, empty signature segment).
```
A related, even simpler variant: some verifiers skip signature checking entirely for any token, not just `alg:none` ones — test by sending just `header.payload` with the signature segment removed entirely, no `alg` change needed.

### 2. Algorithm confusion (RS256 → HS256 key-confusion attack)
When a server is configured to accept an asymmetric algorithm (RS256 — public/private keypair) but the verification code doesn't strictly pin *which specific* algorithm a given key should be used with, an attacker can:
1. Obtain the server's RSA **public** key (often exposed at a `/.well-known/jwks.json` endpoint, embedded in client-side JS, or in TLS cert bundles).
2. Change the token's `alg` header from `RS256` to `HS256`.
3. Re-sign the tampered token using the RSA public key's raw string value as the **HMAC secret** for HS256 signing.
4. If the verifier's code path does `verify(token, key)` without also checking that `alg` matches what it *expects* for that specific key, it ends up doing an HMAC-SHA256 verification using the public key string as the secret — which the attacker, who also used that same public string as the secret, can trivially produce a valid signature for.

### 3. JWK header injection / type confusion (CVE-2018-0114-style)
Some JWT libraries let the token's own header carry an embedded public key (`jwk`) that the library then uses to verify that same token's signature — a design intended for scenarios where the verifier doesn't have the issuer's key pre-provisioned, but which becomes a straightforward "trust whatever key I hand you" bug if the library doesn't separately check that the embedded key is actually one it already trusts:
```json
{
  "alg": "RS256",
  "jwk": {
    "kty": "RSA",
    "n": "<attacker-generated-modulus>",
    "e": "AQAB"
  }
}
```
1. Generate your own RSA keypair.
2. Embed the **public** half in the token's `jwk` header field exactly as shown above.
3. Sign the token with your own **private** key.
4. If the library uses the embedded `jwk` to verify rather than an independently trusted key, the signature checks out — because you produced both the key and the signature.
Node-jose's CVE-2018-0114 is the canonical example of this exact type-confusion flaw; check any target's JWT library + version against known CVEs for this pattern specifically, not just a generic "vulnerable library" sweep.

### 4. `kid` (Key ID) header injection
The `kid` header field is meant to tell the verifier *which* key (out of possibly many) to use for this token — when the application resolves `kid` into an actual key by directly using its value (a file path, a DB lookup) without validating it, two distinct injection primitives open up:

**Path traversal via `kid`:**
```json
{ "alg": "HS256", "kid": "../../../dev/null" }
```
1. Set `kid` to a traversal sequence targeting a file with predictable/empty/known content (`/dev/null` on Linux resolves to an empty string — a known, guessable "secret").
2. Sign the token using that predictable content as the HMAC secret.
3. If the application does something like `key = readFile(basePath + kid)` and then `verify(token, key)`, the traversed path's content becomes the actual verification key — and since you already know that content, you can produce a signature that validates.

**SQL injection via `kid`:**
```json
{ "alg": "HS256", "kid": "example-key' UNION SELECT 'intigriti'; --" }
```
If the `kid` value gets concatenated into an unparameterized SQL query used to fetch the signing key from a database, standard SQLi techniques apply — cross-reference `sqli-waf-bypass-testing` for the injection methodology itself; the JWT-specific angle is that a successful injection here can be used to force the key-lookup query to return an attacker-known value (`UNION SELECT 'known-string'`), which you then sign with, or to directly extract real signing keys/other sensitive DB contents.

### 5. `jku`/`x5u` header SSRF — key fetched from an attacker-controlled URL
`jku` (JWK Set URL) and `x5u` (X.509 URL) headers tell the verifier to *fetch* the verification key from a URL embedded in the token itself, rather than using a pre-provisioned key:
1. Set `jku` (or `x5u`) to a URL you control, hosting a JWKS document containing your own public key.
2. Sign the token with the matching private key.
3. If the verifier blindly fetches whatever URL the token's own header specifies without validating it against an allowlist of trusted issuer domains, it retrieves and trusts your key — full forgery capability.
This is also a distinct SSRF primitive in its own right (cross-reference `ssrf-testing`) — even without full forgery success, getting the verifier to make a request to an OOB listener via `jku`/`x5u` confirms the header is processed unsafely and is worth reporting/escalating on its own.

### 6. Weak HMAC secret brute-forcing
Only applicable to symmetric algorithms (`HS256`/`HS384`/`HS512`) — RSA-signed tokens require the actual private key, making brute-forcing practically impossible:
```bash
john --wordlist=/path/to/wordlist.txt jwt.txt
jwt_tool <token> -C -d /path/to/wordlist.txt   # jwt_tool's own crack mode
```
A successful crack against a common/weak/default secret (`secret`, `changeme`, the app's own name) lets you forge arbitrary valid tokens from then on — treat this as a standing check on any HMAC-signed JWT, it costs nothing to try a short common-secret wordlist first before moving to other techniques.

## Reporting discipline

Per the source, quoted directly: **"submissions regarding missing best practices without it leading to a direct vulnerability are usually rejected as informative findings."** A JWT weakness (an overly-permissive `alg` allowlist, a `jku` with no domain restriction, a short-looking secret) is not independently reportable — it needs a concrete forged-token PoC that actually authenticates as another user, escalates privilege, or bypasses an authorization check. Build the full chain (tamper → sign/forge → replay against a real protected endpoint → observe the elevated/impersonated response) before submitting, exactly the same discipline as this skill's sibling entries elsewhere in this hunting workflow.

## Recorded techniques

### 1. Full JWT attack taxonomy — alg confusion, JWK/kid injection, jku/x5u SSRF, secret brute-force (baseline)
Source: [Exploiting JWT Vulnerabilities](https://www.intigriti.com/researchers/blog/hacking-tools/exploiting-jwt-vulnerabilities)

**Where:** any target issuing JWTs for session/auth state, API bearer-token auth, or embedded in password-reset/email-verification links.

**Root cause:** see Core theory above — JWT libraries' built-in flexibility (multiple algorithms, embeddable/fetchable keys, app-controlled key-lookup via `kid`) becomes an attacker-controlled decision surface whenever the verifier trusts a header field it should instead be validating against a fixed, pre-provisioned expectation.

**Exploit steps:** run the recon pass above to identify signing mode and hunt for a hardcoded secret first (cheapest path); then sweep, in rough order of setup cost: `alg:none`/missing-verification (technique #1) → algorithm confusion if RS256 and the public key is obtainable (technique #2) → `jwk`/`kid`/`jku`/`x5u` header injection if any of those fields are present (techniques #3-5) → HMAC secret brute-force as a fallback (technique #6). Confirm every successful forgery by replaying the tampered token against a real protected endpoint, not just decoding it locally.

**Impact framing:** see Reporting discipline above — authentication bypass/privilege escalation/user impersonation via a working forged-token PoC is the bar; a theoretical weakness with no successful forgery demonstrated is informative at best.

**Generalize note:** cross-reference `403-bypass-testing`'s narrower `alg:none` path-gating-bypass entry (the same technique #1 here, applied specifically to unlock a blocked path rather than to escalate privilege generally) and `session-auth-testing`'s JWT-revocation entry (a *different* JWT weakness — lack of server-side revocation on logout — orthogonal to every forgery technique in this skill, since a properly-signed-but-never-revoked token is a separate bug from a token whose signature was never properly verified in the first place).

<!-- Add new recorded techniques below this line as new JWT-attack writeups are processed. Keep the same structure: Where / Root cause / Exploit steps / Impact framing / Generalize note. -->
