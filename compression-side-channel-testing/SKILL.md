---
name: compression-side-channel-testing
description: Compression side-channel attacks (BREACH/CRIME/HEIST-style) — exploiting the fact that HTTP response compression (gzip/brotli/deflate) makes response size depend on how much of the compressed payload's content matches an attacker-controlled guess, letting an attacker recover a byte-by-byte secret (CSRF token, session ID, API key) reflected into the same compressed response as their own input, purely by measuring response-size deltas over HTTPS. Use this during Phase 3 (Vulnerability Testing — Server-side/Client-side) of bughunting-workflow whenever a page reflects user-controlled input (search query, error message, URL param) into the same response body as a secret token, and that response is served with `Content-Encoding: gzip`/`br`/`deflate`. Also trigger on mentions of BREACH attack, CRIME attack, HEIST attack, compression oracle, gzip side channel, or response-size-based secret extraction.
---

# Compression Side-Channel Attacks (BREACH/CRIME/HEIST)

General technique library for recovering secrets via compression-ratio side channels. Each dated entry below is a validated technique pulled from a real writeup/source — add new entries here (don't create a new skill) whenever a new writeup covers a *different* delivery context (a specific framework, a specific secret type, a specific measurement technique) than what's already recorded.

## Core theory

Compression algorithms (DEFLATE/gzip, Brotli) work by finding repeated substrings and replacing repeats with shorter back-references. If a single compressed blob contains **both** a secret the attacker can't see **and** input the attacker fully controls, then:

- When the attacker's guessed substring **matches** part of the secret, that substring appears twice in the plaintext (once in the secret, once in the attacker's own reflected input) → the compressor collapses the duplicate → the **compressed output gets smaller**.
- When the guess **doesn't match**, no such collapse happens → the compressed output stays the same size (or larger).

So response size alone — visible over HTTPS via `Content-Length` or even just TCP segment counts/timing when `Content-Length` isn't sent — becomes an oracle: iterate character-by-character, keep whichever guess produces the smallest response, and the secret gets reconstructed one byte at a time regardless of encryption. **"Encryption protects data content — not side-channel leaks."**

Named variants by where the compression happens:
- **CRIME** — TLS-level compression (deprecated/disabled in modern TLS, but still worth a quick check on legacy endpoints).
- **BREACH** — HTTP-level response compression (gzip/deflate/brotli via `Content-Encoding`) — the one still commonly found today.
- **HEIST** — browser-side variant that infers compressed response size purely from JS-observable timing/resource-size APIs, so it doesn't even need the response to be readable cross-origin — just embeddable.

**Precondition checklist before spending time on this:**
1. Response has `Content-Encoding: gzip`/`br`/`deflate`.
2. Response body contains a secret (CSRF token, session identifier, API key, any anti-automation token) that stays present across requests.
3. Same response also reflects attacker-controlled input (search results page, error page, "did you mean" text) verbatim.
4. Request is repeatable many times cheaply (no aggressive rate limiting — see `rate-limit-bypass-testing` if there is one) since you need one request per guessed character/prefix.

If any of the four is missing, this class doesn't apply to that endpoint — move on rather than forcing it.

## Trigger technique: incremental-prefix size oracle

1. Confirm compression is active: `curl -s -H "Accept-Encoding: gzip" -D- -o /dev/null "https://target/page?q=x"` — check for `Content-Encoding: gzip` in the response headers.
2. Establish a baseline size with a guess guaranteed *not* to match the secret:
   ```bash
   curl -s -H "Accept-Encoding: gzip" -o /dev/null -w "%{size_download}\n" "https://target/page?q=zzzzzzzz"
   ```
3. Grow the guess one character at a time from a known/guessable prefix (e.g. you usually know a token's parameter name, like `csrf_token=`), watching for a **size drop** exactly when the next candidate character is correct:
   ```bash
   for c in {a..z} {A..Z} {0..9}; do
     size=$(curl -s -H "Accept-Encoding: gzip" -o /dev/null -w "%{size_download}" "https://target/page?q=csrf_token=TOP$c")
     echo "$c -> $size"
   done
   ```
   The candidate that produces the smallest total response size is (almost always) the next correct character — append it and repeat for the following position.
4. Repeat until the full secret is reconstructed. Cross-check with Burp Suite (send the same request repeatedly via Intruder/Repeater, sort by response length) when curl's own overhead/jitter makes small deltas hard to read reliably from the command line alone.
5. If `Content-Length` isn't exposed directly (e.g. chunked transfer-encoding), fall back to a HEIST-style approach: load the target page inside an attacker-controlled page via `<iframe>`/`fetch` and use the browser's Resource Timing API (`PerformanceResourceTiming.transferSize`/`encodedBodySize`) as the oracle instead of a raw `curl` byte count — same underlying signal, read from JS.

## Recorded techniques

### 1. Reflected-query BREACH lab against a Flask app leaking a CSRF token
Source: [Compression Side-Channel Attacks](https://medium.com/bug-bounty-hunting-a-comprehensive-guide-in/%EF%B8%8F-compression-side-channel-attacks-0809f5caa001)

**Where:** any page that both (a) embeds a persistent secret (CSRF token shown in the lab) somewhere in its HTML, and (b) reflects a user-supplied query parameter into the same HTML, with the whole response gzip-compressed.

**Root cause:** the app compressed the full response (secret + reflected input) as one blob without segregating the two, and without adding compression-defeating padding.

**Exploit steps (as demonstrated in the lab):**
1. Identify the gzip-compressed, input-reflecting endpoint: `curl -s -H "Accept-Encoding: gzip" -D- -o /dev/null "http://target/?q=x"` → confirm `Content-Encoding: gzip`.
2. Send a baseline non-matching guess and record size:
   ```bash
   curl -s -H "Accept-Encoding: gzip" -o /dev/null -w "%{size_download}\n" "http://127.0.0.1:5000/?q=x"
   ```
3. Walk the guess forward through the known token structure, watching size drop at each correct extension:
   - `?q=x` → baseline (no match)
   - `?q=csrf` → partial match, smaller response
   - `?q=csrf_token=` → extended match, smaller still
   - `?q=csrf_token=TOP` → deeper match, smaller still
4. Continue character-by-character (using the incremental-prefix loop above) until the token is fully reconstructed from response-size deltas alone.
5. Cross-verify with Burp Suite by resending the same request set and sorting by response length in the results table — a cheap sanity check against curl-side measurement noise.

**Impact framing for report:** full secret disclosure (CSRF token / session cookie / API key) despite the connection being HTTPS-encrypted end-to-end — "encryption protects content, not side-channel leaks." Practical impact framing: complete CSRF-token or session-token reconstruction → CSRF bypass or session hijack depending on which secret leaked.

**Remediation cited (useful for the report's recommendation section too):** disable compression on responses containing sensitive tokens, keep secrets and user-reflectable input in physically separate responses/requests, add random length padding to defeat the size oracle, and rotate tokens frequently so a slow byte-by-byte reconstruction runs out of time before it finishes.

**Generalize beyond this lab:** any endpoint that both compresses its response and reflects attacker input alongside a stable secret is a candidate — search history pages, "did you mean" spelling-correction pages, personalized error pages, and any JSON API that echoes a request parameter back inside an authenticated response are the most common real-world instances, not just a dedicated search box. Treat this as a slow, request-heavy technique (one request per candidate character) — budget accordingly, and prefer it as a follow-up once a promising reflect-and-compress endpoint has already been spotted rather than a first-pass scan target.

<!-- Add new recorded techniques below this line as new compression-side-channel writeups are processed. Keep the same structure: Where / Root cause / Exploit steps / Impact framing / Generalize note. -->
