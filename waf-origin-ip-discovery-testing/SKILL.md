---
name: waf-origin-ip-discovery-testing
description: Finding the real backend/origin IP address of a website hidden behind a WAF/CDN (Cloudflare, Akamai, etc.), then verifying and connecting directly to it to bypass the WAF entirely for every subsequent test. Covers DNS/certificate-based discovery (dnsrecon, Shodan SSL-cert search, Censys, SecurityTrails, viewdns.info history, SPF records), search-engine/favicon-hash pivoting (Fofa, ZoomEye, favicon-hash.kmsec.uk), threat-intel API pulls (VirusTotal, AlienVault OTX), and origin verification (hosts-file redirect test, nmap cert match, the "it redirects back to main site" false-positive trap, Burp Suite host-to-IP binding for testing). Use this during Phase 1/3 (Recon/Vulnerability Testing) of bughunting-workflow whenever the target sits behind a known WAF/CDN (confirm with `wafw00f` or response headers) and WAF-triggered blocks (403/406, generic block pages) are getting in the way of testing any vuln class, not just SQLi. Also trigger on mentions of origin IP, WAF bypass, wafw00f, Shodan SSL cert search, Censys, favicon hash, or "find real IP behind Cloudflare".
---

# WAF/CDN Origin IP Discovery & Bypass

Technique library for unmasking the real backend server behind a WAF/CDN and routing traffic straight to it. Each dated entry below is a validated technique pulled from a real writeup/source — add new entries here (don't create a new skill) whenever a new writeup covers a *different* discovery source or verification trick than what's already recorded. This is a general WAF-bypass primitive usable for any vuln class once the origin IP is confirmed — see `sqli-waf-bypass-testing` for the SQLi-specific application, but the discovery methodology here applies equally to XSS/SSRF/access-control testing that's getting blocked at the WAF layer.

## Core theory

A WAF/CDN (Cloudflare, Akamai, Imperva, etc.) sits in front of the origin server and inspects/filters traffic — but the origin server itself almost always still has a real, routable IP address, and that IP frequently still accepts direct connections because the origin admin never bothered (or forgot) to firewall it to *only* accept traffic from the CDN's IP ranges. If you can find that IP and connect to it directly (bypassing DNS resolution of the public domain), your traffic never touches the WAF at all — every payload that got blocked at the edge now reaches the application unfiltered.

The origin IP leaks through any channel that predates the CDN migration or bypasses it structurally:
- **Historical DNS** — before the CDN was put in front, the domain resolved straight to the origin; that record may still be cached/archived somewhere.
- **TLS certificates** — the origin server's own cert (issued for the same domain/subdomains) shows up in internet-wide cert-transparency scans (Censys, Shodan) even when the public-facing edge uses a different (CDN-issued) cert.
- **Non-HTTP services on the same domain** — mail servers (MX/SPF records), FTP, or other subdomains that were never put behind the CDN.
- **Shared/static assets fingerprinted by favicon hash** — if the origin server is also reachable directly on the internet with the same favicon, a favicon-hash search finds it regardless of what domain it's currently answering for.

**Recon signal:** target returns a WAF block page/403/406 on payloads that look otherwise promising, `wafw00f` or response headers (`Server`, `cf-ray`, `X-CDN`) confirm a known WAF/CDN vendor, or you just want to pre-emptively check before spending time on payload obfuscation.

## Discovery methods

Run several of these in parallel — no single source reliably works against every target, and a stale/decommissioned IP from one source can be cross-checked against a fresher one from another.

**0. Confirm WAF presence first** (skip origin-hunting if there isn't one):
```bash
wafw00f https://target.com
```
Also check via Wappalyzer extension, and ping the domain — if the resolved IP belongs to a known CDN ASN (CloudFront, Akamai, Cloudflare, Fastly), a WAF/CDN is confirmed.

**1. DNS resolution / reverse lookup**
```bash
dnsrecon -d target.com
```
Occasionally the origin is still directly resolvable if the WAF isn't applied consistently across all record types.

**2. Shodan — SSL certificate CN search**
```bash
shodan search 'Ssl.cert.subject.CN:"<DOMAIN>" 200' --fields ip_str | httpx-toolkit -sc -title -server -td
```
Finds any host on the internet presenting a TLS cert issued for the target domain — the origin server included, since it usually still carries its own valid cert even behind the CDN.

**3. Censys — certificate + IPv4/IPv6 correlation**
Search the domain in Censys, inspect matched certificates, and cross-reference the IPv4/IPv6 addresses those certs are currently being served from.

**4. SecurityTrails — historical DNS data**
Use the "Historical Data" tab to pull the domain's prior A-record IPs, from before it was ever put behind the CDN.

**5. Fofa / ZoomEye — favicon-hash-filtered search**
Filter results by favicon hash for much cleaner signal than a raw domain/keyword search (drastically cuts false positives from unrelated hosts).

**6. Favicon hash method (standalone, feeds into Shodan/Censys/Fofa/ZoomEye)**
1. Extract the target's favicon URL (or pull it via a CDN endpoint like `favicons.teamtailor-cdn.com` if the app uses a favicon-serving service).
2. Hash it at `favicon-hash.kmsec.uk` (or the standard `mmh3` favicon hash used by Shodan's `http.favicon.hash` filter).
3. Search that hash on Shodan (`http.favicon.hash:<hash>`), Censys, Fofa, or ZoomEye — any other host on the internet serving the identical favicon is a strong origin-IP candidate.

**7. Historical IP / passive DNS databases**
- **viewdns.info** — IP History tool, lists past A-records for the domain.
- **SPF records** — `dig txt target.com` and inspect the SPF entry; mail-sending infrastructure IPs listed there sometimes share hosting/subnet with the web origin, or directly reveal it if mail and web share one server.

**8. Subdomain / threat-intel correlation (VirusTotal + AlienVault OTX)**
```bash
curl -s "https://www.virustotal.com/vtapi/v2/domain/report?domain=<DOMAIN>&apikey=<API_KEY>" | jq -r '.. | .ip_address?'
curl -s "https://otx.alienvault.com/api/v1/indicators/hostname/<DOMAIN>/url_list?limit=500&page=1"
```
Both APIs surface historical IP associations for the domain and its subdomains; a small bash script combining both calls + deduplicating the IP list is the efficient way to run this at scale. (Same API calls are also recorded in `recon-scanning-toolkit`'s ASN/IP-pivoting technique for general asset discovery — reuse that output here instead of re-querying if you already ran it.)

## Verifying a candidate IP is actually the origin

A candidate IP is not confirmed until you've checked it — WAF-fronted infrastructure sometimes redirects direct-IP traffic right back to the CDN-fronted domain, which *looks* like success but proves nothing:

1. **Hosts-file test**: add `<candidate_IP> target.com` to `/etc/hosts`, then browse to `https://target.com` normally. If the page loads and (critically) does **not** show the WAF/CDN's fingerprint (compare response headers, TLS cert issuer, error-page branding against the CDN-fronted version), you've likely hit the real origin.
2. **Watch for the redirect trap**: "it redirects to the main site" when hitting the IP directly does **not** confirm origin — some infrastructure proxies/redirects direct-IP traffic back through the CDN path specifically to prevent this kind of bypass. Only trust a candidate that serves the actual application content directly, without bouncing back through the CDN.
3. **Certificate match via nmap**: confirm the TLS certificate served by the candidate IP matches the target domain's own certificate (same CN/SAN), which rules out a coincidental match with an unrelated host:
   ```bash
   nmap --script ssl-cert -p 443 <candidate_IP>
   ```

## Exploiting a confirmed origin IP

- **Browser/manual testing**: with the hosts-file entry in place, browse the app normally — the WAF is completely out of the traffic path, so payloads that were previously blocked can now be retested cleanly.
- **Burp Suite**: configure the target's hostname *and* the origin IP together in Burp's target/scope settings (hostname resolution override, or a matching rule under Proxy → Options → Hostname Resolution) so Burp sends the correct `Host`/SNI for the app to respond correctly while physically connecting to the origin IP — this lets you run the full manual/Repeater/Intruder toolkit against unfiltered traffic.
- **Re-run automated scanners** (sqlmap/Ghauri, nuclei, dalfox, ffuf) against the domain while `/etc/hosts` or Burp routes traffic to the origin — see `sqli-waf-bypass-testing`'s "routing around the WAF entirely" section for the SQLi-specific command pattern.

## Recorded techniques

### 1. Multi-source origin-IP discovery + verification methodology (baseline)
Source: [How to Find Origin IP of Any Website Behind a WAF](https://infosecwriteups.com/how-to-find-origin-ip-of-any-website-behind-a-waf-c85095156ef7)

**Where:** any target confirmed to sit behind a WAF/CDN (via `wafw00f`, Wappalyzer, or response-header fingerprinting) where WAF blocks are impeding testing of any vuln class.

**Root cause:** the origin server retains a real, directly-routable IP that the operator failed to firewall to CDN-IP-ranges-only, and that IP (or a TLS cert/favicon/DNS-history trail leading to it) is discoverable through channels the CDN migration didn't scrub.

**Exploit steps:** confirm WAF presence → run the discovery methods above in parallel (DNS resolution, Shodan cert search, Censys, SecurityTrails, Fofa/ZoomEye favicon-hash search, viewdns.info/SPF, VirusTotal/AlienVault) → verify each candidate IP via hosts-file test + nmap cert match, explicitly ruling out the "redirects back to CDN" false positive → once confirmed, route traffic (browser, Burp, or CLI scanners) directly to the origin IP for unfiltered testing of every other vuln class.

**Impact framing for report:** origin-IP exposure itself is typically a Low/Info finding on its own (infrastructure misconfiguration, not a direct data/access impact) — its real value is as a *force multiplier*: report it alongside whatever higher-severity finding it enabled by bypassing the WAF (e.g. "SQLi confirmed via direct origin-IP connection, bypassing the Cloudflare WAF that blocks the payload at the edge — origin IP `<x.x.x.x>` accepts direct unfiltered connections and should be firewalled to CDN ranges only").

**Generalize note:** this is infrastructure-layer recon, not tied to any single vuln class — always run it early (Phase 1) on any WAF/CDN-fronted target so the origin IP is already in hand by the time Phase 3 payload testing starts hitting WAF blocks, rather than discovering the need for it mid-test.

### 2. Active-disclosure vectors: SSRF/pingback outbound requests, email header analysis, forced error messages, and content-fingerprint search
Source: [Identifying a Server's Origin IP](https://www.intigriti.com/researchers/blog/hacking-tools/identifying-servers-origin-ip)

**Where:** any WAF/CDN-fronted target — these techniques are the *active* counterpart to entry #1's passive OSINT trail; use them when the passive DNS/cert/favicon sources above come up empty, since they force the origin to reveal itself directly rather than relying on a historical record surviving somewhere.

**Root cause:** the WAF/CDN only sits in the *inbound* traffic path; anything that makes the origin server itself initiate an *outbound* connection (an SSRF callback, a pingback, an outbound email) leaves that origin's real source IP in whatever infrastructure receives the callback — the CDN was never involved in that leg of the traffic at all.

**Exploit steps — SSRF/pingback-driven disclosure:**
1. Find any feature that makes the backend fetch a URL you control (see `ssrf-testing` for the general parameter-identification methodology) and point it at an **InteractSH** (or Burp Collaborator) listener — the connection log shows the real origin IP making that outbound HTTP/DNS/SMTP request, bypassing the CDN entirely since the CDN never proxies the origin's own *outbound* traffic.
2. **WordPress-specific variant:** the XML-RPC `pingback.ping` method forces the WordPress backend to make an outbound request to a URL you supply as part of a legitimate pingback-verification flow — point it at your own listener the same way; cross-reference `xmlrpc-abuse-testing` for the full XML-RPC attack surface this pingback mechanism belongs to.

**Exploit steps — email header analysis:**
1. Trigger any feature that sends an email (password reset, signup confirmation, notification digest) using an email address you control.
2. Inspect the raw email source's `Received:` header chain — the hop closest to the sending application typically discloses the origin mail/app server's real IP, since outbound SMTP traffic from the origin also bypasses the CDN (which only fronts HTTP/HTTPS). Check custom `X-*` headers too, some app-specific mailers leak an internal hostname/IP there as well.

**Exploit steps — forced error messages:**
Deliberately send malformed input (special characters, oversized payloads, wrong content-types) designed to trigger an unhandled exception rather than a normal error page — verbose stack traces/debug output occasionally disclose the origin's internal hostname or IP directly in the error body, especially on endpoints that haven't had their error handling hardened as carefully as the main app flow (same "test the unhappy path" discipline as this skill's sibling entries elsewhere in this hunting workflow).

**Exploit steps — content-fingerprint search (complements favicon-hash search in entry #1):**
Search Shodan/Censys for a *unique string* the app's own pages contain — a copyright notice, an analytics tracking ID, a distinctive custom response header — instead of (or alongside) a favicon hash:
```
Shodan:  http.html:"© copyright <company>"
Censys:  services.http.response.body:"© copyright <company>"
```
Any other host on the internet serving that identical string is a strong origin candidate — verify with entry #1's hosts-file/nmap-cert-match method before trusting it. Plain Google dorking (`site:` combined with a unique app string) can surface the same indexed origin server too.

**Favicon-hash calculation without a third-party site** (alternative to `favicon-hash.kmsec.uk` in entry #1 — useful when you don't want to send the target's favicon to a third party, or want to script it):
```bash
curl -s '<URL>/favicon.ico' | base64 | python3 -c 'import mmh3,sys;print(mmh3.hash(sys.stdin.buffer.read()))'
```

**Additional verification tool:** **IpInfo** alongside Shodan/Censys for sanity-checking a candidate IP's ASN/organization/geolocation against what you'd expect for the target's actual hosting provider before investing further effort confirming it.

**Impact framing:** same framing as entry #1 — origin-IP exposure is a force multiplier, report it alongside whatever higher-severity WAF-blocked finding it unlocked, not as a standalone Critical.

**Generalize note:** the throughline across all four active techniques here is "find something that makes the origin talk to *you* directly, or leaks its own internal view of itself" — distinct from entry #1's "find where its address was already written down somewhere." Whenever the passive sources in entry #1 dry up, come back to this entry's active-disclosure list before concluding the origin IP is unfindable.

### 3. Shodan SSL-cert-CN lookup to directly bypass a Cloudflare 403 on a sensitive file
Source: [Easy $100: Bypass 403 to 200 OK](https://infosecwriteups.com/easy-100-bypass-403-to-200-ok-b6bc126e2f4b)

**Where:** a target sitting behind Cloudflare where directory bruteforcing (`dirsearch`) found a sensitive path — here `/.env` — that returns a Cloudflare 403/block page on the public domain.

**Root cause:** same as entry #1 — the origin server was still directly reachable and not firewalled to Cloudflare's IP ranges only, so the WAF rule blocking `/.env` on the public domain simply never gets evaluated when the request is sent straight to the origin.

**Exploit steps:**
1. Recon a target subdomain (an unusually fresh/recently-indexed one is worth prioritizing) and run `dirsearch` with a common wordlist — find `/.env` returning 403 on the public hostname, confirmed as a Cloudflare block (not an app-level 403).
2. Run the entry #1 Shodan SSL-cert-CN search (`Ssl.cert.subject.CN:"<domain>" 200`) to get the candidate origin IP — no favicon-hash or cert-transparency pivoting needed, straight cert-CN match was sufficient here.
3. Request the exact same blocked path directly against the origin IP (e.g. `https://<origin_ip>/.env` with the `Host` header set to the target domain, or via the hosts-file method in this skill's Verification section) — 403 becomes 200 OK, full file contents returned.

**Impact:** the `.env` file disclosed database credentials, session-signing keys, and internal API routes — a straight path to backend compromise. Once retrieved, treat the leaked secrets per `github-recon-testing`'s key-validation methodology (confirm each credential actually works before reporting, don't just report "found an .env file").

**Impact framing for report:** reported as Priority 2, paid $100 — a useful calibration point that even a clean, high-quality WAF-bypass-to-credential-leak chain can land on the lower end of payout if the program treats origin-IP exposure as the root (infra-misconfig) issue rather than scoring the full blast radius of the leaked secrets.

**Generalize note:** this is the simplest possible instance of entry #1's "force multiplier" pattern — don't stop at a Cloudflare 403 block page on a juicy-looking path (`.env`, `.git/config`, `/admin`, backup files) without first checking whether the origin IP is already sitting in Shodan's cert-CN index; it's often a 30-second check that turns a dead end into a full read.

<!-- Add new recorded techniques below this line as new origin-IP/WAF-bypass writeups are processed. Keep the same structure: Where / Root cause / Exploit steps / Impact framing / Generalize note. -->
