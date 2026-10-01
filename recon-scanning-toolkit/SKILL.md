---
name: recon-scanning-toolkit
description: Concrete command-line toolchain for end-to-end bug bounty recon and automated scanning — subdomain enumeration (10+ sources incl. ASN/IP pivoting and permutation), live-host probing, visual recon, directory/file bruteforcing, URL collection, JS-file secret/endpoint extraction, port scanning, WordPress scanning, subdomain takeover, mass CVE hunting via Shodan facet analysis + tag-scoped Nuclei scans, and automated XSS/SQLi/SSTI/secrets scanning, one command pipeline at a time. Use this whenever the hunter is starting Phase 1/2/3 tooling on a new target and wants the actual shell commands (not just the methodology) for subfinder/httpx/katana/gau/gospider/dalfox/nuclei/sqlmap/aquatone/dirsearch/ffuf/naabu/wpscan/subzy/linkfinder/shodan. Also trigger on mentions of subfinder, httpx, katana, gau, gospider, dalfox, aquatone, dirsearch, naabu, wpscan, subzy, nuclei templates, nuclei tags, Shodan facet analysis, wayback.sh, or "what command do I run for X".
---

# Recon & Automated Scanning Toolkit

Command-reference library, not a methodology doc — `bughunting-workflow` owns the *why/when*, this skill owns the exact commands. Each dated entry is a validated command chain from a real writeup — add new entries (or extend an existing category) when a new source shows a different/better tool invocation, don't duplicate a category that already exists.

## Core theory

Automation's job is to generate a short list of *leads*; it doesn't close bugs by itself. The chain below exists to turn "one subdomain" into "tens of thousands of URLs and a triaged shortlist of parameters/hosts worth manual attention" as fast as possible, so manual effort (the part that actually finds business-logic and access-control bugs) starts from a rich, deduplicated surface instead of a blank target. Ratio to aim for: automate the scanning, manually deep-dive ~1 in 10 flagged leads.

## Recorded technique: full command pipeline

Source: [My Complete Bug Bounty Hunting Workflow — Every Command I Use, Step by Step](https://medium.com/bugbountywriteup/my-complete-bug-bounty-hunting-workflow-every-command-i-use-step-by-step-68484276471f)

### Setup

```bash
# ProjectDiscovery suite (Go required)
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
# Other essentials
pip install sqlmap
npm install -g jwt-tool
go install github.com/tomnomnom/anew@latest
go install github.com/tomnomnom/gf@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/jaeles-project/gospider@latest
```

### 1. Subdomain enumeration — never rely on one source

```bash
assetfinder --subs-only target.com | tee subs.txt
subfinder -d target.com -all -silent | anew subs.txt
amass enum -passive -d target.com | anew subs.txt
curl -s "https://crt.sh/?q=%.target.com" | grep -E "target.com" \
  | cut -d '>' -f2 | cut -d '<' -f1 | anew subs.txt
```
Each tool finds subdomains the others miss (assetfinder ≠ subfinder ≠ amass), and crt.sh (Certificate Transparency logs) surfaces subdomains that were never meant to be public. Running all four together is what gets you to ~90%+ coverage rather than a single tool's partial view.

### 2. Live-host filtering + tech fingerprint

```bash
cat subs.txt | httpx -silent \
  -ports 80,443,8080,8443,3000 \
  -status-code -title -tech-detect -cdn \
  -o alive_hosts.txt
cat alive_hosts.txt | awk '{print $1}' > alive_urls.txt
```
`-tech-detect` is the highest-value flag here — it tells you the framework (WordPress/Laravel/Spring Boot/etc.) so you know which CVEs/misconfigs to prioritize testing before you've written a single payload.

### 3. URL collection (past + present + hidden), 5-source merge

```bash
# Active crawl, 5 levels deep
cat alive_urls.txt | katana -silent -d 5 -jc -kf \
  -em js,png,jpg,css -o katana_urls.txt
# Historical URLs from Wayback Machine
waybackurls target.com | anew wayback_urls.txt
# GAU — indexes multiple archive sources
gau target.com | anew gau_urls.txt
# Full spider
gospider -s "https://target.com" -o gospider_out -t 20
# Merge + dedupe + strip static-asset noise
cat *_urls.txt gospider_out/* | sort -u \
  | grep -vE '\.(css|jpg|png)' | anew all_urls.txt
```
Expect 10,000–50,000 URLs from a mid-size target after this step — that full list is the hunting ground for parameter extraction and scanning below.

### 4. Parameter extraction + GF pattern matching

```bash
# Every distinct parameter name seen across all collected URLs
cat all_urls.txt | grep "=" | sed 's/.*?//' \
  | cut -d '=' -f1 | sort -u > params.txt
# Tomnomnom's gf patterns — pre-filter URLs likely to be exploitable per class
gf xss all_urls.txt > xss_candidates.txt
gf sqli all_urls.txt > sqli_candidates.txt
```
**Extend to every other vuln-shaped pattern, not just xss/sqli** — pipe through `uro` too (dedupes URLs that differ only in parameter *value*, not structure, so the candidate list doesn't waste scan time on near-duplicates):
```bash
cat all_urls.txt | gf xss | uro > unique_xss_targets.txt
cat all_urls.txt | gf sqli | uro > unique_sqli_targets.txt
cat all_urls.txt | gf idor | uro > unique_idor_targets.txt
cat all_urls.txt | gf ssrf | uro > unique_ssrf_targets.txt
cat all_urls.txt | gf redirect | uro > unique_redirect_targets.txt
```
Pattern definitions: `tomnomnom/gf` (the tool) + `coffinxp/GFpattren` (an extended pattern set beyond the stock ones bundled with `gf`) — install both so `idor`/`ssrf`/`redirect` patterns are actually available, not just `xss`/`sqli`.

### 5. Automated XSS scan

```bash
# Dalfox — automated XSS scanner (DOM + reflected)
cat xss_candidates.txt | dalfox pipe \
  --skip-bav --skip-mining-all \
  --waf-evasion -o xss_confirmed.txt
# Nuclei XSS templates as a second pass
nuclei -l alive_urls.txt \
  -t ~/nuclei-templates/xss/ \
  -severity medium,high \
  -o nuclei_xss.txt
```

### 6. Automated SQLi scan

```bash
sqlmap -m sqli_candidates.txt --batch \
  --level=5 --risk=3 --random-agent \
  --tamper=between,charencode \
  --output-dir=sqlmap_logs
nuclei -l alive_urls.txt \
  -t ~/nuclei-templates/sql-injection/ \
  -severity critical \
  -o nuclei_sqli.txt
# Error-based-specific single template, DAST-fuzzed
cat domains.txt | nuclei -t errorsqli.yaml -dast
```
`--tamper=between,charencode` is there specifically to slip past naive WAF pattern matching on the SQLi payload itself. See `sqli-waf-bypass-testing` once a candidate is confirmed and needs full WAF-evasion exploitation, not just detection.

### 7. SSRF / open redirect via `qsreplace`

```bash
# AWS instance-metadata SSRF probe
cat all_urls.txt \
  | qsreplace "http://169.254.169.254/latest/meta-data" \
  | httpx -silent -path "/latest/meta-data" \
  -match-string "instance-id" \
  -o ssrf_aws.txt
# Open redirect probe
cat all_urls.txt \
  | qsreplace "https://evil.com" \
  | httpx -fr -silent -match-string "evil.com" \
  -o redirects.txt
```
`qsreplace` rewrites every query-string value across the whole URL list to the test payload in one pass — much faster than hand-testing each parameter.

### 8. RCE / SSTI

```bash
nuclei -l alive_urls.txt \
  -t ~/nuclei-templates/rce/ \
  -severity critical \
  -o rce_results.txt
# Template injection
tplmap -u 'https://target.com/profile?name=*' \
  --engine asterisk -o tplmap_report.txt
```

### 9. Auth bypass — JWT / cookie manipulation

```bash
# JWT — attempt privilege escalation by injecting a claim
jwt_tool <JWT_TOKEN> -T -cv "admin:true"
# Cookie/body manipulation
curl -X POST https://target.com/login \
  -H "Cookie: session=invalid" \
  --data '{"admin":1}'
```

### 10. GraphQL introspection check

```bash
curl -X POST https://target.com/graphql \
  -d '{"query":"query {__schema{queryType{name}}}"}'
```
If this returns schema data, introspection is enabled in production — map every query/mutation/field it reveals and test each for missing authorization (feeds `advanced-access-control-testing`).

### 11. Secrets hunting — JS files, exposed `.git`/`.env`

```bash
# Grep API keys/tokens/secrets out of every JS file on the target
cat all_urls.txt | grep "\.js$" | httpx -silent \
  | xargs -I % sh -c 'echo % && curl -s % \
  | grep -Eo "(api|key|token|secret|password)=[\"\x27][^\"\x27]+[\"\x27]"'
# Exposed .git/config
cat alive_urls.txt | httpx -path "/.git/config" -mc 200 -o git_exposed.txt
# Exposed .env
cat alive_urls.txt | httpx -path "/.env" -mc 200 -o env_files.txt
```
An exposed `.env` is treated as an instant Critical — it typically dumps `DB_PASSWORD`, `AWS_SECRET_KEY`, `STRIPE_SECRET`, etc. directly.

### 12. Proof + report generation

```bash
# Screenshot every live host for visual proof
gowitness file -f alive_urls.txt -P screenshots/
# Auto-build a CSV finding log from tool output
echo "Vulnerability,URL,Payload,Impact" > report.csv
cat xss_confirmed.txt | awk '{print "XSS," $1 ",payload=alert(1),High"}' >> report.csv
cat ssrf_aws.txt | awk '{print "SSRF," $1 ",AWS Metadata,Critical"}' >> report.csv
```

### 13. One-line critical-only triage scan

Run this first on any brand-new target before the full pipeline above — if it hits, investigate immediately:
```bash
subfinder -d target.com | httpx -silent \
  | nuclei -t ~/nuclei-templates/ \
  -severity critical -o critical_vulns.txt
```

## Recorded technique: expanded recon command reference (extra sources, dir/JS/port tooling)
Source: [Recon to Master: The Complete Bug Bounty Checklist](https://infosecwriteups.com/recon-to-master-the-complete-bug-bounty-checklist-95b80ea55ff0)

Extends technique #1 above with more subdomain sources, ASN/IP pivoting, visual recon, directory/file bruteforcing, JS-file secret hunting, port scanning, WordPress-specific scanning, and subdomain takeover — use alongside the pipeline above rather than replacing it.

### Subdomain enumeration — additional sources
```bash
subfinder -d example.com -all -recursive -o subfinder.txt
findomain -t target.com | tee findomain.txt
chaos -d target.com -silent | tee chaos.txt
amass enum -passive -d example.com | cut -d']' -f 2 | awk '{print $1}' | sort -u > amass.txt
amass enum -active -d example.com | cut -d']' -f 2 | awk '{print $1}' | sort -u > amass.txt
github-subdomains -d domain.com -t [github_token]
shosubgo -d target.com -s YourAPIKEY
cat *.txt | sort -u > final.txt
```
Public API sources (no local tool needed, just `curl`):
```bash
curl -s https://crt.sh\?q\=\target.com\&output\=json | jq -r '.[].name_value'
curl -s "http://web.archive.org/cdx/search/cdx?url=*.target.com/*&output=text"
curl -s "https://www.virustotal.com/vtapi/v2/domain/report?apikey=[api-key]&domain=target.com"
curl -s "https://api.hackertarget.com/hostsearch/?q=target.com"
curl -s "https://urlscan.io/api/v1/search/?q=domain:target.com"
curl -s "https://index.commoncrawl.org/CC-MAIN-2023-50-index?url=*.target.com&output=json"
```
Subdomain permutation (generate likely-valid variants from known subdomains, then resolve):
```bash
subfinder -d domain.com | alterx | dnsx
echo domain.com | alterx -enrich | dnsx
echo domain.com | alterx -pp word=/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt | dnsx
ffuf -u "https://FUZZ.target.com" -w wordlist.txt -mc 200,301,302
```

### ASN / IP pivoting
```bash
asnmap -d domain.com | dnsx -silent -resp-only
amass intel -org "nasa"
amass intel -active -cidr 159.69.129.82/32
amass intel -active -asn [asnno]
# IP extraction from third-party sources
curl -s "https://www.virustotal.com/vtapi/v2/domain/report?domain=<DOMAIN>&apikey=[api-key]" | jq -r '.. | .ip_address?'
curl -s "https://otx.alienvault.com/api/v1/indicators/hostname/<DOMAIN>/url_list?limit=500&page=1"
shodan search Ssl.cert.subject.CN:"<DOMAIN>" 200 --fields ip_str | httpx-toolkit -sc -title
```
Pivoting off ASN/IP ranges (rather than domain name) surfaces infrastructure the target owns but never linked from a subdomain — old/forgotten hosts included.

**Packaged wrapper scripts** (`coffinxp/scripts` — wraps several of the raw API calls above into single commands, and adds URLScan.io as an additional source not covered by the raw `curl` calls):
```bash
./alienvault.sh domain.com        # full historical URL map from AlienVault OTX in one call
./virustotal.sh domain.com        # needs 3 VirusTotal API keys configured in the script; has surfaced
                                   # user-submitted files containing email/password combos, internal
                                   # API keys, and password-reset tokens in VirusTotal's own database
python urlscan.py -d domain.com --mode subdomains   # discovered subdomains → pipe to httpx for live check
python urlscan.py -d domain.com --mode urls         # unique endpoint set → feed into a separate nuclei scan
```
The `virustotal.sh` result category is worth calling out specifically — it's not just IP/domain pivoting, it's scanning what *other people* have uploaded to VirusTotal that happens to mention the target, which is a different leak surface entirely from anything the target's own infrastructure exposes (same "developer/third-party mistake" logic as `github-recon-testing`, just a different platform).

### Visual recon
```bash
cat hosts.txt | aquatone -ports 80,443,8000,8080,8443
```
Screenshot every live host at once — much faster for triage than opening each in a browser, and catches obviously-interesting hosts (login portals, admin panels, error pages) at a glance across hundreds of hosts.

### Directory & file bruteforcing
```bash
dirsearch -u https://example.com --full-url --deep-recursive -r
ffuf -w seclists/Discovery/Web-Content/directory-list-2.3-big.txt -u https://example.com/FUZZ \
  -fc 400,401,402,403,404,429,500,501,502,503 -recursion -recursion-depth 2 \
  -e .html,.php,.txt,.pdf,.js,.css,.zip,.bak,.old,.log,.json,.xml,.config,.env \
  -H "X-Forwarded-For: 127.0.0.1" -t 100
```

**Hidden API endpoint bruteforce, API-specific wordlist** (source: [Hidden API Endpoints: The Hacker's Secret Weapon](https://infosecwriteups.com/hidden-api-endpoints-the-hackers-secret-weapon-a9ee297a29c2)) — same ffuf mechanics, but pointed at SecLists' API-specific wordlist instead of the generic directory list, since undocumented API routes cluster around a different naming convention than static-content paths:
```bash
ffuf -u https://target.com/api/FUZZ -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt -mc 200,301,302
```
Seed additional custom wordlist entries from the naming conventions real hidden endpoints tend to follow — version bumps the frontend doesn't call yet (`/api/v2/...` when the app only calls `/api/v1/...`) and privilege/environment keywords (`internal`, `admin`, `dev`, `private`, `config`, `test`) combined with the object names already harvested from `params.txt`/`all_urls.txt` (technique #4) — e.g. if the app has a public `/api/v1/users/export`, also try `/api/v2/users/exportAll`, `/api/internal/users`, `/api/admin/deleteUser`. A real-world example: an unauthenticated `/api/v2/users/exportAll` endpoint (a `v2` sibling of a properly-authed `v1` route) leaked every user's email — reported for a $2,000 bounty.

### JS-file secret hunting (deeper than the grep in technique #1)
```bash
echo example.com | katana -d 3 | grep -E "\.js$" | nuclei -t nuclei-templates/http/exposures/ -c 30
cat jsfiles.txt | grep -r -E "aws_access_key|aws_secret_key|api key|passwd|slack|firebase|jdbc|.env|ssh key|.git"
cat alljs.txt | xargs -I@ -P10 bash -c 'python3 linkfinder.py -i @ -o cli 2>/dev/null' | tee endpoints.txt
cat alljs.txt | xargs -I@ -P5 python3 SecretFinder.py -i @ -o cli | tee secrets.txt
```
LinkFinder pulls *endpoints* (not just secrets) out of JS — feeds directly back into the URL list for further parameter-level testing; SecretFinder is regex-tuned specifically for credential-shaped strings.

## Recorded technique: JSRecon — manual + jsleaks/nuclei chain for JS secrets
Source: [How to Identify Sensitive Data in JavaScript Files (JSRecon)](https://medium.com/bugbountywriteup/how-to-identify-sensitive-data-in-javascript-files-jsrecon-306b8a2e6462)

Adds a manual pass and a different tool (`jsleaks`) on top of the JS-file secret hunting above — run before or alongside it.

**Manual pass first** (cheap, catches what regex chains miss): open the target, Ctrl+U for source, Ctrl+F search `.js` to list every JS file, open each and search for keywords `api`, `token`, `password`, `jwt`, `secrets`. Browser extensions **LazyEgg** (auto-extracts all `.js` URLs from a page, bulk-opens them, keyword-searches across all) and **EndPointer** (auto-parses page + linked JS for endpoints, keyword-filters for `secret`/`API`/`jwt`/`token`/`keys`/`passwords`) automate this same manual step.

**Equally cheap DevTools variant** (no tooling at all — good for a quick single-target manual check): F12 → Sources tab instead of view-source, look specifically for files named like `config.js`, `main.*.js`, or anything with `bundle` in the name, then Ctrl+F inside each for `key`, `token`, `auth`, `api`, `aws`. Cross-verify any hit is a live, actively-linked key (not a dead/placeholder value) before reporting. Source: [How I Found My First Web Bug as a Beginner](https://medium.com/@shaikhminhaz1975/how-i-found-my-first-web-bug-as-a-beginner-960712e8002f) — if the target has no bug bounty program, report by direct email to the maintainer with minimal disclosure (file/line/screenshot only, never the full key value in the report itself).

**Command chain:**
```bash
# Active crawl for JS URLs
katana -u target.com -d 5 -jc | grep '\.js$' | tee alljs.txt
# Passive/historical JS URLs from Wayback + archives
echo target.com | gau | grep '\.js$' | anew alljs.txt
# Keep only live (200) JS files
cat alljs.txt | httpx-toolkit -mc 200 -o live_js.txt
# jsleaks: -s SecretFinder mode, -l LinkFinder mode, -k status-code check
cat live_js.txt | jsleaks -s -l -k
# Nuclei credential-disclosure templates as a second pass
cat live_js.txt | nuclei -t prsnl/credentials-disclosure-all.yaml -c 30
# LazyEgg CLI tool — one-shot multi-vector extraction per JS URL
cat live_js.txt | xargs -I{} bash -c 'python lazyegg.py "{}" --js_urls --domains --ips --leaked_creds --local_storage'
```
`jsleaks -s -l -k` is the compact one-liner worth remembering: it does SecretFinder + LinkFinder + status-code filtering in a single pass instead of chaining three separate tools. Report findings with sensitivity level, attack-vector consequence, and whether the exposed endpoint itself requires authorization — a leaked internal API key on an unauthenticated endpoint is a very different severity than one gated behind existing auth.

**Gospider-driven JS-hunting one-liners** (an alternative crawl source to katana/gau above — worth running both since crawlers surface different URL sets):
```bash
gospider -s https://target.com | grep -Eo 'https?://[^"'\''<>[:space:]]+' | sort -u
gospider -s https://target.com -d 3 | grep '\.js$' | grep -Eo 'https?://[^"'\''<>[:space:]]+'
gospider -s https://target.com | grep -Eo 'https?://[^"'\''<>[:space:]]+' | grep '\.js$' | jsleaks -s -k
gospider -s https://target.com | grep -Eo 'https?://[^"'\''<>[:space:]]+' | grep '\.js$' \
  | xargs -I{} bash -c 'echo -e "\ntarget : {}\n" && python lazyegg.py "{}" --js_urls --domains --ips --leaked_creds --local_storage'
gospider -s https://target.com | grep -Eo 'https?://[^"'\''<>[:space:]]+' | grep '\.js$' \
  | nuclei -t credentials-disclosure-all.yaml -c 30
```

**Lost Uncover** (browser bookmarklet, not a CLI tool) — a floating in-page panel that regex-harvests endpoints from page elements/attributes/external JS in real time (`["'%60]\/[a-zA-Z0-9_?&=\/\-\#\.]*`), with copy/export-to-`.txt` and domain-only filtering; useful as a manual companion to the CLI crawlers above when eyeballing a single page rather than scripting a full-site sweep — same category as LazyEgg/EndPointer noted earlier in this section.

**Source map exploitation** (source: [JavaScript Secret Hunting: 11 Methods Bug Bounty Hunters Use to Extract Hidden Treasures](https://freedium-mirror.cfd/https://infosecwriteups.com/javascript-secret-hunting-11-methods-bug-bounty-hunters-use-to-extract-hidden-treasures-6950df4cc42e)) — check every minified JS file for a matching `.map` file left deployed alongside it; a source map hands back the **original, unminified source** — real variable names, full comments, complete code structure — which is dramatically easier to secret-hunt than the minified bundle it maps to:
```bash
curl https://target.com/js/app.js.map
curl https://target.com/static/bundle.js.map
ffuf -w js_files.txt:FUZZ -u https://target.com/FUZZ.map
```
Always check for a `.map` sibling on every `.js` file already collected in `alljs.txt`/`live_js.txt` above — it costs one extra request per file and, when present, is strictly higher-signal than running regex against the minified version. **`unwebpack-sourcemap`** and **`source-map-explorer`** automate the fetch-and-reconstruct step (pulling every `.js.map` a target serves and rebuilding the original directory tree/source files in one pass) rather than pulling and parsing each map file by hand. (Tooling source: [elementalsouls/Claude-BugHunter — hunt-source-leak skill](https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/hunt-source-leak/SKILL.md).)

**`.DS_Store` content parsing** (source: same) — macOS's Finder leaves a `.DS_Store` file in every directory it's browsed, and if a server directory was ever populated/managed from a Mac, the file can get deployed alongside the real content. It's a binary format, not plaintext, but parsing it (the Python `ds_store` library, or `python3 -m ds_store .DS_Store`) reveals the **full directory listing** of whatever folder it came from — filenames the file-serving config itself doesn't expose anywhere else (no directory listing enabled, no sitemap entry). Check `/`.`DS_Store`, every discovered subdirectory + `/.DS_Store`, and any path recon turned up as a parent directory.

**Deobfuscation before regex-hunting a minified bundle** — minification can break naive keyword/regex matching (a secret split across a line-wrap, a variable renamed to a single letter losing its identifying context); beautify first when no source map is available:
```bash
npm install -g js-beautify
js-beautify uglified-file.js > readable-file.js
for file in *.min.js; do js-beautify "$file" > "beautified_${file}"; done
```

**Additional secret-detection tools** (beyond `jsleaks`/LazyEgg above):
```bash
cat javascript_files.txt | mantra -d | grep "+"   # Mantra — JS-specific, confidence-scored, entropy-aware, lower false-positive rate
cat javascript_files.txt | jsecret                # JSSecret — pure entropy-based, language-agnostic, catches high-randomness strings regex misses
```
**Sensitive Discoverer** (Burp Suite BApp Store extension) — passive scanner that runs automatically as you browse the target through Burp's proxy, flags secrets/sensitive patterns in every response (JS included) with custom-pattern support, no separate CLI pass needed once installed.

**Configuration-object mining** — grep for the object literal itself rather than individual key names, since a whole config block often carries several secrets at once (Firebase config, OAuth client config, third-party service integration blocks):
```bash
grep -ri "config\|init\|setup\|credentials\|env\|settings" *.js
grep -r "const config = {\|var settings = {\|let credentials = {" *.js
grep -r "window\.config\|window\.settings" *.js
```

**Comment archaeology** — developers leave credentials, debug notes, and disabled code in comments far more often than in live logic; grep comments specifically rather than only scanning executable code:
```bash
grep -i "todo\|fixme\|pass\|key\|secret\|hack\|temp\|debug" *.js
grep -A 10 -B 2 "/\*.*\(config\|credential\|key\)" *.js
grep "//.*\(api\|key\|token\|secret\)" *.js
```

**`getJS`** (simpler alternative to katana/gospider when you just want the JS-URL list, nothing else): `getjs -u https://target.com` — one command, no crawl-depth/JC flags to think about, worth reaching for on a quick single-target pass.

**Version archaeology** — old/backup path variants of a JS file frequently survive on the server after a "current" minified version replaces it, and older builds are disproportionately likely to be unminified, unobfuscated, or simply predate a secret-removal cleanup:
```bash
for suffix in v1 v2 old bak .bak .old .orig; do
  curl -s -o /dev/null -w "%{http_code} https://target.com/js/app.${suffix}.js\n" "https://target.com/js/app.${suffix}.js"
done
```
Also worth trying directly against Wayback/archive.org for a fully historical unminified build from before the current bundler pipeline existed.

**Debug-flag exploitation** — grep specifically for a hardcoded debug toggle (`const DEBUG = true`, `window.DEBUG = 1`, `isDev: true`) rather than only credential-shaped keywords:
```bash
grep -rn "DEBUG\s*=\s*true\|isDev\s*:\s*true\|debug\s*:\s*1" *.js
```
A hardcoded-`true` debug flag left in a production bundle often gates verbose error output or hidden admin/beta features — confirm by toggling the equivalent value via browser console (`window.DEBUG = true`) or a matching hidden URL parameter (`?debug=1`) and diffing the page/response against the default state.

**Bounty calibration by secret type** (source: [11 Secrets in JS Files and How to Find Them](https://infosecwriteups.com/11-secrets-in-js-files-and-how-to-find-them-f4088cf71610) — largely the same technique set as the "11 Methods" article already cited above for source-map exploitation, this reference table is the one genuinely new addition):
| Tier | Bounty range | Example secret |
|---|---|---|
| Low | $100-$500 | internal IPs, non-sensitive endpoints, outdated libraries with no known exploit |
| Medium | $500-$1,500 | read-only API keys, misconfigured services **with proof-of-access** |
| High | $1,500-$5,000 | PII-exposing endpoints, write-access keys, staging credentials |
| Critical | $5,000+ | master API keys, AWS credentials, database connection strings, GitHub tokens with repo scope |

**Reporting discipline this table implies:** a Medium-or-above report needs **proof of data retrieval**, not just "I found a key" — actually call the API/service the leaked credential grants access to and capture real returned data (redacted appropriately) before submitting, since passive discovery alone caps a report at Low regardless of how sensitive the key type looks.

**Vulnerability chaining reminder:** a leaked internal endpoint or credential is rarely the end of the chain — feed it into `ssrf-testing` (an internal URL discovered this way) or `advanced-access-control-testing` (an ID/object-reference pattern discovered this way) rather than reporting the leak in isolation when a further step is reachable.

**Service-specific secret regex catalog** — run these across every collected JS file (or pipe into any of the tools above as a manual cross-check):
```bash
# Google
grep -rE "AIza[0-9A-Za-z_-]{35}" *.js
grep -rE "[0-9]+-[0-9a-z]{32}\.apps\.googleusercontent\.com" *.js
# AWS
grep -rE "AKIA[0-9A-Z]{16}" *.js
grep -rE "ASIA[0-9A-Z]{16}" *.js
# Stripe
grep -rE "pk_live_[0-9a-zA-Z]{24}" *.js
grep -rE "sk_live_[0-9a-zA-Z]{24}" *.js
# Slack
grep -rE "xoxb-[0-9]{12}-[0-9]{12}-[0-9a-zA-Z]{24}" *.js
grep -rE "xoxp-[0-9]{12}-[0-9]{12}-[0-9a-zA-Z]{24}" *.js
# JWT
grep -rE "eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*" *.js
# Firebase
grep -rE "firebaseConfig|firebase.*apiKey" *.js
grep -rE "\.firebaseio\.com|\.firebaseapp\.com" *.js
```
Cross-reference `vibe-coded-app-testing` for the full Supabase/Firebase-specific exploitation methodology once a key is found via these patterns, not just detection.

**Lookaround regex for custom/non-standard token formats** (source: [Stop Guessing and Start Grepping: The Hacker's Masterclass in Regex](https://cyphernova1337.medium.com/stop-guessing-and-start-grepping-the-hackers-masterclass-in-regex-6a6e96cee549)) — the service-specific catalog above only covers known providers with a fixed prefix; when a target uses its own internal token/key naming convention (spotted once via the manual keyword pass), build a one-off extraction pattern instead of eyeballing matches out of noisy grep output:
```bash
# Extracts only the 32-char token value itself, not the surrounding variable-assignment syntax —
# positive lookbehind confirms it's preceded by `authorization_token = "`, positive lookahead confirms
# the terminating quote, neither is included in the captured match
grep -oP '(?<=authorization_token\s*=\s*['"'"'"])[a-zA-Z0-9-_]{32}(?=['"'"'"])' *.js
```
Swap `authorization_token` for whatever variable/key name the manual pass turned up (`api_key`, `session_secret`, `internal_token`, ...) and adjust the `{32}` length quantifier to match the observed token — a tight length range (e.g. `{16,64}`) filters out short unrelated matches that a bare `[a-zA-Z0-9-_]+` would catch as false positives. Pipe the output into `gf`/`ripgrep` for a clean deduplicated list across a whole `alljs.txt` sweep rather than reviewing raw grep hits one file at a time. This is the general skill (anchors `^`/`$`/`\b`, character classes, quantifiers, capture groups, lookarounds) behind every fixed-prefix pattern in the catalog above — worth building fluency in rather than only ever reusing pre-made patterns, since a target's custom auth-token format will never show up in someone else's regex list.

**Verifying a found key before reporting** (don't report an unverified string — confirm it's live and scope its actual access first):
```bash
curl "https://PROJECT-ID.firebaseio.com/.json"                                    # Firebase — unauthenticated read test
curl -X PUT "https://PROJECT-ID.firebaseio.com/test.json" -d '{"test":"value"}'    # Firebase — write test
curl "https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=YOUR_TOKEN"      # Google OAuth token — validity + scope
aws sts get-caller-identity --aws-access-key-id YOUR_KEY --aws-secret-access-key YOUR_SECRET  # AWS key — confirms it's live, shows the IAM identity
aws iam get-user --aws-access-key-id YOUR_KEY --aws-secret-access-key YOUR_SECRET             # AWS key — permission scope
aws s3 ls --aws-access-key-id YOUR_KEY --aws-secret-access-key YOUR_SECRET                    # AWS key — quick bucket-access check
```
`aws sts get-caller-identity` is the single cheapest first call for any found AWS key — it confirms liveness and returns the exact IAM identity/account without needing any particular permission grant, before spending further calls probing what that identity can actually do. See `cloud-storage-bucket-testing` for the fuller unauthenticated-AWS-CLI exploitation methodology once a key/bucket combination is confirmed live.

### Port scanning
```bash
naabu -list ip.txt -c 50 -nmap-cli 'nmap -sV -SC' -o naabu-full.txt
nmap -p- --min-rate 1000 -T4 -A target.com -oA fullscan
masscan -p0-65535 target.com --rate 100000 -oG masscan-results.txt
```
naabu for fast initial port discovery across many hosts, nmap for deep service/version detection on the ports that matter, masscan only when you need full-range speed across a huge IP set.

**Operational-safety notes on the aggressive nmap flags used above** (source: [The Nmap Scans That Can Get You Into Trouble (And How to Stay Safe)](https://systemweakness.com/the-nmap-scans-that-can-get-you-into-trouble-and-how-to-stay-safe-a7a4dea7c383)) — the `-A`/`-p-`/`--script` combo above is convenient but noisy; know what it costs before firing it at a production or out-of-scope host:
- **`-A`** (aggressive: OS detection + version probing + NSE scripts + traceroute) triggers IDS/IPS almost instantly and reads as textbook pre-attack recon — restrict to hosts you own or a program has explicitly authorized for active scanning.
- **`-p-`** (all 65535 ports) can generate enough traffic to cause timeouts or look like a DoS against a fragile target. Throttle it (`nmap -p- --min-rate 50 <target>`) or scan just the top ports (`nmap -F <target>`) when scope/rate limits are unclear.
- **`--script=<category>`**: the `vuln`, `auth`, and `exploit` NSE categories actively brute-force credentials and run exploit-like probes — stick to `--script=safe` outside a personal lab or an engagement that explicitly authorizes active exploitation.
- **`-sS`** (SYN scan) is still fingerprinted by modern firewalls as a scan; pair with timing controls (`-T2` quiet, `-T1` ultra-quiet) when discretion matters more than speed.
- **`-sU`** (UDP scan) can crash or reboot fragile embedded/IoT/router targets that mishandle malformed UDP — scope it to the specific ports you need (`nmap -sU -p 53,67,123 <target>`) rather than a full UDP sweep.
- Golden rule: never run any of this without explicit written scope/permission; corporate, university, and public networks are heavily monitored and a loud scan can burn a program relationship even when the underlying finding would've been legitimate. Default to `nmap -sV <target>` first and only escalate to `-A`/full-port/script-heavy scans once scope confirms it's warranted.

**Two smaller diagnostic flags worth remembering** (source: [Nmap Found the Port. The Real Work Started After That](https://freedium-mirror.cfd/https://medium.com/@fatihaali093/nmap-found-the-port-the-real-work-started-after-that-3ace2ca07462)): `nmap --reason <target>` explains *why* nmap classified each port the way it did (which specific probe/response triggered open/closed/filtered), useful when a port's state looks surprising and you need to know whether that's a real firewall rule or just nmap's own inference; `nmap -O <target>` attempts OS fingerprinting from TCP/IP stack behavior, treat its output as a probabilistic guess rather than a confirmed fact the same way `-sV` service-version output is a behavioral pattern match, not a verified version string — both are worth double-checking against other signals (banner text, response headers, other fingerprinting tools) before relying on them for exploit selection.

**The six port states, and why "filtered" ≠ "closed"** (source: [Nmap Port Scanning: Finding Out What's Actually Running (Part 3)](https://freedium-mirror.cfd/https://surajapar.medium.com/nmap-port-scanning-finding-out-whats-actually-running-part-3-00c556c3267a)): `open` (service accepting connections), `closed` (reachable, nothing listening), `filtered` (a firewall is blocking the probe — Nmap genuinely can't tell open vs. closed), `unfiltered` (reachable but state undetermined, mostly from ACK scans), `open|filtered` (no response at all — common with UDP, since a silently-ignoring service and a silently-dropping firewall look identical on the wire), `closed|filtered`. Misreading `filtered` as "nothing here" is a common mistake that skips over a live, firewalled service worth further probing.

**Scan-type reference beyond the default `-sS`/`-sT`/`-sU` already covered above:**
- **`-sA`** (ACK scan) — doesn't determine open/closed at all; it maps *firewall behavior*. Sends a lone ACK: a RST response means `unfiltered` (the packet got through the firewall, whether or not a service is listening — a **stateless** firewall often lets a lone ACK through since it superficially resembles traffic from an already-established connection); no response/an ICMP error means `filtered` (the firewall is stateful and drops unsolicited ACKs too). Run this specifically against a port your SYN/connect scan reported as `filtered` to learn *why* — the finding "the firewall is stateless" is itself useful recon even with no open-port confirmation attached.
- **`-sF`/`-sN`/`-sX`** (FIN/NULL/Xmas scans) — exploit RFC 793: a closed port on a Unix-style TCP/IP stack should RST a segment with no SYN/RST/ACK flags, an open port should silently ignore it. `-sF` sends only FIN, `-sN` sends no flags at all (careful: `-sN` is NULL-scan, `-sn` lowercase is the unrelated host-discovery/no-port-scan flag — nmap won't warn you if you typo the case), `-sX` sets FIN+PSH+URG together ("Christmas tree" of lit flags). **Catch:** Windows targets ignore this RFC behavior and RST regardless of real port state, making these nearly useless against Windows stacks — and the unusual flag combinations are easy for a modern IDS/firewall to fingerprint and block outright, so treat these as a legacy-Unix-specific technique rather than a general-purpose evasion trick.
- **`--top-ports <n>`** — scan only the N statistically-most-common ports (Nmap's own real-world frequency data) instead of the default top 1,000; tune the speed/coverage tradeoff explicitly (`--top-ports 10` for an ultra-fast multi-host sweep, `--top-ports 5000` for deeper single-host coverage short of a full `-p-`).
- **`-iL <file>`** — read targets from a file instead of the command line, the natural hand-off point from a saved live-hosts list.
- **`-oN <file>`** — save human-readable output to a file (pair with `-oA` from the existing fullscan command above when you want all output formats at once).

**Staged workflow — fast sweep now, full sweep in the background, UDP last:**
```bash
# Step 1: fast SYN scan, top 100 ports — quick wins to start enumerating immediately
sudo nmap -sS -F -iL live_hosts.txt -oN fast_scan.txt
# Step 2: full 65535-port sweep queued in the background while you work the fast results
sudo nmap -sS -p- -iL live_hosts.txt -oN full_scan.txt
# Step 3: targeted UDP sweep — never blind-scan all 65535 UDP ports, it's too slow
sudo nmap -sU --top-ports 20 -iL live_hosts.txt -oN udp_scan.txt
```
This avoids sitting idle waiting for a full `-p-` scan to finish before starting recon on whatever the fast scan already found — start working the fast-scan output immediately, let the full scan and UDP sweep run alongside.

**When ICMP ping is blocked** (source: [How to Scan a Host When Ping is Blocked by a Firewall (Nmap Tutorial)](https://freedium-mirror.cfd/https://medium.com/@hrofficial62/how-to-scan-a-host-when-ping-is-blocked-by-a-firewall-nmap-tutorial-b51b746ff02f)): a failed ping never means the host is down, only that ICMP Echo specifically is filtered — nmap's default host-discovery phase relies on ICMP and will skip a live host entirely if it doesn't respond. Use `nmap -Pn <target>` to force nmap to treat the host as up and go straight to port scanning regardless of ping result; combine with `-sS`/`-sV` as normal (`nmap -Pn -sS -sV <target>`). Default to `-Pn` on any target where ICMP might plausibly be filtered (most production/WAF-fronted hosts) rather than trusting a "host seems down" result from a plain ping sweep.

### WordPress-specific scanning
```bash
wpscan --url https://site.com --disable-tls-checks --api-token <token> \
  -e at -e ap -e u --enumerate ap --plugins-detection aggressive --force
# Setup-wizard disclosure — a fresh/misconfigured install left wp-admin/setup-config.php reachable
cat domains.txt | nuclei -t wp-setup-config.yaml
```
`-e at`/`-e ap`/`-e u` enumerate themes/plugins/users respectively; `--plugins-detection aggressive` actively probes rather than relying on passive fingerprinting — use once tech-detect (technique #2) flags WordPress. An exposed `setup-config.php` lets an attacker re-run the install wizard against a live site — treat as P1 (source: a curated private template collection at `https://github.com/coffinxp/nuclei-templates`, also cited for several other single-purpose templates recorded across this file). Also always check `/xmlrpc.php` reachability on any confirmed WordPress target — see `xmlrpc-abuse-testing` for the full attack surface that single endpoint exposes (brute-force amplification, SSRF/DDoS via pingback, port scanning, legacy-library RCE). Fingerprint the WordPress version from `/feed/`'s `<generator>` tag (or `<meta name="generator">` on the homepage) and check it against the current release — the REST API's `/wp-json/batch/v1` endpoint had an unauthenticated blind-SQLi-capable route-dispatch bug through WordPress 7.0 (fixed 7.0.2+/6.9.5+/6.8.6+); see `sqli-waf-bypass-testing` for the full exploit chain and its live Cloudflare WAF-bypass variant.

**Media-library REST enumeration for unlinked sensitive files** (source: HackerOne report [#3839889 — 29 Premium Plugin Packages with License Keys Publicly Accessible in Uploads Directory](https://hackerone.com/reports/3839889), program Essity, reporter matty69v, Medium 6.9, weakness: Incorrect Permission Assignment for Critical Resource):
```bash
# The core WP REST API media endpoint is public by design — list everything ever uploaded,
# not just files linked from a rendered page, and filter for sensitive extensions
curl -s "https://target/wp-json/wp/v2/media?per_page=100&media_type=application" \
  | python3 -c "
import sys, json
for m in json.load(sys.stdin):
    url = m.get('source_url','')
    if '.zip' in url: print(url)
"
# Files under wp-content/uploads/ are typically served with no auth at all once you have the URL
curl -O "https://target/wp-content/uploads/2025/10/some-plugin-6.5.14-HcwXam9CAYQZ0Y5.zip"
unzip some-plugin-*.zip && grep -r "purchase_code\|license\|api_key\|activation" some-plugin/
```
The finding here wasn't a bug in the REST endpoint itself (`/wp/v2/media` listing is intended to be public) — it's that someone used the media library as general file storage for paid-plugin ZIP archives, which the REST API then dutifully enumerates regardless of whether anything on the live site links to them. Treat **any** WordPress target's media endpoint as a full asset inventory, not just an image gallery — paginate with `per_page=100&page=N` and filter by `media_type`/URL extension for anything that shouldn't be public (`.zip`, `.sql`, `.bak`, `.env`, `.log`, `.pem`, `.key` — same extension list as this file's Wayback CDX deep-dive section). Even when the archive itself has no embedded credentials, treat exposure of the *source code* as high-value: it can reveal `unserialize()`/deserialization sinks, `file_get_contents($url)`-style SSRF sinks, and — for security-plugin ZIPs specifically (Wordfence in the source report) — the exact WAF rule logic an attacker needs to craft a bypass. A spread of version-numbered archives across years also hands an attacker a precise CVE-applicability timeline (which version was live when a given CVE was published) even without touching the currently-active version at all. Same underlying lesson as `github-recon-testing`/`cloud-storage-bucket-testing`: check every enumeration surface a platform exposes by design, not just the ones a human would think to browse.

**WordPress-specific backup/config-file naming patterns** (feed these into the generic dir-bruteforce/extension-fuzzing command earlier in this file as a WordPress-tailored wordlist, alongside Google dorking for indexed copies):
```
wp-config-backup.php   wp-config.php.save   wp-config.php~   wp-config.php.old
error_log.log          php_error.log
wp.sql                 db.sql               wpbackup.sql     mysql_backup.sql
{TARGET}.zip           {TARGET}-backup.zip  backup.zip
```
Tilde (`~`) and `.save` suffixes are common text-editor backup artifacts (vim/nano leave these behind on some server configs) — worth trying against *any* sensitive filename on a WordPress target, not just `wp-config.php`, and worth trying `.rar`/`.tar`/`.tar.gz`/`.bak`/`.gz` variants on every candidate too.

**Open-registration check:**
```bash
curl -s -o /dev/null -w "%{http_code}" https://target.com/wp-register.php
curl -s -o /dev/null -w "%{http_code}" "https://target.com/wp-login.php?action=register"
```
A live registration page on a target that's supposed to be invite-only/staff-only is itself worth flagging — unauthorized account creation is a standing precondition for privilege-escalation testing (mass assignment on the registration payload, role-manipulation) even before any specific escalation bug is found.

**REST API user enumeration + firewall-bypass variant:**
```bash
curl -s "https://target.com/wp-json/wp/v2/users" | jq '.[] | {id, name, slug}'
curl -s "https://target.com/wp-json/wp/v2/users/1"
```
Leaks real author usernames/display-names (and sometimes email addresses depending on plugin config) — feed the harvested usernames directly into `/xmlrpc.php`'s rate-limit-free brute-force (`xmlrpc-abuse-testing`) or a standard `wp-login.php` credential-stuffing pass. If a WAF/firewall rule specifically blocks the `/wp-json/wp/v2/users` path pattern, retry through the query-string routing form instead — many WAF rules match on path but not on this equivalent query-parameter form, which WordPress's own router accepts identically:
```bash
curl -s "https://target.com/?rest_route=/wp/v2/users"
```

**Authenticated theme-editor RCE** (source: [Mr. Robot CTF — WordPress Exploitation and SUID Nmap to Root](https://osintteam.blog/mr-robot-wordpress-exploitation-and-suid-nmap-to-root-e8eea00ca695)):
Once valid WordPress credentials are in hand (brute-force, credential stuffing, leaked creds — see `session-auth-testing`), the built-in Appearance → Theme File Editor lets an authenticated user with `edit_themes` capability (default for Administrator, sometimes over-granted to Editor on misconfigured sites) directly edit a live theme PHP file through the admin UI:
1. Navigate to `wp-admin` → Appearance → Theme Editor → select the active theme's `404.php` (or any file).
2. Paste a PHP reverse-shell payload (e.g. the Pentestmonkey script) over the file contents and save — WordPress writes it straight to disk, no upload-filter/extension-check involved since this is a legitimate "edit a PHP file" feature, not a file-upload endpoint.
3. Trigger it by requesting a non-existent page on the site (forces the 404 template to render) while a `nc -lvnp 4444` listener is running — the reverse shell fires as the webserver user (`www-data`/`daemon`).
Treat this as a standing authenticated-RCE primitive on *any* WordPress target once admin/editor credentials are obtained by any means — don't stop at "got creds, logged in," that's still only a Medium-severity auth finding until chained into code execution via this editor. Cross-reference `post-access-impact` for what to do once the resulting shell is in hand.

### IIS-specific scanning
```bash
cat domains.txt | nuclei -t iis.yaml -c 30
shortscan https://domain.com -F
```
`shortscan` targets the IIS short-filename (8.3/tilde) disclosure vulnerability — it enumerates truncated 8.3-format filenames the server leaks, which can reveal sensitive files/directories not otherwise discoverable via normal brute-forcing; the `-F` flag runs its full/aggressive fingerprint mode. Use once tech-detect (technique #2) flags IIS. Once IIS is confirmed, see `iis-exploitation-testing` for the full IIS/ASP.NET-specific attack surface beyond shortname disclosure — WebDAV verb abuse, cookieless-session and `Request.Path` authz-bypass primitives, `trace.axd` exposure, and ViewState deserialization RCE.

### Subdomain takeover
```bash
subzy run --targets subdomains.txt --concurrency 100 --hide_fails --verify_ssl
```
Run this against the full subdomain list from technique #1 — dangling CNAMEs pointing at deprovisioned cloud resources (S3, Heroku, GitHub Pages, Azure, etc.) are cheap, high-confidence findings and cost nothing extra once you already have the subdomain list. See `subdomain-takeover-testing` for the full methodology beyond this detection command: manual verification against "Can I Take Over XYZ?", the non-destructive proof-of-control PoC standard, and the post-takeover escalation checklist (OAuth-redirect theft, cross-subdomain cookie theft, CORS/CSP allowlist bypass) that determines actual severity.

### Git repository disclosure (refined)
```bash
cat urls.txt | httpx-toolkit -silent -path /.git/config -mc 200 -ms "[core]"
# Nuclei alternative covering more .git exposure signatures than the single-path check above
cat domains.txt | nuclei -t gitExposed.yaml
```
Same idea as technique #11's `.git/config` check, but `-ms "[core]"` confirms the response body actually looks like a real git config rather than a 200 from a custom error page. Once `.git` exposure is confirmed, use **Git Dumper** (`git-dumper https://target.com/.git/ ./dumped_repo`) to reconstruct the full repository — including commits that were later force-pushed/removed from the live branch but still sit in `.git`'s object store — rather than manually poking around inspecting individual object files.

## Recorded technique: directory-listing exposure on SSL-cert-discovered infrastructure
Source: [HackerOne report #3584078](https://hackerone.com/reports/3584078) — disclosed report against Essity, "[Server] Full Exposure with Database Credentials", Critical (9-10), no CVE, bounty hidden. Report was heavily redacted (target hostname/IP, screenshots all blacked out) — recorded here only the non-redacted, reusable methodology.

**Asset discovery — finding infrastructure that's never linked anywhere in normal DNS/subdomain enumeration:** the reporter found an unlinked server belonging to the target purely via **SSL certificate search-engine pivoting** — searched a security search engine for the target's name, filtered by SSL certificate, and got back an IP address whose certificate's Subject/Issuer fields directly named the target company even though nothing in the target's own DNS pointed at it. A second platform's passive-DNS/hostname records for that same IP showed multiple other hostnames also tied to the target, cross-confirming ownership. **This is the exact technique already recorded in full in `waf-origin-ip-discovery-testing`** (Shodan `Ssl.cert.subject.CN` search + Censys cert/IP correlation) — don't duplicate the command reference here, just note that this report is a real-world example of that discovery method surfacing a completely unlinked, unmonitored server rather than just an origin IP hiding behind a WAF. Run that skill's SSL-cert-pivoting techniques as a standing Phase 1 check on every target, not only when a WAF is confirmed in front of the main domain — orphaned/forgotten infrastructure is exactly the kind of asset that never shows up in subfinder/crt.sh output because it was never given a matching subdomain at all.

**The actual vulnerability once the asset is found — check for enabled directory listing on every discovered host/path:** a bare request to the server's root (or any directory path found via ffuf/dirsearch) returned a full auto-generated file index instead of a 403/404 — the single cheapest possible check once any new host is in hand, and one that turns a single lucky filename guess into full recursive discovery of everything the web server can see under that path. What this one exposed: working database credentials (direct read/write DB access), a 69MB full website backup (complete source code), an uploads directory (potential PII), and a visible `admin.php` (a brute-force target it wouldn't otherwise have been worth enumerating for). **Always fetch the bare directory URL directly and look for an "Index of /"-style listing** as a first move on any newly-discovered host or directory path — it costs one request and, when it hits, hands you the target's entire file tree for free instead of needing to guess filenames one at a time.

**Proving asset ownership when a triager pushes back:** the program initially responded "Needs more info," specifically asking how the reporter connected an unfamiliar IP address to their domain. The reporter's answer — cite the exact SSL-certificate CN/issuer match plus the cross-referenced passive-DNS hostname records from a second platform — is the reusable template for justifying scope inclusion of any asset discovered through infrastructure pivoting rather than a named subdomain: always capture and quote the specific certificate fields and cross-referencing evidence that tie the IP back to the target, since "I found this in Shodan" alone won't satisfy a skeptical triager on an asset with no obvious DNS link.

**Impact framing for report:** the reporter didn't stop at "directory listing is enabled" — walked every distinct consequence out explicitly: database compromise (credentials grant read/write on a PII-containing DB), complete source-code theft (the 69MB backup), customer data exposure (uploads directory), an admin-panel attack-surface expansion (`admin.php` now a known brute-force target), business-logic/IP theft (internal documents), and a regulatory-compliance angle (GDPR/CCPA violation from exposed PII) — six distinct impact bullets from one root cause. That regulatory-framing bullet in particular is worth reusing on any PII-exposure finding against an EU/US-consumer-facing program: naming the specific compliance regime a data exposure violates is a persuasive severity argument triagers respond to beyond the technical impact alone.

## Recorded technique: ffuf command reference — vhost/parameter/auth fuzzing modes
Source: [ffuf Mastery: The Ultimate Web Fuzzing Guide](https://infosecwriteups.com/ffuf-mastery-the-ultimate-web-fuzzing-guide-f7755c396b92)

Directory/file bruteforcing with ffuf is already covered above (technique "Directory & file bruteforcing" and the multi-wordlist clusterbomb usage in the pipeline below) — this section is the rest of what ffuf can fuzz beyond paths: virtual hosts, parameters, credentials, and headers, plus the auth/proxy/output flags that make those runs usable against a real target.

**Virtual host (vhost) enumeration** — find hostnames routed differently by the same backend even though DNS never advertised them:
```bash
ffuf -w vhosts.txt -u https://example.com/ -H "Host: FUZZ.example.com"
```
Same server, same IP, but a different `Host:` value can route to a completely different vhost config (staging, admin, internal) — always worth a pass once a target's IP is known, even without a matching subdomain in your enumeration list.

**GET/POST parameter fuzzing** — discover hidden parameters a normal crawl won't surface (complements Arjun/x8/Param Miner-based discovery — see `hidden-parameter-discovery-testing` for the full tool/wordlist/candidate-name-sourcing methodology this ffuf command is one piece of):
```bash
ffuf -w params.txt -u https://example.com/page.php?FUZZ=value -fs <baseline-size>
ffuf -w params.txt -u https://example.com/api -X POST -d 'FUZZ=value' -H "Content-Type: application/x-www-form-urlencoded"
```
Filter by `-fs <baseline-size>` (the response size for a known-bogus parameter) rather than status code — most apps return 200 regardless of whether the parameter did anything, so a *different* response size is the actual signal a parameter was recognized.

**Credential/login brute-force** — password (or paired username:password) fuzzing directly against a login endpoint:
```bash
# Single-field brute-force (fixed username)
ffuf -w passwordlist.txt -X POST -d "username=admin&password=FUZZ" -u https://example.com/login -fc 401,403

# Clusterbomb mode — every username × every password (use only against a test account you control, or with explicit program authorization for credential-stuffing-shaped testing)
ffuf -w users.txt:USER -w passwords.txt:PASS -u https://example.com/login -X POST -d "username=USER&password=PASS" -mode clusterbomb -fc 401,403

# Pitchfork mode — paired entries only (line 1 of users.txt with line 1 of passwords.txt, etc.) — for testing known username:password pairs from a breach list rather than a full cross-product
ffuf -w users.txt:USER -w passwords.txt:PASS -u https://example.com/login -X POST -d "username=USER&password=PASS" -mode pitchfork -fc 401,403
```

**Authenticated/session-aware fuzzing** — carry a session into any fuzzing run, including verb-based ones (pairs directly with `iis-exploitation-testing` technique #2's WebDAV `PUT` testing — swap in `-X PUT` here to fuzz filenames for write access under an authenticated session):
```bash
ffuf -b "SESSIONID=abcd1234; USER=admin" -w wordlist.txt -u https://example.com/FUZZ
ffuf -w wordlist.txt -X PUT -u https://target.com/FUZZ -b 'session=abcdef'
```

**Header-value fuzzing** — fuzz the *value* of a fixed header name (distinct from `403-bypass-testing`'s header-name sweep, which loops different header *names*):
```bash
ffuf -w headers.txt -u https://example.com/ -H "X-Custom-Header: FUZZ"
```

**Route through Burp for visibility** — every fuzzed request lands in Proxy history for manual follow-up on interesting hits:
```bash
ffuf -x http://127.0.0.1:8080 -w wordlist.txt -u https://example.com/FUZZ
```

**Rate control** — throttle down from ffuf's default max speed when a target's WAF/rate-limiter starts dropping requests or you want to stay under a program's stated testing-rate rules:
```bash
ffuf -w wordlist.txt -u https://example.com/FUZZ -rate 50 -t 50
```

**Output for later triage:**
```bash
ffuf -w wordlist.txt -u https://example.com/FUZZ -o results.html -of html
ffuf -w wordlist.txt -u https://example.com/FUZZ -o results.json -of all   # writes every supported format
```

Wordlist sources for all of the above: `github.com/coffinxp/payloads` (curated, target-agnostic payload sets used across several entries in this file) and `github.com/danielmiessler/SecLists` (the general-purpose reference — `Discovery/Web-Content`, `Fuzzing`, `Usernames`/`Passwords` subdirectories cover the modes above).

## Recorded technique: fuzzing-configuration discipline — hidden-path prefixes, extension list, SPA false-negative trap, thread tuning
Source: [Web Fuzzing for Hackers](https://www.intigriti.com/researchers/blog/hacking-tools/web-fuzzing-for-hackers)

Adds config-level refinements on top of the ffuf/dir-bruteforce/vhost coverage already in this file — the source's core thesis is that "tool configuration is what separates meaningful fuzzing from thousands of meaningless results," so treat every item below as a filter/wordlist tweak to layer onto the existing commands, not a new tool.

**Four hidden-path prefix patterns worth a dedicated pass on every target** (beyond the plain directory-list bruteforce above):
```bash
ffuf -w wordlist.txt -u https://target.com/.FUZZ    # dotfiles/hidden dirs: .git/, .env, .DS_Store
ffuf -w wordlist.txt -u https://target.com/-FUZZ    # flag-style: -backup, -old, -tmp
ffuf -w wordlist.txt -u https://target.com/~FUZZ    # tilde/user-home backup convention: ~admin/, ~root/
ffuf -w wordlist.txt -u https://target.com/../FUZZ  # parent-directory traversal probe
```

**Extended high-value extension list** (add to the `-e` list already in the Directory & file bruteforcing command above — that list already covers `.bak/.old/.log/.json/.xml/.config/.env`; these fill the gap):
```
.md                          # Markdown docs, increasingly common for AI-generated/internal notes left in web roots
.db, .sql                    # database files/dumps
.7z, .tar.gz                 # archives (in addition to the already-covered .zip)
.asmx, .ashx, .aspx.bak, .asp, .dll, .exe   # IIS/ASP.NET-specific — cross-reference `iis-exploitation-testing` once one of these hits
```

**SPA false-negative trap:** React/Angular/Vue single-page apps route every path through client-side JS and typically return `200 OK` with near-identical content length for *any* path, including ones that don't actually exist server-side — a naive status-code-only filter (`-mc 200`) makes every fuzzed path look like a hit. Fix: filter strictly on response size/word count (`-fs <SPA-default-body-size>`) rather than status code, or manually diff a known-bogus path's body against the fuzzed result before trusting any "hit" on a target you've fingerprinted as an SPA.

**Thread-count starting points** (tune down from these if a WAF/rate-limiter starts dropping requests — see the `-rate`/`-t 50` guidance already in this file's ffuf reference):
- `-t 350` as a starting point from a VPS/cloud box with real bandwidth.
- `-t 50` to `-t 100` from a home connection, where the bottleneck is your own uplink, not the target.

**Wildcard-safe subdomain bruteforce with `dnsx`:**
```bash
dnsx -l wordlist.txt -d target.com -wd target.com
```
`-wd` auto-detects and filters out wildcard DNS responses (a `*.target.com` record resolving *everything* to the same IP, which would otherwise make every brute-forced name look like a live hit) — always pair wildcard-detection with any DNS-bruteforce pass, whether via `dnsx` here or the `alterx`-based permutation already covered above.

**`dnsx` standalone flag reference** (beyond piping subdomain lists through it, as used elsewhere in this file) — install via `go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest` (relocate the binary with `sudo cp ~/go/bin/dnsx /usr/local/bin` if it doesn't run globally afterward):
```bash
cat domain.txt | dnsx                          # basic alive-domain check
cat domain.txt | dnsx -silent -a -resp          # domains with resolved IP addresses
cat domain.txt | dnsx -silent -a -resp-only     # IP addresses only (clean list for piping to naabu/nmap)
cat domain.txt | dnsx -silent -cname -resp      # CNAME records — reveals third-party services/subdomain-takeover candidates
cat domain.txt | dnsx -silent -resp-only -ptr   # reverse DNS (PTR) lookup from an IP list
```
The `-cname` output doubles as cheap `subdomain-takeover-testing` triage — a CNAME pointing at an unclaimed third-party service (an unclaimed S3 bucket, a deprovisioned Heroku/Azure app) is exactly the signal that skill's takeover check looks for, so run this pass before or alongside `subzy`.

**Debug/internal-flag header fuzzing** — a header-name sweep distinct from `403-bypass-testing`'s access-control-bypass header list (`X-Original-URL`, `X-Forwarded-Host`, etc.) and `web-cache-poisoning-testing`'s unkeyed-header taxonomy — these specifically toggle *application debug/internal behavior* rather than routing or caching:
```
X-Debug: true
X-Dev: true
X-Internal: true
X-Admin-Token: <fuzz>
```
Analysis note: don't rely on status-code changes alone to detect whether one of these did anything — a debug header flip often leaves the status code identical while changing response *size* or adding a *timing* delay (a stack trace or verbose env dump appended to an otherwise-unchanged 200 page), so diff size/word-count/timing the same way the SPA-trap fix above does.

**Additional wordlist source:** Assetnote's parameter/wordlist collections (`wordlists.assetnote.io`) — alongside the SecLists/coffinxp sources already referenced in this file, worth pulling target-technology-specific lists from when the generic `common.txt`/`api-endpoints.txt` lists underperform.

**Common configuration errors this source calls out explicitly (self-check before a fuzzing run):**
1. No clear objective — running one generic wordlist/config against files, parameters, *and* headers at once instead of a config tuned per fuzzing target.
2. Wrong wordlist — a generic list misses the target's actual naming conventions (company terminology, tech-stack-specific paths); seed a custom list from in-page content, JS files, and harvested URL paths (technique #4/JS-secret-hunting above already does this harvesting — feed its output into the wordlist, not just the vuln scanners).
3. Ignoring rate limits — beyond just risking a block, an inconsistent response-time baseline (some requests throttled, some not) corrupts the timing/size-diff signals several of the techniques above depend on.

## Recorded technique: writing custom Nuclei templates (beyond running the 9,000+ stock ones)
Source: [The Ultimate Nuclei Guide: How to Find Bugs with 9,000+ Templates](https://systemweakness.com/the-ultimate-nuclei-guide-how-to-find-bugs-with-9-000-templates-2026-bug-bounty-edition-d5daf02666a1)

Every existing Nuclei entry in this file runs *stock* templates (`-tags cve`, `-t gitExposed.yaml`, etc.) — this covers writing your own YAML template for a target-specific check no public template covers (a custom internal panel path, a company-specific exposed-config filename, an app-specific auth-then-probe flow).

**Basic template anatomy:**
```yaml
id: unique-identifier
info:
  name: Human readable name
  author: creator
  severity: critical/high/medium/low/info
  description: What this checks
http:
  - method: GET
    path:
      - "{{BaseURL}}/endpoint"
    matchers:
      - type: word
        words:
          - "detection string"
```
**Matcher types:** `status` (HTTP status codes), `word` (literal string in response), `regex`, `kval` (extract/match header values). Combine multiple matchers with `matchers-condition: and`/`or` — `and` requires every matcher to hit (reduces false positives on a generic status-200 check), `or` fires on any single match.

**Worked example — confirming a `.git/config` exposure with two matchers ANDed together** (status *and* content, not status alone, since plenty of endpoints return 200 for a nonexistent path on an SPA — see this file's SPA false-negative trap above):
```yaml
id: git-directory-exposed
http:
  - method: GET
    path:
      - "{{BaseURL}}/.git/config"
    matchers-condition: and
    matchers:
      - type: status
        status: [200]
      - type: word
        words:
          - "[core]"
          - "repositoryformatversion"
```

**Multi-step authenticated flow via `cookie-reuse`:** chain a login request into a follow-up authenticated probe within the same template — the second HTTP block automatically carries forward cookies set by the first:
```yaml
http:
  - method: POST
    path: ["{{BaseURL}}/login"]
    body: "username=admin&password=admin"
    matchers:
      - type: word
        words: ["session"]

  - method: GET
    path: ["{{BaseURL}}/admin"]
    cookie-reuse: true
    matchers:
      - type: word
        words: ["admin panel"]
```
This is the template-native equivalent of writing a small auth-then-probe script by hand — useful for confirming any finding that requires being logged in first (an IDOR, an admin-panel exposure) at Nuclei-scan scale across many hosts rather than one-off manually.

**Other template primitives worth knowing:** `extractors` pull data out of a matched response (regex or keyword) for use in later steps or reporting; `payloads` fuzz a parameter across a list of values within the template itself, similar in spirit to `ffuf`'s fuzzing but expressed as a reusable, shareable YAML file instead of a one-off command.

**Validate a template before running it at scale:** `nuclei -validate -t template.yaml` — catches YAML/schema errors before wasting a scan run across a large host list.

**Persistent config file** (`~/.config/nuclei/config.yaml`) — sets default flags so they don't need repeating on every invocation:
```yaml
severity: [critical, high, medium]
rate-limit: 50
bulk-size: 25
concurrency: 10
header:
  - 'User-Agent: BugBounty-Scanner'
```

**Tech-detect-conditional scanning** — gate a targeted tag scan behind a tech-fingerprint check rather than always running every relevant tag set against every host:
```bash
tech=$(httpx -silent -tech-detect -u $TARGET | jq -r '.tech[]')
if echo "$tech" | grep -qi "wordpress"; then
  nuclei -u $TARGET -tags wordpress
fi
```

**Impact framing:** the source notes Nuclei's community template set detected CVE-2025-1974 and shipped Log4Shell-detection templates within hours of public disclosure — faster than most commercial scanners — but also warns that an unfiltered, un-tag-scoped scan against a large host list generates excessive false positives; targeted tag/severity filtering (as already practiced throughout this file's other Nuclei entries) is what turns raw template coverage into actual finding quality.

**Generalize note:** write a custom template (rather than a one-off curl/script check) specifically when the same check needs to run repeatably across many hosts, gets reused across engagements, or is worth sharing/committing to a private template collection (this file already cites `coffinxp/nuclei-templates` as exactly that kind of curated private collection) — a single ad-hoc check is still faster done by hand.

## Recorded technique: IP-deduped chaos→naabu→nmap→nuclei→ffuf pipeline
Source: [A Practical Workflow for Fuzzing and Scanning in Bug Bounty](https://infosecwriteups.com/a-practical-workflow-for-fuzzing-and-scanning-in-bug-bounty-64fa00ded29b) (author: 𝙇𝙤𝙨𝙩𝙨𝙚𝙘, example target: redbull.com)

A six-stage chain that dedupes by **origin IP** rather than by hostname before port/vuln scanning — several subdomains often resolve to the same backend server, so scanning by unique IP instead of unique hostname avoids redundant naabu/nmap/nuclei runs against what is really one host.

```bash
# 1. Subdomain discovery via certificate transparency + DNS aggregation
chaos -d redbull.com -o redbull.txt

# 2. Resolve to live hosts, extract + dedupe the underlying IPs
httpx-toolkit -l redbull.txt -ip -silent | sed -nE 's/.*\[([0-9.]+)\].*/\1/p' | sort -u > ip.txt

# 3. Port scan the deduped IP list (top 100 ports, verified open, rate-limited)
naabu -l ip.txt -top-ports 100 -rate 1500 -verify -silent -o naabu.txt

# 4. Deep service/version fingerprinting — automation script bridges naabu output straight into nmap
python naabutonmap.py -i naabu.txt
# then convert the resulting nmap XML into a readable HTML report
./nmap-parse-output /nmap-out/[timestamp]/nmap_out.xml html > scan.html

# 5. CVE/misconfig scanning against both the IP list and the port-scan output
cat ip.txt | nuclei -tags cve -bs 200
cat naabu.txt | nuclei -tags cve -bs 200

# 6. Multi-wordlist ffuf — fuzzes SUBdomain/IP × backup-FILE-name combinatorially in one run
ffuf -w ip.txt:SUB -w payloads/backup_files_only.txt:FILE -u https://SUB/FILE -mc 200 -rate 50 -fs 0 -c
ffuf -w naabu.txt:SUB -w payloads/backup_files_only.txt:FILE -u https://SUB/FILE -mc 200 -rate 50 -fs 0 -c
```

- `naabutonmap.py`: `https://github.com/coffinxp/scripts/blob/main/naabutonmap.py` (same repo already cited elsewhere in this file for `alienvault.sh`/`virustotal.sh`/`urlscan.py`).
- `nmap-parse-output`: `https://github.com/ernw/nmap-parse-output` — turns raw nmap XML into a browsable HTML report instead of re-reading terminal output.
- `-bs 200` on nuclei is a bulk-size/batch-size flag — sizes the concurrent request batch for large IP/host lists rather than the default.
- The ffuf `-w list:KEYWORD` syntax (two `-w` flags, two different keywords used in the `-u` template) is ffuf's multi-wordlist "cluster bomb" mode — every SUB × FILE combination gets requested, so a single command fuzzes backup-file names across the *entire* deduped host list instead of one host at a time. `-fs 0` filters out empty-body responses (common false-positive shape for backup-file guesses on servers that 200 everything).
- **Triage discipline emphasized by the author**: judge hits by **response size and word count together**, not status code alone — "a 200 OK is just a custom error page that happens to match the size of a real page" is a real false-positive shape worth checking for before reporting. Treat any 403 surfaced during the ffuf sweep as a lead, not a dead end — feed it into `403-bypass-testing` rather than skipping past it.

## Recorded technique: one-script narrow-then-triage pipeline (subfinder→httpx→waymore→katana→nuclei→ffuf), stops at 403 collection
Source: [A Real-World Recon Workflow: One Command, Clean Results](https://medium.com/bug-bounty-hunting-a-comprehensive-guide-in/a-real-world-recon-workflow-one-command-clean-results-0043c6d9b552)

Philosophy stated directly by the author: **"Recon should narrow the attack surface, not explode it."** The whole point of wrapping this in one `./recon.sh target.com` script is to end each run with a small number of curated files worth a human looking at, not a firehose of raw tool output — and to stop automation *before* the exploitation stages (403 bypass, IDOR, privesc), which stay manual by design.

```bash
# 1. Passive subdomain enumeration
subfinder -d target.com -silent -o subs.txt

# 2. Live-host filtering with tech fingerprinting
httpx -l subs.txt -silent -status-code -title -tech-detect -o alive.txt

# 3. Historical endpoint discovery via waymore (broader source aggregation than plain waybackurls/gau —
#    pulls Wayback Machine + additional archives with its own filtering modes)
waymore -i alive.txt -mode U -o waymore_urls.txt

# 4. Live crawl on top of the alive host list
katana -list alive.txt -jc -kf all -silent -o katana_urls.txt

# 5. Severity-triaged vuln scan — only critical/high/medium, not the full template set, to keep output reviewable
nuclei -l alive.txt -severity critical,high,medium -silent -o nuclei.txt

# 6. Parameter extraction from the combined URL set — keep only param-bearing URLs, drop static media
cat waymore_urls.txt katana_urls.txt | grep '=' | grep -vE '\.(jpg|jpeg|png|gif|svg|css|woff|woff2|ttf)$' | sort -u > params.txt

# 7. Precision ffuf pass that deliberately KEEPS 401/403 in the output instead of filtering them out —
#    a 403 here is a lead for 403-bypass-testing, not noise to discard
ffuf -u https://FUZZ.target.com/api -w api_wordlist.txt -mc 200,401,403 -t 15 -ac -of json -o ffuf_403.txt
```

- `waymore`: worth running alongside (not instead of) the plain `gau`/`waybackurls` calls and this skill's own CDX API deep-dive elsewhere in this file — different tools' archive-source coverage and filtering don't fully overlap, so running more than one catches URLs the others miss.
- `-ac` on ffuf is **auto-calibrate** — ffuf baselines the target's own "not found" response shape first and filters those out automatically, which is what makes `-mc 200,401,403` practical here (without it, a wildcard-response server would flood the 200/403 buckets with false positives).
- Output files produced end-to-end: `alive.txt` (validated live hosts), `params.txt` (dedup'd parameter-bearing URLs — feed straight into any injection-class testing), `nuclei.txt` (severity-triaged findings), `ffuf_403.txt` (forbidden endpoints specifically curated for manual follow-up, JSON-formatted for easy re-parsing) — treat `ffuf_403.txt` as the direct hand-off point into `403-bypass-testing` rather than a discard pile, matching this file's existing triage discipline from the chaos→naabu pipeline above.
- **Run-over-run diffing** (source: [How I Automated My Bug Bounty Recon Pipeline Using Nmap, Nuclei, FFUF](https://meetcyber.net/how-i-automated-my-bug-bounty-recon-pipeline-using-nmap-nuclei-ffuf-3b388ff16745)): save each `nuclei -json-export` run's output to a dated file and diff it against the previous run (`jq`/`diff` on the JSON) instead of re-reading the full result set every time — on a recurring/monitored target this surfaces only *net-new* findings since the last pass, the same signal-over-noise discipline as this file's `crtmon` standing-watch entry but applied to vuln-scan output rather than subdomain discovery. Also track connection-timeout/error rates per run as a WAF-blocking indicator distinct from an actual finding, and treat every automated hit as a lead requiring manual confirmation before reporting, not a result on its own.

## Recorded technique: Wayback Machine CDX API deep-dive (beyond plain `waybackurls`)
Source: [Unlock the Full Potential of the Wayback Machine for Bug Bounty](https://infosecwriteups.com/unlock-the-full-potential-of-the-wayback-machine-for-bug-bounty-8b6f57e2637d)

`waybackurls`/`gau` (already used throughout this file) wrap the same underlying CDX API — querying it directly gives finer control over filtering and dedup than the wrapper tools expose, and is faster via `curl` than the browser UI for large domains.

**Raw CDX query — every unique archived URL for a domain + all subdomains:**
```bash
curl 'https://web.archive.org/cdx/search/cdx?url=*.target.com/*&output=text&fl=original&collapse=urlkey' > output.txt
```
`collapse=urlkey` is the key dedup flag — it collapses multiple snapshots of the same URL down to one entry, so the output is a unique URL list rather than a full snapshot-by-snapshot history.

**Server-side extension filtering (via the API's own `filter` param, cheaper than piping through grep for huge domains):**
```bash
curl "https://web.archive.org/cdx/search/cdx?url=*.target.com/*&collapse=urlkey&output=text&fl=original&filter=original:.*\.(xls|xml|xlsx|json|pdf|sql|doc|docx|pptx|txt|git|zip|tar\.gz|tgz|bak|7z|rar|log|cache|secret|db|backup|yml|gz|config|csv|yaml|md|md5|exe|dll|bin|ini|bat|sh|tar|deb|rpm|iso|img|env|apk|msi|dmg|tmp|crt|pem|key|pub|asc)$" | tee output.txt
```
**Equivalent client-side grep** (if you already pulled the unfiltered list, or prefer piping):
```bash
cat out.txt | grep -E '\.xls|\.xml|\.xlsx|\.json|\.pdf|\.sql|\.doc|\.docx|\.pptx|\.txt|\.zip|\.tar\.gz|\.tgz|\.bak|\.7z|\.rar|\.log|\.cache|\.secret|\.db|\.backup|\.yml|\.gz|\.config|\.csv|\.yaml|\.md|\.md5|\.exe|\.dll|\.bin|\.ini|\.bat|\.sh|\.tar|\.deb|\.git|\.env|\.rpm|\.iso|\.img|\.apk|\.msi|\.dmg|\.tmp|\.crt|\.pem|\.key|\.pub|\.asc'
```
That extension list is deliberately broad — it covers spreadsheet/doc leaks (`.xls`, `.doc`, `.pptx`), DB/backup artifacts (`.sql`, `.db`, `.bak`, `.backup`), config/secret files (`.env`, `.yml`, `.config`, `.secret`), crypto material (`.pem`, `.key`, `.crt`), and compiled/installer artifacts (`.exe`, `.apk`, `.msi`) in one pass.

**PDF content scanning for sensitive keywords (not just filtering by `.pdf` extension — actually reading the archived file):**
```bash
cat output.txt | grep -Ea '\.pdf' | while read -r url; do
  curl -s "$url" | pdftotext - - | grep -Eaiq \
    '(internal use only|confidential|strictly private|personal & confidential|private|restricted|internal|not for distribution|do not share|proprietary|trade secret|classified|sensitive|bank statement|invoice|salary|contract|agreement|non disclosure|passport|social security|ssn|date of birth|credit card|identity|id number|company confidential|staff only|management only|internal only)' \
    && echo "$url"
done
```
Requires `pdftotext` (poppler-utils). This is the highest-signal step in the whole technique — an archived PDF matching these keywords is worth manually reviewing even before touching anything else in the URL list.

**Deleted-file recovery via 404s:** browse the Wayback Machine's timeline UI for a URL currently returning 404 on the live site, then step back to an older snapshot — the archived copy can still serve content the live server has since removed (old configs, old admin pages, decommissioned API docs).

**Archived `robots.txt`:** pull historical snapshots of `/robots.txt` specifically — paths a developer *disallowed* from crawling (and therefore never wanted indexed) are exactly the paths worth checking for lingering functionality: `https://web.archive.org/web/*/target.com/robots.txt`.

**Browser-friendly timeline for manual triage:**
```
https://web.archive.org/web/*/target.com/*
```
Use the page's own search bar to filter by extension (e.g. `.xls`, `.pdf`) interactively instead of scripting a query, when eyeballing a smaller target.

**Chrome extension:** the official "Wayback Machine" extension auto-offers an archived snapshot whenever you land on a live 404/403 — useful passively while browsing a target manually, no separate query needed.

**Packaged wrapper script** (`coffinxp/scripts/wayback.sh` — wraps the raw CDX API above with status-code filtering flags, useful when the raw `curl` query is more than you need):
```bash
./wayback.sh example.com -s -sc 200          # all subdomains, live (200) pages only
./wayback.sh example.com -sc 200,302,403     # multiple status codes at once
./wayback.sh example.com -scx 404,500        # exclude codes (strip dead links)
./wayback.sh example.com -e                  # only URLs with specific file extensions
# One-liner straight into a vuln-class filter:
./wayback.sh example.com -s -sc 200 | gf xss
```
`-s` includes all subdomains (needed for wildcard-scope programs), `-sc`/`-scx` are the live-vs-dead-link filters that the raw CDX API's `filter=` param can also do but this wraps more conveniently for repeated use across targets.

## Recorded technique: real-time Certificate Transparency monitoring with crtmon
Source: [Monitor Bug Bounty Targets in Real-Time Using Certificate Transparency Logs](https://infosecwriteups.com/monitor-bug-bounty-targets-in-real-time-using-certificate-transparency-logs-247caa34d0f9) (author: 𝙇𝙤𝙨𝙩𝙨𝙚𝙘)

Every other technique in this file's subdomain-enumeration sections (crt.sh curl query, `chaos`, etc.) is a **one-shot snapshot** — it tells you what subdomains existed at query time. `crtmon` inverts that into a **standing watch**: it tails Certificate Transparency logs continuously and pushes a notification the moment a new cert is issued for a matched domain, so a freshly-stood-up subdomain (often a staging/dev host with weaker security) gets tested within minutes of going live instead of at the next manual recon pass — a real timing edge on multi-hunter programs.

```bash
# Single domain
crtmon -target example.com
# File of domains
crtmon -target domains.txt
# Stdin
cat targets.txt | crtmon -target -
# Custom config + notification channel
crtmon -target example.com -config custom.yaml -notify discord
crtmon -target example.com -notify telegram
crtmon -target example.com -notify both
# Help
crtmon -h
```

Notification config (`~/.config/crtmon/provider.yaml`):
```yaml
# crtmon configuration
# monitor your targets real time via certificate transparency logs

# discord webhook url for notifications
webhook: ""

# telegram bot credentials for notifications (optional)
telegram_bot_token: ""
telegram_chat_id: ""

# target wildcard to monitor
targets:
  -
```
Discord uses a plain webhook URL; Telegram needs a bot token + chat ID — either or both can be filled in to fan alerts out to multiple channels at once.

**Keeping it running 24/7** — the tool itself doesn't daemonize, so persistence is bolted on:
```bash
# Backgrounded on a VPS, survives the SSH session ending
nohup crtmon -target domains.txt
# Auto-restart after a VPS reboot
echo "@reboot nohup crtmon -target github.com > /tmp/crtmon.log 2>&1 &" | crontab -
```

Run this against every in-scope wildcard domain from day one of an engagement, not just the already-enumerated subdomain list — the entire point is catching hosts that don't exist yet at the time Phase 1 recon runs.

## Recorded technique: mass CVE hunting via Shodan facet analysis + Nuclei tag scan
Source: [My 5-Minute Workflow to Find Bugs on Any Website](https://infosecwriteups.com/my-5-minute-workflow-to-find-bugs-on-any-website-c20075320c96)

A different starting point from the rest of this file — instead of "pick a target, enumerate its assets, test each vuln class," this starts from **a specific known CVE/product vulnerability** and finds every internet-facing host running the vulnerable software, filtered down to (or cross-checked against) the current engagement's in-scope IP ranges/ASNs from Phase 1's infrastructure-discovery stage.

**Steps:**
1. Pick a target CVE in popular, widely-deployed software (the article's example: a Grafana vulnerability).
2. Search Shodan for the product/version fingerprint.
3. On the Shodan results page, open **Facet Analysis** → select **"ip"** to organize every matching result by IP address.
4. Extract the IP list — either via `shef` (CLI, no API key required) or a browser bookmarklet:
   ```javascript
   javascript:(function(){var ipElements=document.querySelectorAll('strong');var ips=[];ipElements.forEach(function(e){ips.push(e.innerHTML.replace(/["']/g,''))});var ipsString=ips.join('\n');var a=document.createElement('a');a.href='data:text/plain;charset=utf-8,'+encodeURIComponent(ipsString);a.download='ip.txt';document.body.appendChild(a);a.click();})();
   ```
5. Run a tag-scoped Nuclei scan against the extracted IP list:
   ```bash
   cat ip.txt | nuclei -tags grafana -bs 50 -c 50 -es info
   ```
   `-tags <product>` restricts to templates for that specific product (fast, low-noise); `-bs 50 -c 50` batches/concurrency for scanning at scale; `-es info` excludes info-level noise so only actionable findings surface.

**Scoping this into a per-target engagement:** this technique is naturally internet-wide, but it collapses into ordinary in-scope testing the moment you either (a) restrict the Shodan search with a `net:`/ASN filter to the current target's own IP ranges (from Phase 1b infrastructure discovery), or (b) simply run the `nuclei -tags <product>` scan directly against the current target's own already-enumerated host list once tech-detect has identified the product/version — skip the Shodan-wide step entirely and go straight to the tag-scoped Nuclei scan for a same-target CVE check. Cross-reference `bughunting-workflow` Phase 2's "cross-reference tech stack findings against known CVEs" step — this is the concrete command for that step.

**Lightweight alternative scanner:** **LostFuzzer** — a lighter passive-URL-fuzzing + Nuclei-DAST wrapper for automating this kind of domain-list scan without hand-building the pipeline above.

## Recorded technique: manual bypass checklist (non-automatable)

Source: same article as above.

These don't have a tool command — they're things to try by hand once automation has produced a shortlist:

- **"Boring" endpoints most hunters skip:** `/health` (can leak internal service data), `/metrics` (Prometheus internal stats), `/phpinfo.php` (server config leak), `/console` (sometimes an unauthenticated admin console). Check these on every host in `alive_urls.txt`, not just the obvious app routes.
- **Trusted-header spoofing:** try setting `X-Forwarded-Host: evil.com`, `X-Original-URL: /admin`, `X-Forwarded-For: 127.0.0.1` on requests — apps that blindly trust these headers are vulnerable to SSRF, access-control bypass (route-based authz keyed off `X-Original-URL`), or cache poisoning. See `403-bypass-testing` for the full header/method/path-encoding bypass catalog once a path returns 403/401 specifically.
- **Cheap parameter pollution probe:** `?id=123&id=456` — note whether the server uses the first, last, or both values; this simple test alone has produced paid IDOR bypasses (see `http-parameter-pollution-testing` for the full technique family).
- **Read every error message, don't dismiss them:** a MySQL error string implies SQLi is viable; a stack trace discloses framework + file paths; a message like `"Access denied for user 'root'"` can leak literal database credentials.

## Recorded technique: sensitive-files-and-paths checklist during recon
Source: [Common Sensitive Files You Should Look For During Web Recon](https://freedium-mirror.cfd/https://medium.com/h7w/common-sensitive-files-you-should-look-for-during-web-recon-d4ff35e3d7f0)

A standing checklist of specific well-known files/paths to hit on every target during Phase 1, on top of whatever dir-bruteforce wordlist is already running — these are cheap, static, one-request checks worth doing by hand or scripting into a loop over `alive_urls.txt`, distinct from the dynamic fuzzing covered elsewhere in this file:

| File/Path | Why it's worth checking |
|---|---|
| `/robots.txt` | Directory *names* the site deliberately hid from search engines (`admin`, `backup`, `private`, `test`, `staging`) — a developer's own hint list of paths worth checking first; cross-reference this file's Wayback-CDX entry for *archived* `robots.txt` snapshots, which can reveal since-removed disallow entries the live file no longer lists |
| `/sitemap.xml` | Can enumerate hundreds of URLs at once, including unlisted/orphaned pages never linked from the visible nav |
| `/.well-known/security.txt` | The org's own disclosure policy — contact info, PGP key, and (often) a direct link to their bug bounty program/scope page; a fast way to confirm you're testing something they actually want reports on |
| `/.git/`, `/.git/HEAD`, `/.git/config` | Live version-control exposure — see `github-recon-testing`'s dump/restore workflow (git-dumper/GitTools) once directory listing or `HEAD` is reachable |
| Backup file variants (`backup.zip`, `.tar.gz`, `.sql`, `{name}-backup.zip`) | Full data/source dumps left on the web root by a manual backup step that was never cleaned up |
| `.env`, `.env.production`, `.env.local` | Live application secrets/credentials — cross-reference `github-recon-testing`'s per-service secret regex catalog for what to grep the contents against once found |
| `config.php`, `config.json`, `config.yaml`, `web.config` | Application settings, frequently including DB connection strings or internal hostnames |
| `/swagger`, `/swagger-ui`, `/api/docs`, `/openapi.json` | Full API endpoint/schema reference — see `swagger-ui-xss-testing` for the exploitation angle once found, and `hidden-parameter-discovery-testing` for mining undocumented parameters out of the schema |
| `error.log`, `access.log`, `debug.log` | System activity disclosure — stack traces, internal paths, occasionally credentials logged in cleartext by mistake |

**Recon methodology behind the checklist:** the source combines Google dorking, `katana`/`waymore`/`cariddi` crawling (already run elsewhere in this file for JS-secret hunting and URL collection — just check their output against this path list too instead of a separate crawl), directory brute-forcing, and manual verification of anything a tool flags. Worth internalizing: *"finding one doesn't automatically mean you've discovered a vulnerability"* — most of this checklist is recon signal (what's the tech stack, what's the internal naming convention, is there a bounty program at all) rather than a vulnerability on its own; treat a hit as a lead into the cross-referenced skill above, not a finished report by itself. Also expect most of this list to come back protected on a modern/well-maintained target — the value is in running it on *every* target cheaply, not in expecting a high hit rate on any one target.

## Recorded technique: HTTP status-code triage quick-reference
Source: [HTTP Responses, Status Codes, and Security Vulnerabilities](https://freedium-mirror.cfd/https://medium.com/@HalilIbrahimEroglu/http-responses-status-codes-and-security-vulnerabilities-248be5c50673)

Not a new technique on its own — every individual check below already has a full write-up in its own topic skill. What's useful here is the compact index: which status code to notice mid-recon, and which skill to jump to once you see it. Quoted framing worth internalizing: *"the most valuable intel usually isn't sitting on the UI; it's hiding in the raw HTTP responses"* — treat every non-generic status code during a scan/fuzz pass as a routing signal, not noise to filter out.

| Status | Signal | Where to go |
|---|---|---|
| **101** Switching Protocols | WebSocket upgrade in play — check `Origin` validation (CSWSH) and note WAFs frequently don't deep-inspect this traffic | `websocket-security-testing` |
| **200** among a wall of 401s | a credential-stuffing/brute-force hit landed | `rate-limit-bypass-testing`, `session-auth-testing` |
| **200** on a normally-restricted path (`/.git/HEAD`, `/admin/config.xml`) | sensitive file disclosure | `github-recon-testing`, this file's directory-listing/`.git`-exposure entries |
| **201** Created from an unprivileged session against an admin-only endpoint | broken access control / privilege escalation | `advanced-access-control-testing` |
| **301/302** with a client-controlled destination param | open redirect, or SSRF if the redirect target itself is server-fetched | `open-redirect-testing`, `ssrf-testing` |
| **401** | you've found a real auth boundary — valid target, wrong/missing credentials | (confirms the endpoint is worth further auth-flow testing — see `session-auth-testing`) |
| **403** | path exists and is gated — don't treat as dead | `403-bypass-testing`; and if the 403 flips to 200 on a later revisit, see that skill's passive-monitoring entry |
| **403** on a numeric-ID resource that a *different* ID number returns 200 for | IDOR candidate | `advanced-access-control-testing` |
| **405** Method Not Allowed | the blocked method isn't the only one available — cycle `PUT`/`HEAD`/`PATCH`/others | `403-bypass-testing`'s HTTP-method-tampering category |
| **429** Too Many Requests | an active rate limiter exists — don't stop, bypass it | `rate-limit-bypass-testing` |
| **500** with a verbose stack trace, or flipping on a single `'` | SQL injection candidate (and free schema/DB-version disclosure from the trace itself) | `sqli-waf-bypass-testing` |
| **503/504** correlated with an injected `SLEEP()`/`WAITFOR DELAY` payload | time-based blind SQLi confirmation | `sqli-waf-bypass-testing` |
| **503/504** under normal load, no injected delay | possible weak resource-management/DoS susceptibility — note for report, don't actively DoS the target |  |

## Recorded technique: CeWL-generated target-specific wordlist → Hydra login-form brute-force
Source: [I Cracked 12 Passwords in 3 Hours Using This Free Tool Nobody Talks About (CeWL Tutorial)](https://systemweakness.com/i-cracked-12-passwords-in-3-hours-using-this-free-tool-nobody-talks-about-cewl-tutorial-3f9299010b6d)

**Responsible-scope note before using this:** active login brute-forcing against a live production endpoint risks account lockouts, security-team alerts, and WAF bans, and many programs explicitly restrict or exclude automated login-brute-force testing from scope — check `notes/scope.md` and the program's brute-force/rate-limit rules before running this beyond a handful of confirmatory attempts, and prefer testing against a low-value/throwaway account you control rather than a real employee/customer account.

**Core idea:** a generic rockyou.txt-style wordlist wastes most of its guesses on words that have nothing to do with the target. `CeWL` (Custom Word List generator) crawls the target's own website and spits out a wordlist built entirely from words that actually appear there — company jargon, product names, employee names from staff/about pages — which is dramatically more likely to match a real employee's password than a generic list, since people build passwords out of words meaningful to them and their employer.

**Wordlist generation:**
```bash
# Basic: harvest every word from the target site
cewl techcorp-solutions.com -w techcorp_words.txt

# Deeper crawl, normalized, filtered to plausible password-length words
cewl target.com --lowercase -w target_deep.txt -d 3 -m 6
#   -d 3 : follow links 3 levels deep (not just the homepage)
#   -m 6 : minimum word length 6 (filters out short noise words unlikely to be a password root)

# Harvest email addresses too -> doubles as a username list for the same target
cewl techcorp-solutions.com -n -e -w techcorp_emails.txt
#   -n : count word occurrences
#   -e : also extract email addresses found on the site

# Frequency ranking -- the *most*-repeated terms on the site are the highest-value password-root candidates
cewl target.com -c -w target_deep.txt
```

**Mutation pass before brute-forcing** — raw scraped words are still just words; real passwords append the predictable suffixes people actually use. Take the CeWL output and generate variants with year (`2024`, `2025`), common numeric suffixes (`123`, `1`), and a capitalized-first-letter + special-character-suffix pattern (`Word@`, `Word!`) — a small custom script or a mutation tool (e.g. feeding the base wordlist through `hashcat` rules, or John the Ripper's rule engine) generates this mutated list before the actual attack.

**Login-form brute-force with Hydra:**
```bash
hydra -L target_emails.txt -P target_mutated.txt target.com http-post-form \
  "/login:username=^USER^&password=^PASS^:Invalid"
```
`-L` supplies the CeWL-harvested email list as usernames, `-P` supplies the mutated CeWL wordlist as passwords, and the `http-post-form` module's final colon-delimited argument is: the login path, the POST body template with `^USER^`/`^PASS^` placeholders, and the substring that identifies a *failed* login response (Hydra treats any response *not* containing that string as a potential hit).

**Illustrative result claimed:** a demonstration ("TechCorp" scenario) found passwords like `TechCorp@2025`, `CloudSync123`, and `Johnson2024!` within 15 minutes using a target-tailored wordlist, versus hours with a generic one — the pattern in all three: company/product name + year or a themed word + a numeric/special-character suffix, exactly the shape the mutation pass above is built to generate.

**Generalize note:** this is the password-cracking analogue of the bucket-name-permutation technique already recorded in `cloud-storage-bucket-testing` (which also uses CeWL, but to generate candidate *bucket names* rather than *passwords* — same tool, same "scrape the target's own vocabulary" principle, different target of the brute-force). If the login endpoint has an active rate limiter, this technique alone won't get far — pair it with `rate-limit-bypass-testing` first. A `200` response landing among a wall of `401`s during this attack is exactly the status-code signal already flagged in this file's HTTP status-code triage table above.

**Even cheaper first pass, before building the full CeWL wordlist:** try the organization's own name as both username and password (`<org_name>:<org_name>`) plus SecLists' `Passwords/Default-Credentials/` list against every discovered login panel (admin consoles, CI/CD dashboards, Jenkins, device/router admin UIs) — a surprising fraction of default-credential findings need nothing more targeted than this, and it costs a handful of requests before escalating to the full CeWL/Hydra pipeline above.

<!-- Add new recorded techniques/commands below this line as new workflow/command writeups are processed. -->
