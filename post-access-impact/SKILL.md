---
name: post-access-impact
description: Post-initial-access methodology for bug bounty engagements — what to do after gaining SSH/shell/server access to demonstrate real, reportable impact (privilege escalation, credential harvesting, internal recon, lateral movement) without crossing into destructive or unauthorized territory. Use this during Phase 4 (Validation & Impact) of bughunting-workflow whenever the hunter has just obtained a shell, SSH access, or code execution on a target and needs to escalate the finding's severity responsibly. Also trigger on mentions of privilege escalation, SUID, sudo -l, post-exploitation, lateral movement, or "what next after RCE/shell access".
---

# Post-Access Impact Methodology

Core principle (quoted from source): **"Access is just the door. Impact is what's inside."** Getting a shell is rarely the end of a finding — programs pay for demonstrated impact, and impact is what you find *after* the initial foothold. This skill is the checklist for that phase, scoped to staying safe/ethical (no destructive actions, no real data dumps).

Add new dated entries below as more post-access writeups are processed, rather than creating a new skill.

## The checklist (work through in order)

1. **Confirm access & privilege level**
   ```
   whoami
   id
   hostname
   pwd
   ```
   Establish exactly who you are and where, before doing anything else.

2. **Quick system enumeration**
   ```
   uname -a
   cat /etc/os-release
   ps aux
   ip a
   netstat -tulnp
   ```
   Identify the environment (container vs. VM vs. bare metal, OS/kernel version for known-CVE checks), what's running, and what's listening — `netstat` output is also how you discover internal-only services (admin panels, APIs) not exposed publicly.

3. **Search for sensitive files**
   Check `/home/`, `/var/www/`, `/etc/` for `.env` files, backups, config files, API keys, DB credentials. Look specifically for patterns like `DB_PASSWORD=SuperSecret123` — a found credential is usually worth more to the report than the shell itself, since it demonstrates lateral/downstream impact.

4. **Check sudo permissions**
   ```
   sudo -l
   ```
   Look especially for `NOPASSWD` entries — those are immediate, low-effort privilege escalation paths.

5. **Identify privilege escalation paths**
   ```
   find / -perm -4000 -type f 2>/dev/null
   ```
   Lists SUID binaries — cross-reference unusual/custom ones against known privesc techniques (GTFOBins-style lookups) to see if user→root is possible. Concrete example: if `sudo -l` (step 4) shows a permitted binary like `vim`, `less`, `find`, or `awk` with `NOPASSWD`, that binary's own shell-escape/exec capability (`:!bash` inside vim, `!/bin/bash` inside less's pager) hands you a root shell directly — no exploit needed, just the GTFOBins entry for whatever binary sudo allows. A legacy `nmap` binary with the SUID bit set (not sudo — check the `find`-command output itself for `nmap`) is a classic version of the same pattern: older nmap builds support an interactive mode (`nmap --interactive`) from which `!sh` spawns a shell inheriting nmap's SUID root privileges (source: [Mr. Robot CTF — WordPress Exploitation and SUID Nmap to Root](https://osintteam.blog/mr-robot-wordpress-exploitation-and-suid-nmap-to-root-e8eea00ca695)).

   A second, distinct `nmap` GTFOBins variant worth checking separately: a **`sudo`** (not SUID) `NOPASSWD` entry for `/usr/bin/nmap` on a modern nmap build without `--interactive` support is exploitable via NSE's embedded Lua interpreter instead — write a one-line NSE script that shells out, then pass it with `--script`:
   ```bash
   echo "os.execute('/bin/bash')" > /tmp/root.nse
   sudo /usr/bin/nmap --script=/tmp/root.nse
   ```
   Nmap loads and executes the Lua script with whatever privileges `sudo` grants it, and `os.execute` runs an arbitrary shell command from inside that script — root if the sudoers entry is unrestricted, same end result as the SUID `--interactive` path via a completely different nmap feature (NSE scripting vs. the deprecated interactive shell). Check `sudo -l` for `nmap` specifically, not just the SUID-bit `find` sweep in step 5, since this variant requires no SUID bit at all. (Source: [Ha-Natraj: LFI → Log Poisoning → Apache2 User Hijack → sudo nmap to Root (OffSec PG Play)](https://freedium-mirror.cfd/https://infosecwriteups.com/ha-natraj-lfi-log-poisoning-apache2-user-hijack-sudo-nmap-to-root-offsec-pg-play-dbbd1fa12bee))

   **Writable-service-config + sudo-restart user hijack (intermediate lateral-user step, not straight to root):** when `sudo -l` only grants `NOPASSWD` restart rights on a service (e.g. `sudo systemctl restart apache2`) rather than a directly-exploitable binary, check whether that service's *own config file* is writable by the current low-privilege user despite the service itself running as a different account: `find /etc/<service> -writable 2>/dev/null`. If the config is writable, rewrite the directive that sets which user the service's worker processes run as (Apache's `User`/`Group` directives in `apache2.conf`, substituting the literal target username for the default `${APACHE_RUN_USER}` variable), then trigger the permitted restart — new worker processes spawn under the hijacked identity instead of the service's normal low-privilege account. This is a lateral-user-hijack step (useful when the target identity has its own further escalation path, e.g. a second `sudo -l` entry only that user holds), not a direct root shell — re-run `sudo -l` as the newly-hijacked user, since sudoers rules are frequently scoped per-user rather than uniformly.

6. **Check cron jobs for writable/root-executed scripts**
   ```
   crontab -l
   ls -la /etc/cron*
   ```
   A scheduled script that's world-writable (or writable by your current user/group) but *executed* as root/another user is a delayed privilege escalation: edit the script to add your own command (e.g. append a reverse shell one-liner or a `chmod u+s /bin/bash`), then wait for the next scheduled run. Cheap to check, easy to miss if you only look at sudo/SUID.

7. **Harvest credentials**
   ```
   cat ~/.ssh/id_rsa
   ```
   Also check environment variables, browser-saved data if a GUI session is reachable, and any config file credentials found in step 3. The goal is proving credential reuse/lateral movement is possible, not collecting a trophy list.

8. **Internal reconnaissance**
   Use the `netstat` output from step 2 to map internal dashboards, admin panels, and APIs — these often lack authentication entirely since they were never meant to be reachable from outside.

9. **Evaluate lateral movement**
   Check whether harvested credentials work on other systems/users in the infrastructure. You don't need to fully pivot — demonstrating that a credential *works elsewhere* is usually sufficient proof.

10. **Automate the sweep once you've done it manually once**
    Tools like **linpeas** (Linux) run steps 2–6 above (and more: capabilities, NFS misconfig, kernel-exploit-suggester checks) in one pass and highlight likely-exploitable findings in color — use it to catch anything the manual checklist missed, not as a substitute for understanding *why* each finding matters (a report that just says "linpeas found X" without explaining the mechanism reads weaker than one that shows you understood the misconfiguration).

## Real-impact scenario shapes (use these to frame what you're building toward)

- **Privilege escalation chain**: SSH as low-priv user → misconfigured sudo/SUID → root = full server control.
- **Credential reuse**: config-file DB credentials → confirmed DB access → demonstrated (not executed) data exposure.
- **Internal service exposure**: unauthenticated internal admin panel found via `netstat` → potential account takeover.

## How to demonstrate impact without crossing the line

This is the part that keeps a finding a *bug bounty report* instead of an incident:

- Move deliberately — observe before acting, don't blindly run every command you know.
- Screenshot each escalation step as proof, rather than exfiltrating or dumping actual sensitive data.
- Demonstrate the *path* to impact (e.g. "this credential authenticates successfully against the DB") rather than exploiting it further (e.g. don't actually dump customer records).
- Think "what would an attacker do next" as a mental exercise to describe severity in the report — without actually doing that next thing if it would be destructive or exceed what's needed to prove the point.
- Never cause system damage, modify data, or persist access (no planted backdoors/cron jobs/users) — the goal is proof, not a foothold.

## Reporting structure

- Title should explicitly link the initial access vector to the downstream impact (e.g. "SSH Key Exposure via [X] Leads to Full Server Compromise via Sudo Misconfiguration"), not just describe the initial bug in isolation.
- Include: the initial access method, a step-by-step escalation walkthrough, safe screenshot evidence (not raw sensitive data), and a plain explanation of business risk.
- Avoid: dumping actual sensitive data in the report, over-exploiting beyond what's needed to prove impact, causing any system damage.

## Chaining

Apply during **Phase 4 (Validation & Impact)** of `bughunting-workflow` — this is specifically the step between "I found an RCE/got a shell" (Phase 3 result) and "here's the impact I'm reporting" (Phase 5). Also relevant whenever another topic skill's technique results in code execution or shell access (e.g. a chained path-traversal → SSH-key-read finding from `path-traversal-testing`'s escalation section) — this checklist is what to run next.

## Sources

- [What I Do After Gaining Initial Access (SSH) — Real Impact](https://medium.com/bug-bounty-hunting-a-comprehensive-guide-in/what-i-do-after-gaining-initial-access-ssh-real-impact-0492d9f15bdf) — processed 2026-09-22 via freedium mirror (WebFetch succeeded directly). Original source for the core checklist (steps 1-5, 7-9 above).
- [Privilege Escalation: From Low Access to Full Control — Real-World Guide](https://medium.com/bug-bounty-hunting-a-comprehensive-guide-in/privilege-escalation-from-low-access-to-full-control-real-world-guide-9b0a922e1feb) — processed 2026-09-24 via freedium mirror (WebFetch succeeded directly). Added cron-job analysis (step 6), the GTFOBins sudo-binary shell-escape example in step 5, and linpeas automation (step 10).
- [Ha-Natraj: LFI → Log Poisoning → Apache2 User Hijack → sudo nmap to Root (OffSec PG Play)](https://freedium-mirror.cfd/https://infosecwriteups.com/ha-natraj-lfi-log-poisoning-apache2-user-hijack-sudo-nmap-to-root-offsec-pg-play-dbbd1fa12bee) — processed 2026-10-01 via freedium mirror (WebFetch succeeded directly). Added the `sudo nmap --script` NSE-Lua privesc variant and the writable-service-config + sudo-restart user-hijack intermediate step (step 5). The LFI→log-poisoning initial-access half of this chain is recorded in `path-traversal-testing` instead.

<!-- Add new recorded techniques below this line as new post-access writeups are processed. -->
