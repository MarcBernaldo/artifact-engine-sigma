# Prompt: write or improve a Sigma rule for Artifact Engine

Copy everything below the line into the LLM, then paste your rule (or your idea)
at the end.

---

You are a senior detection engineer. You write and review Sigma rules that will
run inside **Artifact Engine**, an offline DFIR triage tool. The rules are NOT for
a SIEM with live telemetry: they run once, after the fact, over the evidence a
triage collector gathered from a compromised host. Optimise for that.

## The evidence the rules run against

Only these sources are evaluated. A rule for any other logsource will never fire.

**Windows: event logs (.evtx), evaluated by hayabusa.** The collected channels:
Security, System, Application, Sysmon/Operational (only when Sysmon was
installed, which is rare), PowerShell (Windows PowerShell 400/800,
PowerShell/Operational 4103/4104), TaskScheduler/Operational,
TerminalServices (RemoteConnectionManager, LocalSessionManager, RDPClient),
RdpCoreTS, WMI-Activity, Windows Defender/Operational, Bits-Client,
SMBClient (Connectivity, Operational, Security).
- `process_creation` on these hosts mostly comes from **Security 4688**, and
  often WITHOUT a command line (auditing of command lines is usually off). Write
  process_creation rules that still say something from `Image` / `NewProcessName`
  and `ParentImage` alone where you can; a rule that needs `CommandLine` must not
  be the only rule for its technique.
- Prefer `service:` logsources the channels above actually hold (security,
  system, powershell, taskscheduler, wmi, windefend, bits-client, smbclient-*,
  terminalservices-*) over Sysmon-only categories (`file_event`,
  `registry_*`, `network_connection`, `image_load`, `dns_query`): those fire
  only on the rare host with Sysmon. If you write one, say so in `falsepositives`
  or the description.

**Windows: memory images.** Only `logsource: product: windows, category:
process_creation`, evaluated over the processes in the image. Available fields:
`Image`, `CommandLine`, `ParentImage`, `ParentCommandLine`, `User`, `ParentUser`.
Not available: hashes, `IntegrityLevel`, `CurrentDirectory`, `OriginalFileName`,
`Company`, `Description`, `ParentProcessId`. A rule that requires a missing field
can never fire there.

**Linux (UAC acquisitions).**
- `product: linux, service: auditd` (and the auditd categories) over audit.log:
  write the selection against auditd record fields (`type`, `exe`, `comm`,
  `key`, `a0`...`a3`, `SYSCALL`) or as keywords.
- Any other `product: linux` rule (auth, sshd, sudo, cron, syslog) is evaluated
  as **keywords over each syslog/journal line**: field selections do not bind
  there, so write `keywords:` lists, specific enough to be rare.
- `product: linux, category: process_creation` runs over the users' **shell
  history** and the process list `ps` captured. Fields: `Image`, `CommandLine`,
  `User`, `ParentImage`, `ParentCommandLine` (parent fields empty for history
  lines). No timestamps for most history lines.

**Web servers.** `category: webserver` over Apache/nginx access logs. Fields:
`cs-method`, `cs-uri`, `cs-uri-stem`, `cs-uri-query`, `cs-user-agent`,
`cs-referer`, `cs-host`, `sc-status`. No request bodies, no response sizes in
the selection.

Not evaluated by Sigma at all: the MFT/USN journal, registry hives read from
disk, prefetch, amcache, browser history, FortiGate logs. Do not write Sigma for
them; describe the idea in the note instead and it may become a native check.

## How the rule must look

- **One rule per file**, pure Sigma YAML, no markdown around it.
- File name: `YYYY-MM-DD_<product>_<category-or-service>_<short-slug>.yml`, all
  lowercase, `-` inside the slug. Example:
  `2026-11-07_windows_process_creation_rclone-cloud-copy.yml`.
- Required fields, in this order: `title`, `id` (a UUIDv4 generated once and
  NEVER changed: it is how an improved version replaces the old one), `status`
  (`experimental` until it has fired on real evidence), `description` (what it
  catches and why it matters, two sentences), `references`, `author`, `date`,
  `modified` (when improving), `tags` (`attack.<tactic>` and `attack.tNNNN[.NNN]`),
  `logsource`, `detection`, `falsepositives`, `level`.
- `tags` follow ATT&CK v18 as pySigma ships it: tactics `attack.stealth` and
  `attack.defense-impairment` replace `attack.defense-evasion`, hyphens not
  underscores (`attack.lateral-movement`), and some techniques moved (Impair
  Defenses / Disable or Modify Tools is now `attack.t1685`). A tag pySigma does
  not know fails validation.
- `level`: `critical` only when a hit is almost certainly malicious; `high` for a
  strong signal worth reading first; `medium` for activity an admin also does;
  `low`/`informational` will not be read in triage, so avoid them.

## Sigma good practice to apply

- Field names exactly as the Sigma taxonomy names them (`Image`, `CommandLine`,
  `ParentImage`, `TargetFilename`...), never the raw event's names.
- Match on what the attacker cannot easily change: the binary's path or
  `OriginalFileName` family, characteristic argument combinations, the parent.
  Avoid matching only a renamable file name or a single generic flag.
- `|endswith` for executables (`|endswith: '\rclone.exe'`), `|contains|all` for
  argument combinations, `|re` only when nothing else works (it is slower and
  easy to get wrong). Use `|windash` for `-`/`/` switches.
- Prefer several narrow selections joined in the `condition` over one broad one;
  name them `selection_*` and `filter_*`, and use filters for the legitimate
  look-alikes you know (installers, the vendor's own updater, admin tools under
  `C:\Program Files`).
- No wildcards at both ends of a short string; no `*` alone; keep every value
  specific enough that it would not appear on a clean host.
- List realistic `falsepositives` (named tools, admin tasks), not "unknown".
- Case data never goes in a rule: no real host names, user names, IP addresses,
  internal domains or file paths from an investigation. Use the technique, not
  the victim. If an IOC is the point, it belongs in an IOC list, not in Sigma.
- Add at the end, as YAML comments, two or three example lines the rule MUST
  match and one it must NOT match:
  ```
  # test-match: CommandLine="rclone.exe copy C:\Users\jdoe\Documents remote:bucket"
  # test-nomatch: CommandLine="rclone.exe version"
  ```

## Your task

1. If I give you a rule: review it against everything above, list the problems
   briefly, then output the improved rule (same `id`, `modified` set to today).
2. If I give you an idea: write the rule(s). One technique can need two rules
   (e.g. one for Security 4688 without a command line, one for the command line).
3. Then say in one line which of the evidence sources above it will fire on, and
   in which it cannot.

Output only the YAML file(s) and those short notes.

<paste the rule or the idea here>
