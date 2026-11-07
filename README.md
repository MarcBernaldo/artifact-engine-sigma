# artifact-engine-sigma

Sigma rules for [Artifact Engine](https://github.com/MarcBernaldo/Artifact-Engine),
written for offline DFIR triage of the evidence a collector gathers (KAPE event
logs, memory images, UAC Linux acquisitions, web-server logs). Artifact Engine
downloads this repository with `aeng update` (config key `sigma_rules_repo`) and
runs these rules beside the bundled SigmaHQ sets.

## Layout

```
rules/
  windows/process_creation/        EVTX (Security 4688, Sysmon 1) via hayabusa, and memory images
  windows/builtin/<service>/       one Windows event-log channel (system, security, powershell...)
  windows/<category>/              other Sysmon categories (fire only where Sysmon was installed)
  linux/<category-or-service>/     auditd, process_creation (shell history + ps), syslog keywords
  web/                             webserver access logs
tools/validate.py                  the gate every rule passes (also run by CI)
tests/benign/<folder>.txt          ordinary clean-host events no rule may match
GUIDE.md                           how to write a rule for this engine (also an LLM prompt)
```

## Adding or improving a rule

1. Write it following [GUIDE.md](GUIDE.md) (paste the guide into an LLM to draft
   or review a rule).
2. One rule per file: `YYYY-MM-DD_<product>_<category-or-service>_<slug>.yml`, in
   the folder of its logsource. An improved rule keeps its `id`.
3. `python tools/validate.py` must pass: pySigma parses it with no validator
   issue, required fields, a unique UUIDv4 `id`, level critical/high/medium,
   concrete false positives, no IP or hash in the detection, a logsource the
   engine evaluates, 2+ `# test-match:` and 1+ `# test-nomatch:` lines that
   behave (each nomatch a near miss of a match), no hit in the benign corpus
   `tests/benign/`, and no large overlap with another rule.
4. Commit and push; CI runs the same validation.

A rule rejected for firing on legitimate activity adds that activity to
`tests/benign/<folder>.txt`, so no later rule repeats the mistake.

Contributions are welcome as pull requests; CI runs the same validation. A rule
must never carry case data: no real host names, users, addresses, internal
domains or paths from an investigation.

Requirements for the validator: `pip install "pySigma>=1.4,<2" "pySigma-backend-sqlite>=1.2,<3" pyyaml` (the range Artifact Engine accepts).
