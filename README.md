# CyberArmy V10.7.15

CyberArmy is a conservative game-security assessment toolkit. It validates an
explicit target scope, blocks private-network destinations, applies an
authorization policy, performs passive reconnaissance, and produces Markdown
reports.

## Setup

```bash
cd CyberArmyV10.7.15
python -m venv .venv
python -m pip install -r requirements.txt
```

For a reproducible development/test environment on Python 3.12, install the
tested lock set instead:

```bash
python -m pip install -r requirements-dev.txt
```

Run commands from that directory:

```bash
python command_center.py --config config.yaml --validate
python command_center.py --config config.yaml --recon example.com
python command_center.py --config config.yaml --scan
```

Reconnaissance and scanning remain blocked until the policy hash is valid, the
policy is acknowledged, and the kill switch is disabled. Only test systems for
which you have explicit authorization.

## Deploy on Kali Linux (or Debian / Ubuntu)

On a fresh Kali VM, one command clones-and-bootstraps: it creates an isolated
virtualenv, installs the dependencies, and runs the test suite as a self-check.
It never contacts a target — it only sets the tool up.

```bash
git clone https://github.com/minhkien0412-debug/ki-m-th-game.git
cd ki-m-th-game
./setup.sh              # runtime deps + unittest self-check
```

If `python3-venv`/`pip` or the `lxml` build is missing on a minimal image, let
the script install the system packages first (needs sudo):

```bash
./setup.sh --apt        # apt-get the system packages, then set up
./setup.sh --dev        # use the pinned lock set and run pytest (Python 3.12)
```

Then activate the environment and validate your profile before any testing:

```bash
source .venv/bin/activate
cd CyberArmyV10.7.15
python command_center.py --config config.yaml --validate
```

Kali is a means to run this authorized-testing toolkit; it does not grant
authorization. Every active mode stays fail-closed — configure the relevant
profile (`hackerone` / `local_lab` / `console_lab` / `integrity`) and only test
systems you are explicitly permitted to.

## Tests

```bash
python -m unittest discover -s tests -v
```

## Passive analysis and findings

The `--scan` command runs only SAFE, passive validators over evidence that was
already collected for the mission (nothing is injected and no active traffic is
generated). When collected traffic exists, the validators report real,
evidence-backed findings:

- `security_headers` — missing/weak security headers (CSP, HSTS,
  X-Content-Type-Options, clickjacking protection, Referrer-Policy) and session
  cookies missing `Secure` / `HttpOnly` / `SameSite`.
- `reflection` — test markers reflected unencoded in response bodies (possible
  injection sink for manual XSS review).
- `authorization_boundary` — sensitive endpoints that returned success with no
  authorization on the request, and inconsistent auth enforcement.

Findings are de-duplicated by a stable signature (repeats increment an
`occurrences` count) and sorted by severity. With no collected evidence the scan
reports nothing — it never fabricates a result.

## Offline game-integrity / anti-cheat analysis

`--analyze-integrity` runs an offline, defensive anomaly triage over a telemetry
or event CSV that you own. It makes no network contact; it flags values that are
physically impossible or statistically anomalous (time scaling, speed hacks,
score injection). Configure optional hard bounds under an `integrity` section in
`config.yaml`:

```yaml
integrity:
  mad_threshold: 6.0
  bounds:
    player_speed_mps: {min: 0, max: 12}
```

```bash
python command_center.py --config config.yaml --analyze-integrity telemetry/owned-session.csv
```

It is a triage aid, not a full anti-cheat runtime: it surfaces rows worth a
human's attention with the evidence for why.

### Declarative anti-cheat rules

Each game has its own physics and economy, so encode *your* game's rules under
`integrity.rules` and the analyzer evaluates them offline (rules are data, never
code — nothing is `eval`'d). Supported `type` values: `max`, `min`, `max_delta`
(jump between consecutive rows), `max_rate` (change per unit of a `per` column),
`monotonic` (`increasing`/`nondecreasing`/`decreasing`/`nonincreasing`), and
`allowed_set`.

```yaml
integrity:
  rules:
    - {id: speed-cap,    type: max,       column: speed_mps, value: 12}
    - {id: no-teleport,  type: max_delta, column: pos_x,     value: 50}
    - {id: time-forward, type: monotonic, column: t_ms,      direction: nondecreasing}
    - {id: score-rate,   type: max_rate,  column: score, per: t_ms, value: 5}
```

## Coverage-guided fuzzing (Python harness)

In addition to the black-box native fuzzer (`--lab-fuzz`), the lab can fuzz a
Python harness with real edge-coverage feedback, keeping inputs that reach new
code and shrinking crash reproducers. The harness is a callable in the workspace
taking one `bytes` argument. (For an opaque prebuilt binary, run a
sanitizer/coverage-instrumented build under `--lab-fuzz`; its crash triage now
parses ASan/UBSan reports.)

```bash
python command_center.py --config config.yaml \
  --lab-cov-fuzz mypackage.parser_harness:parse --lab-cov-seed samples/seed.bin --lab-fuzz-cases 100
```

## OWASP ZAP integration

Two ways to work with OWASP ZAP, both fail-closed:

**Import ZAP alerts for triage** — read a ZAP JSON export, normalize it to
findings, filter to the HackerOne scope, and write a report:

```bash
python command_center.py --config config.yaml --zap-import zap-alerts.json
```

ZAP alerts are *scanner output*: verify each manually and do **not** submit raw
scanner output where a program excludes it (PlayStation does).

**Drive ZAP spider / active scan from the terminal** (requires a running ZAP and
`pip install zaproxy`). Automated scanning sends traffic, so it is authorized
**only** for self-hosted loopback targets, or hosts you explicitly attest are
permitted. It **refuses to scan a HackerOne in-scope target** — PlayStation and
most programs list scanner output as out of scope and forbid disruption; use ZAP
as a passive proxy with manual testing for those.

```yaml
zap:
  api_url: "http://127.0.0.1:8080"
  api_key: ""                       # or set ZAP_API_KEY
  spider_max_duration_min: 5
  scan_poll_seconds: 5
  automated_testing_allowed: false  # true ONLY for a program whose policy permits it
  authorization_reference: ""
  allowed_hosts: []                 # hosts you are authorized to actively scan
```

```bash
python command_center.py --config config.yaml --zap-scan http://127.0.0.1:8080/
python command_center.py --config config.yaml --zap-active-scan http://127.0.0.1:8080/
```

## PlayStation HackerOne safe mode

This mode is intentionally fail-closed. It does not contain a built-in list of
PlayStation assets because program scope changes over time. Before each testing
session:

A filled-in starting point is provided at
`examples/hackerone_playstation.example.yaml` (a dated scope snapshot). Copy it,
then set your handle and refresh the review timestamp — do not rely on the
snapshot; re-check the live page each session.

1. Sign in to the official PlayStation program at
   <https://hackerone.com/playstation/policy_scopes>.
2. Copy only currently in-scope assets into `config.yaml` under
   `hackerone.scope_assets`. Treat an apex domain and `*.domain` as separate
   assets; a wildcard entry intentionally does not authorize the apex.
3. Set your HackerOne handle, the current UTC review timestamp,
   `acknowledged_current_policy: true`, and finally `enabled: true`.
4. Validate the profile and target before generating any traffic.

```bash
python command_center.py --h1-validate-profile
python command_center.py --h1-check-target https://verified-target.example/path
python command_center.py --h1-authorize http_head https://verified-target.example/path
```

The only networked HackerOne operations provided are passive certificate
transparency discovery and one metadata-only `HEAD` request. The `HEAD` request
does not follow redirects and does not collect a response body.

```bash
python command_center.py --h1-passive-recon verified-target.example
python command_center.py --h1-observe-head https://verified-target.example/path
```

To create a report draft, copy
`examples/hackerone_finding.example.json`, replace every placeholder with a
manually confirmed and sanitized result, then run:

```bash
python command_center.py --h1-draft-report examples/my-confirmed-finding.json
```

Drafts are never submitted automatically. Re-check scope, impact, evidence and
third-party data before manually submitting through HackerOne. Do not use this
tool for denial of service, brute force, credential stuffing, phishing, spam,
social engineering, destructive testing or bulk data access.

## Isolated game-security research lab

The local lab implements the defensive portions of the supplied four-phase
methodology while remaining restricted to self-hosted targets:

- Phase I: deterministic boundary-value and limited-concurrency checks against
  an explicit loopback API only.
- Phase II: offline byte, entropy and string analysis of an owned protocol
  corpus. It cannot sniff, modify or forward packets.
- Phase III: generation of an observation-only Frida symbol trace. The script
  logs entry/exit events and cannot replace returns or write memory.
- Phase IV: bounded mutation fuzzing of an allowlisted executable and seed file
  inside the configured workspace. It retains crash inputs but creates no
  shellcode, ROP chain or privilege-escalation primitive.

Before use, review `config.yaml`, set `local_lab.workspace_root` to the isolated
lab directory, and set both `enabled` and `authorized_self_hosted_only` to
`true`. Set `authorization_reference` to your internal lab approval, ownership
record or engagement identifier. Set `network_isolated: true` only after an OS,
VM or firewall boundary prevents the target process from reaching external
networks while preserving loopback. Never point this profile at production or
third-party systems.

```bash
python command_center.py --lab-validate
python command_center.py --lab-api-boundary http://127.0.0.1:8080/test examples/local_payload.example.json quantity integer
python command_center.py --lab-analyze-protocol samples/owned_capture.bin
python command_center.py --lab-build-trace OwnedParserFunction
python command_center.py --lab-fuzz samples/owned_target.exe samples/valid_seed.bin --lab-fuzz-cases 25
```

The following directives from the supplied methodology are deliberately not
implemented: payment/fulfillment response rewriting, premium entitlement
override, live packet patch-and-forward, TLS pinning bypass, memory return-value
patching, kernel exploitation, shellcode and ROP construction.

## Authorized PlayStation dev/test-kit bridge

The console bridge connects this repository to tools from an official local
PlayStation SDK installation without embedding proprietary binaries, command
names, credentials, or documentation. Sony's public partner page states that
registered partners receive development support, tools and testing systems:
<https://partners.playstation.net/>. Partner registration and the SDK/dev-kit
provisioning process therefore remain external prerequisites.

This bridge adds the repository-side pieces that were previously missing:

- fail-closed attestations for partner access, official SDK installation,
  dev/test-kit ownership, human review and network isolation;
- a dry-run command planner that hashes the owned build before deployment;
- an opt-in SDK runner using an argv list and `shell=False`;
- crash/log import with SHA-256 and a JSON chain-of-custody manifest;
- an offline symbolication hook using the official tool configured locally;
- deterministic indexing of game-input corpora for repeatable testing.
- capability-specific validation, so offline corpus/crash work does not require
  an installed runner or symbolicator;
- a guarded preflight/deploy/launch/collect/stop workflow that always attempts
  cleanup after launch and writes a redacted session audit;
- normalized crash fingerprints and a persistent duplicate-occurrence index;
- offline CSV telemetry summaries for frame time, memory, CPU/GPU and network.

Start from `examples/console_lab.example.yaml`. Keep
`allow_device_execution: false` until the dry-run command is reviewed. The
first item of each configured command must be an existing `.exe`; supported
placeholders are `{artifact}`, `{kit_id}`, `{crash}`, `{symbols}`, and
`{output_dir}`. Secrets must not be stored in the YAML file.

```bash
python command_center.py --console-validate
python command_center.py --console-validate-capability workflow
python command_center.py --console-plan builds/owned-game.pkg
python command_center.py --console-workflow-plan builds/owned-game.pkg
python command_center.py --console-index-corpus samples/owned-corpus
python command_center.py --console-import-crash inbox/exported-crash.dmp
python command_center.py --console-symbolicate state/console_artifacts/imports/ID/exported-crash.dmp symbols/owned-symbol-map.log
python command_center.py --console-analyze-telemetry telemetry/owned-session.csv
```

After validating the generated argv and the physical/network lab boundary, set
`allow_device_execution: true` and run an owned build on the configured kit:

```bash
python command_center.py --console-run builds/owned-game.pkg
python command_center.py --console-workflow builds/owned-game.pkg
```

Telemetry CSV requires `frame_time_ms`; optional numeric columns are
`memory_mb`, `cpu_percent`, `gpu_percent`, and `network_kbps`. Rows with invalid
or negative values are counted and ignored. The configured frame budget is used
to report over-budget frames, while min/average/p95/max are computed offline.
Copy `examples/telemetry.example.csv` when preparing the first export.

The bridge does not turn a retail PS4/PS5 into a dev kit, install an SDK, obtain
partner approval, or bypass platform protections. SDK-specific command names
must be copied from the official documentation available to the approved
partner account. HackerOne testing remains separately governed by the current
program scope in the `hackerone` profile.
