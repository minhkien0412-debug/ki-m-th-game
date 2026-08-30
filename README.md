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

Run commands from that directory:

```bash
python command_center.py --config config.yaml --validate
python command_center.py --config config.yaml --recon example.com
python command_center.py --config config.yaml --scan
```

Reconnaissance and scanning remain blocked until the policy hash is valid, the
policy is acknowledged, and the kill switch is disabled. Only test systems for
which you have explicit authorization.

## Tests

```bash
python -m unittest discover -s tests -v
```

## PlayStation HackerOne safe mode

This mode is intentionally fail-closed. It does not contain a built-in list of
PlayStation assets because program scope changes over time. Before each testing
session:

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
