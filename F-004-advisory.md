TITLE (paste into the advisory Title field):
agentless <arguments> bypasses the upload-configuration remote-commands policy (check_remote_commands)

SUGGESTED SEVERITY: Low (provisional Low in REPORT.md; file as Low)
AFFECTED PRODUCT/ECOSYSTEM: pip/other — use: Wazuh manager, affected versions 4.14.10 and 4.14.12 dev branch (not fixed in dev), component framework/wazuh/core/utils.py (check_remote_commands) via framework/wazuh/manager.py (update_ossec_conf)

DESCRIPTION (paste into the Description field):
## Title
agentless `<arguments>` bypasses the upload-configuration
remote-commands policy (`check_remote_commands` does not check it)

## Affected
- Product: Wazuh manager
- Versions tested: **v4.14.10** and the **4.14.12 dev branch** — unlike F-003
  (prefilter_cmd), this vector is **not fixed in dev**
- Component: `framework/wazuh/core/utils.py` — `check_remote_commands()`
  (called from `framework/wazuh/manager.py:356` `update_ossec_conf` via
  `validate_wazuh_xml(new_conf, config_file=True)`), entry point
  `manager:update_config` (`@expose_resources`)
- Prerequisites: an API user with `manager:update_config`, on a deployment
  where the admin has explicitly disabled remote commands in `api.yaml`
  (`upload_configuration.remote_commands`: `localfile.allow: False`,
  `wodle_command.allow: False`); a host already registered in
  `agentless/.passlist` (admin-created via `register_host.sh`), with
  `wazuh-agentlessd` running and a shipped script type
  (e.g. `ssh_generic_diff`)
- Classification: CWE-693 (Protection Mechanism Failure),
  CWE-862 (Missing Authorization) — policy-bypass framing
- Provisional severity: Low. This is an opt-in policy bypass only, not a
  default-deployment finding. No unauthenticated access, cluster-peer
  reachability, default-deployment RCE, or arbitrary-host claim is made.

## Summary
`check_remote_commands()` is the gate that lets an admin delegate
`ossec.conf` upload without granting command execution: when
`upload_configuration.remote_commands` disallows localfile / wodle
commands in `api.yaml`, adding one to an uploaded config raises
WazuhError 1124. In 4.14.10 it checks only the `localfile` and `wodle`
hierarchies — it does **not** check the `<agentless>` section, and
neither does the 4.14.12 dev branch, which only adds the syscheck
`prefilter_cmd` check (F-003). An API user with `manager:update_config`
on a deployment where the admin disabled remote commands can therefore
add an `<agentless>` entry whose `<arguments>` are sent verbatim as a
shell command over SSH to an already-registered agentless host, and
executed there as the stored SSH user.

## Demonstrated (real release code — `harness_f004.py`)
Run: `tools/venv/bin/python findings/F-004-agentless-arguments/harness_f004.py <tree>`
| # | Test | v4.14.10 | dev 4.14.12 branch |
|---|------|----------|--------------------|
| T1 | agentless added, both remote cmds disallowed | **FAIL — accepted, no error** | **FAIL — accepted, no error** |
| T2 | agentless added, only localfile disallowed | **FAIL — accepted** | **FAIL — accepted** |
| T3 | control: localfile `full_command` added, both disallowed | PASS — 1124 "localfile" | PASS — 1124 |
| T4 | control: agentless unchanged, both disallowed | PASS — accepted | PASS — accepted |
| T5 | agentless added, defaults (both allowed) | accepted (expected) | accepted (expected) |

## Execution chain (code-read, not live-run)
1. `wazuh.manager.update_ossec_conf` (`framework/wazuh/manager.py:356`,
   `@expose_resources` `manager:update_config`) calls
   `validate_wazuh_xml(new_conf, config_file=True)` →
   `check_remote_commands()` (`core/utils.py:866` release / `:952` dev).
   Release checks only `localfile` and `wodle` hierarchies; dev adds only
   `PREFILTER_HIERARCHY`. Neither tree mentions `agentless`
   (`grep -c agentless` on dev `core/utils.py` = 0).
2. The C parser accepts the section on the manager:
   `src/config/config.c` maps `agentless` as a server config section;
   `src/config/agentlessd-config.c` `Read_CAgentless` reads `<type>`,
   `<host>`, `<state>`, `<frequency>` and `<arguments>` verbatim. The only
   guards are on `<type>`: parent-folder references are rejected and the
   script must exist under `AGENTLESSDIR` (`var/agentless/`).
3. `src/agentlessd/agentlessd.c` `command_args()` builds
   argv = `[AGENTLESSDIR/<type>, use_su/use_sudo?, <host>, <arguments>
   split on spaces]` and `run_periodic_cmd()` runs it with `wpopenv()`
   on the configured schedule (`<frequency>`, default 86400s,
   attacker-settable, e.g. 60s). `wazuh-agentlessd` is in the server
   `DAEMONS` list (`src/init/wazuh-server.sh:30`).
4. The shipped expect scripts take `$args` (argv after the hostname,
   `src/agentlessd/scripts/main.exp`) and send it verbatim to the remote
   host over SSH. `ssh_generic_diff`: `spawn ssh $hostname` then
   `send "$args\r"`. So `<arguments>id; cat /etc/passwd</arguments>` runs
   that shell command on the agentless host.
5. `<run_command>` is **not** the vector: it is only reported via
   `getAgentlessConfig()` JSON. The vector is `<arguments>`.

## Impact (bounded — read before filing)
- **Opt-in policy only.** `api.yaml` defaults are `remote_commands:
  localfile.allow: True, wodle_command.allow: True`
  (`api/api/configuration.py:77`), so on a default deployment the check
  does not apply to *any* remote command and this is not a bypass at all.
  The finding only bites where an admin explicitly disabled remote
  commands — which is precisely the hardening the vendor's check exists
  to enforce.
- **Privileged caller.** The entry point needs `manager:update_config`
  (can already rewrite the whole `ossec.conf`). This is NOT the
  cluster-peer / DAPI threat model of F-001/F-002; no DAPI reachability
  for `update_ossec_conf` is claimed here.
- **Needs a pre-registered agentless host.** The expect scripts look the
  host up in `agentless/.passlist` (created by the admin's
  `register_host.sh`); an unregistered host fails with "Password not
  found" and nothing executes. So this can only reach hosts the admin
  already monitors agentlessly, as the SSH user whose credentials the
  manager stores — it cannot pick an arbitrary new host or new
  credentials. It also needs `wazuh-agentlessd` running and a shipped
  script type (`ssh_generic_diff` ships by default).
- **Not live-proven end to end.** The Python gate was executed on both
  trees; the C-side execution chain (config parse → agentlessd schedule
  → expect script → SSH command) is code-read only. No live manager, no
  registered host, no SSH execution observed here.
- **Not fixed in dev.** `src/agentlessd/agentlessd.c` and
  `src/config/agentlessd-config.c` are identical between 4.14.10 and
  the 4.14.12 dev branch, and dev `check_remote_commands` has no
  agentless check. Unlike F-003, this is a live gap in the current dev
  branch, not just a release-side leftover.
- Do NOT file this with F-002's cluster-peer threat model, a
  default-deployment claim, or an arbitrary-host claim — none is
  supported.

## Prior art / duplicate check
Web search 2026-11-11 for "Wazuh agentless arguments remote command CVE"
returned no matching public advisory for this vector. Closest prior art
in the same policy area: CVE-2026-74041 (ossec.conf validator vs
logcollector `LOG_FORMAT` case mismatch bypassing the same remote-command
validation, fixed in 4.14.8) and CVE-2025-15616 (logcollector/maild/
Kaspersky config shell injection, before 4.8.0) — neither covers
agentless `<arguments>` in 4.14.10. The 4.14.12 dev branch still contains
the gap, so no dev fix exists to reflect a private report; only vendor
triage can confirm novelty, as with F-001/F-002.

## Relationship to F-003
Same incomplete `check_remote_commands` gate as F-003 (prefilter_cmd),
but F-003 is fixed in dev and this one is not. Options: (a) file this as
a separate Low GHSA using this draft; (b) fold it into the F-003 filing
as an additional vector of the same gate — the F-003 draft's "residual
mootness" question is now answered by this finding, and the vendor's
prefilter-only fix is demonstrably incomplete; (c) park it as a
hardening note. Filing route (b) is arguably the cleanest, since both
are halves of one incomplete gate.

## Recommended remediation
Extend `check_remote_commands()` to cover the agentless `<arguments>`
hierarchy (analogous to the dev branch's `PREFILTER_HIERARCHY` addition
for F-003), and audit the remaining `ossec.conf` settings for any other
command-execution vector reachable while `remote_commands` is disabled.
The F-004 audit already checked active-response `<command>`,
integrator `<name>`, localfile/wodle `<command>`, syscheck
`<prefilter_cmd>`, and the CVE-2026-74041 `LOG_FORMAT` variant — agentless
`<arguments>` was the one remaining hole found.

## Evidence in this packet
- `harness_f004.py` — runs the matrix above against either tree:
  `python harness_f004.py wazuh-4.14.10-release` / `python harness_f004.py wazuh-4.14`
- `REPORT.md` — full analysis, evidence table, execution chain, and bounded impact
