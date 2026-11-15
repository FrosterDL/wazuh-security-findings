TITLE (paste into the advisory Title field):
syscheck prefilter_cmd bypasses the upload-configuration remote-commands policy (check_remote_commands)

SUGGESTED SEVERITY: Low (provisional Low–Moderate in REPORT.md; file as Low)
AFFECTED PRODUCT/ECOSYSTEM: pip/other — use: Wazuh manager, affected version 4.14.10, component framework/wazuh/core/utils.py (check_remote_commands) via framework/wazuh/manager.py (update_ossec_conf)

DESCRIPTION (paste into the Description field):
## Title
syscheck `<prefilter_cmd>` bypasses the upload-configuration
remote-commands policy (`check_remote_commands` does not check it)

## Affected
- Product: Wazuh manager
- Version tested: **v4.14.10**
- Component: `framework/wazuh/core/utils.py` — `check_remote_commands()`
  (called from `framework/wazuh/manager.py:355` `update_ossec_conf` via
  `validate_wazuh_xml(new_conf, config_file=True)`), entry point
  `manager:update_config` (`@expose_resources`)
- Prerequisites: an API user with `manager:update_config`, on a deployment
  where the admin has explicitly disabled remote commands in `api.yaml`
  (`upload_configuration.remote_commands`: `localfile.allow: False`,
  `wodle_command.allow: False`)
- Classification: CWE-693 (Protection Mechanism Failure),
  CWE-862 (Missing Authorization) — policy-bypass framing
- Provisional severity: Low. This is an opt-in policy bypass only, not a
  default-deployment finding. No unauthenticated access, cluster-peer
  reachability, or default-deployment RCE is claimed.

## Summary
`check_remote_commands()` is the gate that lets an admin delegate
`ossec.conf` upload without granting command execution: when
`upload_configuration.remote_commands` disallows localfile / wodle
commands in `api.yaml`, adding one to an uploaded config raises
WazuhError 1124. In 4.14.10 it checks only the `localfile` and `wodle`
hierarchies — it does **not** check syscheck `<prefilter_cmd>`, a setting
that syscheckd executes via `wpopenv()` while hashing files. An API user
with `manager:update_config` on a deployment where the admin disabled
remote commands can therefore add `<prefilter_cmd>` to `ossec.conf` and
get command execution as the syscheckd user (root on a standard manager
install). The dev 4.14.12 branch adds exactly this check (error 1124,
"syscheck prefilter_cmd").

## Demonstrated (real release code — `harness_f003.py`)
Run: `tools/venv/bin/python findings/F-003-prefilter-cmd-bypass/harness_f003.py <tree>`
| # | Test | v4.14.10 | dev 4.14.12 branch |
|---|------|----------|--------------------|
| T1 | prefilter added, both remote cmds disallowed | **FAIL — accepted, no error** | PASS — WazuhError 1124 "syscheck prefilter_cmd" |
| T2 | prefilter added, only localfile disallowed | **FAIL — accepted** | PASS — 1124 |
| T3 | control: localfile `full_command` added, both disallowed | PASS — 1124 "localfile" | PASS — 1124 |
| T4 | control: prefilter unchanged, both disallowed | PASS — accepted | PASS — accepted |
| T5 | prefilter added, defaults (both allowed) | accepted (expected) | accepted (expected) |

## Execution chain (code-read, not live-run)
1. `wazuh.manager.update_ossec_conf` (`framework/wazuh/manager.py:355`,
   `@expose_resources` `manager:update_config`) calls
   `validate_wazuh_xml(new_conf, config_file=True)` →
   `check_remote_commands()` (`core/utils.py:866` release / `:952` dev).
2. Release `check_remote_commands` checks only `localfile` and `wodle`
   hierarchies. Dev adds `PREFILTER_HIERARCHY =
   ['ossec_config', 'syscheck', 'prefilter_cmd']` and raises 1124 when
   either remote-command setting is disallowed
   (`core/utils.py:1019,1039-1043` dev).
3. A `<prefilter_cmd>` in the manager's own `ossec.conf` is accepted by
   the C parser: `src/config/syscheck-config.c:2239-2255` — the
   `allow_remote_prefilter_cmd` gate applies only to agent-remote config
   (`CAGENT_CONFIG`), not to the manager's local config.
4. `src/syscheckd/src/create_db.c:1424` hashes files via
   `OS_MD5_SHA1_SHA256_File(file, syscheck.prefilter_cmd, ...)`; that
   function (`src/os_crypto/md5_sha1_sha256/md5_sha1_sha256_op.c`) splits
   the command on spaces, appends the hashed filename, and runs it with
   `wpopenv()` — i.e. executes it, once per hashed file.

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
- **Not live-proven end to end.** The Python gate was executed; the
  C-side execution chain is code-read only. No live manager/syscheckd
  run, so the exact trigger timing (next syscheck scan / restart) and
  the process user are as documented for a standard install, not
  observed.
- **Residual mootness question — ANSWERED 2026-11-11 by F-004.** The
  audit in findings/F-004-agentless-arguments/REPORT.md checked the
  remaining `ossec.conf` command-execution surfaces: agentless
  `<arguments>` also bypasses `check_remote_commands`, on **both**
  4.14.10 and the 4.14.12 dev branch (not fixed in dev). So the vendor's
  prefilter-only dev fix is incomplete — if filing F-003, consider
  folding F-004 in as a second vector of the same gate (see
  findings/F-004-agentless-arguments/advisory_paste.md) rather than
  filing F-003 alone.
- Do NOT file this with F-002's cluster-peer threat model or with a
  default-deployment RCE claim — neither is supported.

## Prior art / duplicate check
Web search 2026-11-10 for "Wazuh prefilter_cmd CVE" returned no matching
public advisory (hits were unrelated Wazuh CVEs, e.g. CVE-2023-50260,
CVE-2026-74034). The 4.14.12 fix could still reflect a private report —
only vendor triage can confirm novelty, as with F-001/F-002.

## Fix present in the development branch
The 4.14.12 dev branch adds exactly the missing check to
`check_remote_commands()`: `PREFILTER_HIERARCHY =
['ossec_config', 'syscheck', 'prefilter_cmd']`, raising WazuhError 1124
when either remote-command setting is disallowed.

## Recommended remediation
Extend `check_remote_commands()` to cover the syscheck
`<prefilter_cmd>` hierarchy (as the dev branch does), and audit the
remaining `ossec.conf` settings for any other command-execution vector
reachable while `remote_commands` is disabled.

## Evidence in this packet
- `harness_f003.py` — runs the matrix above against either tree:
  `python harness_f003.py wazuh-4.14.10-release` / `python harness_f003.py wazuh-4.14`
- `REPORT.md` — full analysis, evidence table, execution chain, and bounded impact
