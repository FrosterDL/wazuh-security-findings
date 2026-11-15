TITLE (paste into the advisory Title field):
Group configuration functions accept path traversal via DistributedAPI (cluster peer reads and writes files outside etc/shared)

SUGGESTED SEVERITY: Moderate
AFFECTED PRODUCT/ECOSYSTEM: pip/other — use: Wazuh manager, affected version 4.14.10, component framework/wazuh/core/configuration.py

DESCRIPTION (paste into the Description field):
## Title
Group configuration functions accept path traversal via DistributedAPI
(`get_file_conf` / `get_agent_conf` / `get_agent_conf_multigroup` /
`upload_group_configuration` / `upload_group_file` do not validate
`group_id` against the shared path)

## Affected
- Product: Wazuh manager (cluster mode)
- Version tested: **v4.14.10**
- Component: `framework/wazuh/core/configuration.py` —
  `get_file_conf`, `get_agent_conf`, `get_agent_conf_multigroup`,
  `upload_group_configuration`, `upload_group_file`
  (reachable as `wazuh.agent.get_file_conf` / `get_agent_conf` /
  `upload_group_file`, all `@expose_resources`, hence callable through
  DistributedAPI by a cluster peer)
- Prerequisites: authenticated cluster peer (valid cluster key / compromised
  worker node)
- Classification: CWE-22 (Improper Limitation of a Pathname to a Restricted
  Directory), CWE-73 (External Control of File Name or Path)
- Provisional severity: Medium (confidentiality + integrity impact inside
  the cluster-peer threat model). No unauthenticated access, RCE, or
  privilege escalation is claimed.

## Summary
The group configuration helpers build paths as
`os.path.join(SHARED_PATH, group_id, filename)` and then check containment
only against the attacker-shifted base directory
`os.path.join(SHARED_PATH, group_id)` — never against `SHARED_PATH` itself,
and `group_id` itself is never validated. With a `group_id` such as
`../../outside`, the base moves outside `etc/shared` and any file under the
new base passes the check. `get_agent_conf_multigroup` has no containment
check at all (only an `os.path.exists` gate, which a traversal path
satisfies).

This is NOT a REST-API finding: the REST layer rejects `/` in `group_id`
(`group_names` format, `api/api/validator.py:24`). A cluster peer does not
go through the REST controller — it sends a DistributedAPI (`dapi`) request
whose JSON encodes the framework function as a `__callable__`
(`framework/wazuh/core/cluster/common.py:1923` `as_wazuh_object`), and
functions carrying `@expose_resources` pass that gate.

## Demonstrated (real release code — `harness_f002.py`)
| # | Test | v4.14.10 | dev 4.14.12 branch |
|---|------|----------|--------------------|
| T1 | `get_file_conf(filename='secret.txt', group_id='../../outside', raw=True)` — file outside `etc/shared` | **Returned the outside file's contents** | Rejected, WazuhError 1722 |
| T2 | `get_agent_conf(group_id='../../outside', filename='agent.conf')` — XML outside `etc/shared` parsed as group config | **Parsed it** (returned the outside file's `<localfile>` content) | Rejected, WazuhError 1722 |
| T3 | `get_agent_conf_multigroup(multigroup_id='../../outside', filename='agent.conf')` | **Parsed it** | Rejected, WazuhError 1722 |
| T4 | Legitimate `default` group read | Works | Works |

Run: `tools/venv/bin/python findings/F-002-group-path-containment/harness_f002.py wazuh-4.14.10-release`
then `... wazuh-4.14`.

## Demonstrated — write path (real release code, `harness_f002_write.py`, 2026-11-09)
The upload functions build the destination as
`os.path.join(SHARED_PATH, group_id, "agent.conf")` and move the validated
temp file there via `safe_move()`, which has no containment check. The only
gate is `os.path.exists(os.path.join(SHARED_PATH, group_id))`, which a
traversal to any existing directory satisfies. The harness stubs the external
`bin/verify-agent-conf` binary (exit 0 — the behaviour for valid XML on a
real manager) and uses a minimal valid `agent_config` block, the same shape
as real group configs.
| # | Test | v4.14.10 | dev 4.14.12 branch |
|---|------|----------|--------------------|
| W1 | `upload_group_configuration(group_id='../../outside', valid XML)` — target dir outside `etc/shared` | **Wrote `agent.conf` with attacker XML outside `etc/shared`** ("Agent configuration was successfully updated") | Rejected, WazuhError 1722 |
| W2 | `upload_group_configuration(group_id='../../..', valid XML)` — target at the install root | **Wrote `agent.conf` there** | Rejected, WazuhError 1722 |
| W3 | Legitimate `default` group upload | Works | Works |

Run: `tools/venv/bin/python findings/F-002-group-path-containment/harness_f002_write.py wazuh-4.14.10-release`
then `... wazuh-4.14`.

## Impact (bounded)
- **Arbitrary file read as the `wazuh` user, by an authenticated cluster
  peer.** `group_id` depth is attacker-controlled, so with enough `../`
  segments plus a `filename` the read is not limited to the test directory
  used in the harness: in a real install `SHARED_PATH` is
  `/var/ossec/etc/shared`, so paths such as `client.keys` and `ossec.conf`
  (which embeds the cluster key) are in reach — the same sensitive targets
  named in CVE-2026-93347.
- **Arbitrary-directory file write as the `wazuh` user, by an authenticated
  cluster peer (now demonstrated, W1/W2).** A cluster peer can plant a
  file named `agent.conf` with attacker-controlled (XML-validated) content
  in any existing directory the `wazuh` user can write to, outside the group
  directory the API is supposed to confine writes to. Bounds: the filename
  is fixed to `agent.conf` (no arbitrary filename/extension), the content
  must pass `verify-agent-conf` XML validation, and the target directory
  must already exist (the exists-gate). Not claimed: unauthenticated
  access, RCE, privilege escalation, or a live-cluster (network-level)
  reproduction — that needs a real two-node lab.

## Prior art — same pattern, different functions (why this was missed)
Wazuh fixed the identical DistributedAPI-traversal pattern in 4.14.8:
CVE-2026-93347 (`get_list_file`, GHSA-xrjw-cqrv-j92g),
CVE-2026-74043 (`upload_list/rule/decoder_file`, GHSA-cw26-jj8q-x7w5) and
CVE-2026-74031 (`delete_rule/decoder_file`, GHSA-w4qc-m4j4-6m9c), all
describing cluster workers sending DistributedAPI requests with `../`
sequences, "bypassing REST controller validation". The group helpers were
not in that 4.14.8 fix — their 4.14.10 code still has no `SHARED_PATH`
containment check, unlike the fixed `upload_list_file`, which gained one.
No published advisory was found for traversal in `get_agent_conf` /
`get_file_conf` / multigroup (duplicate check 2026-11-09). Residual risk,
as with any dev-branch fix: the 4.14.12 fix could reflect a private report
already queued — only vendor triage can confirm novelty.

## Fix present in the development branch
The 4.14.12 dev branch adds exactly the missing defence to all five
functions: `InputValidator().group(group_id)` (error 1722) plus
`commonpath([base_path, shared_path]) == shared_path`.

## Recommended remediation
Validate `group_id` with `InputValidator().group()` at every entry point
(including DistributedAPI-exposed functions, not only the REST layer) and
enforce containment of the resolved path against `SHARED_PATH` itself, not
against a base directory derived from unvalidated input. Apply the same
containment check to the multigroup variant and to the upload paths
(`upload_group_configuration` / `upload_group_file`).

## Evidence in this packet
- `harness_f002.py` — runs the read matrix above against either tree:
  `python harness_f002.py wazuh-4.14.10-release` / `python harness_f002.py wazuh-4.14`
- `harness_f002_write.py` — runs the write matrix (W1–W3) against either
  tree, same invocation pattern
- `REPORT.md` — full analysis, duplicate check, and bounded impact
