TITLE (paste into the advisory Title field):
Wazuh cluster synchronization accepts unverified file claims for sync tasks (end_receiving_file does not require a checksum-verified transfer)

SUGGESTED SEVERITY: Moderate
AFFECTED PRODUCT/ECOSYSTEM: pip/other — use: Wazuh manager, affected version 4.14.10 (and check earlier 4.x), component framework/wazuh/core/cluster/common.py

DESCRIPTION (paste into the Description field):
## Title
Wazuh cluster synchronization accepts unverified file claims for sync tasks
(`end_receiving_file` does not require a checksum-verified transfer)

## Affected
- Product: Wazuh manager (cluster mode)
- Version tested: **v4.14.10** (tag commit 6e7835b4880c3210ef30e855a6bb43432be792e1);
  code inspection indicates the same pattern in earlier 4.x (to be confirmed by vendor)
- Component: `framework/wazuh/core/cluster/common.py` —
  `WazuhCommon.end_receiving_file()` / `error_receiving_file()`
- Prerequisites: authenticated cluster peer (valid cluster key / compromised node)
- Classification: CWE-841 (Improper Enforcement of Behavioral Workflow);
  secondary CWE-863 (Incorrect Authorization)
- Provisional severity: Medium (integrity + availability impact inside the
  cluster-peer threat model). No confidentiality, RCE, or unauthenticated
  impact is claimed.

## Summary
The cluster file-reception flow has two unconnected completion steps.
`Handler.end_file()` verifies the SHA-256 of a transferred file, but records
nothing about that success. The separate sync-task completion handler,
`WazuhCommon.end_receiving_file(task_id, filename)`, validates only that the
filename is confined to `queue/cluster` (`_ALLOWED_PREFIXES`) and that the
task exists, then assigns the path to the task and signals its consumer.
It does not verify the file exists, was transferred in this session, passed
its checksum, belongs to that task, or has not already been claimed.

Master/worker consumers (`master.py` integrity check and extra-valid sync,
`worker.py` `process_files_from_master`) wait on that signal, then decompress
and process the named file.

## Demonstrated (handler-level, real release code — `harness_v2.py`)
| # | Test | v4.14.10 | dev 4.14.12 branch |
|---|------|----------|--------------------|
| T1 | Claim a file that was never transferred | **Accepted** (`b'ok'`, task signalled) | Rejected (WazuhClusterError 3027) |
| T2 | File genuinely transferred, then claimed for a *different* task on the same connection | **Accepted** | **Still accepted** — see "Fix limitation" |
| T3 | Claim a file, then report an error for that task (`error_receiving_file`) | **Claimed file deleted** | Blocked (claim itself fails) |
| T4 | Consumer-side processing of a valid-format archive (`cluster.decompress_files`) | Metadata parsed and returned | Same (by design — evidence the claimed file is really processed) |

Not demonstrated: network-level exploitation over a live two-node cluster,
and any impact beyond sync integrity/availability. Those are stated as
potential, not established.

## Fix limitation worth vendor attention
The 4.14.12 development branch adds `received_files` (a set of pathnames
populated on checksum success, consumed on claim). This closes T1/T3 but —
as executed in the same harness against the dev code — **not T2**: because
the set is not bound to a task, a file transferred on a connection can still
be claimed by a different pending task on that same connection.

## Recommended remediation
Bind each sync task to its expected transfer: record (task_id → verified
pathname) at checksum success, require an exact match at claim time, and
consume the record atomically. In `error_receiving_file`, only delete files
recorded as owned by the aborted task.

## Evidence in this packet
- `harness_v2.py` — runs the matrix above against either tree:
  `python harness_v2.py wazuh-4.14.10-release` / `python harness_v2.py wazuh-4.14`
- `harness_poc.py` — original minimal reproduction
- `duplicate_check.md` — related published advisories and why they differ
