# Wazuh Security Findings

Security research by **FrosterDL** on the Wazuh manager (v4.14.10).
Each finding below was validated by executing a Python harness against the
real release code of Wazuh v4.14.10 and, for comparison, the 4.14.12
development branch. No live cluster was used; impact claims are bounded to
what the harnesses and code analysis establish.

| ID | Finding | Severity (provisional) | Advisory | Proof of concept |
|----|---------|------------------------|----------|------------------|
| F-001 | Cluster synchronization accepts unverified file claims for sync tasks (`end_receiving_file` does not require a checksum-verified transfer) | Medium | [F-001-advisory.md](F-001-advisory.md) | [F-001-harness_v2.py](F-001-harness_v2.py) |
| F-002 | Group configuration functions accept path traversal via DistributedAPI (cluster peer reads and writes files outside `etc/shared`) | Medium | [F-002-advisory.md](F-002-advisory.md) | [F-002-harness_f002.py](F-002-harness_f002.py), [F-002-harness_f002_write.py](F-002-harness_f002_write.py) |
| F-003 | Syscheck `<prefilter_cmd>` bypasses the upload-configuration remote-commands policy (`check_remote_commands` is incomplete) | Low | [F-003-advisory.md](F-003-advisory.md) | [F-003-harness_f003.py](F-003-harness_f003.py) |
| F-004 | Agentless `<arguments>` bypasses the upload-configuration remote-commands policy (same incomplete gate as F-003; not fixed in the 4.14.12 dev branch) | Low | [F-004-advisory.md](F-004-advisory.md) | [F-004-harness_f004.py](F-004-harness_f004.py) |

## Disclosure status

- **F-001** — reported to Wazuh via GitHub Security Advisory
  GHSA-x9qv-cghc-8xf4 on 2026-11-08. No maintainer response as of
  2026-11-15.
- **F-003 / F-004** — reported to Wazuh as one combined GitHub Security
  Advisory GHSA-f48h-x9rq-9cmm on 2026-11-12 (both vectors share the same
  incomplete policy gate). No maintainer response as of 2026-11-15.
- **F-002** — first disclosed with the VulDB submission referencing this
  repository.

These findings are also submitted to VulDB (a MITRE CVE Numbering
Authority) with CVE requests, referencing the advisory files in this
repository as the external proof for each entry.
