#!/usr/bin/env python3
"""
F-002 write-path validation — upload_group_configuration / upload_group_file.

Usage: harness_f002_write.py <tree>   # wazuh-4.14.10-release or wazuh-4.14

F-002's REPORT.md left the write claim unproven: the release code builds the
destination as os.path.join(SHARED_PATH, group_id, "agent.conf") and moves the
validated temp file there via safe_move(), which has NO containment check.
The only thing standing between a traversal group_id and a write in this
source-only environment is the external `bin/verify-agent-conf` binary, which
does not exist here. This harness stubs that binary (exit 0, as it would for
valid agent.conf XML on a real manager) and patches wazuh_uid/gid, exactly
like the read harness fakes WAZUH_PATH — the code under test is the REAL
configuration.py of each tree.

Tests, in a fake WAZUH_PATH:
  W1  upload_group_configuration(group_id='../../outside', valid XML)
      — target dir exists OUTSIDE etc/shared. Secure = rejected, no file.
  W2  upload_group_configuration(group_id='../../..', valid XML)
      — writes agent.conf at the fake install root, three levels above
      etc/shared. Secure = rejected, no file. (The first version of this
      test used '../victim', which is invalid: join(SHARED, '../victim')
      is etc/victim, which does not exist — the exists-gate correctly
      rejects it. Traversal only reaches directories that exist.)
  W3  Legitimate control: upload_group_configuration(group_id='default')
      — must succeed and update default/agent.conf on both trees.

PASS = secure behaviour, FAIL = vulnerable behaviour observed.
"""
import os
import stat
import sys
import tempfile
from unittest import mock

TREE = sys.argv[1] if len(sys.argv) > 1 else "wazuh-4.14.10-release"
BASE = os.path.join(os.path.dirname(__file__), "..", "..", "targets", TREE)
sys.path.insert(0, os.path.join(BASE, "framework"))
sys.path.insert(0, os.path.join(BASE, "api"))

from wazuh.core import common as core_common  # noqa: E402
from wazuh.core import configuration  # noqa: E402

RESULTS = {}

VALID_XML = ("<agent_config><localfile><location>/tmp/pwned.log</location>"
             "<log_format>syslog</log_format></localfile></agent_config>")


def report(test, secure, detail):
    RESULTS[test] = secure
    print(f"{test}: {'PASS (secure)' if secure else 'FAIL (vulnerable)'} — {detail}")


def main():
    tmp_root = tempfile.mkdtemp(prefix="wazuh_f002w_")
    fake_root = os.path.join(tmp_root, "ossec")
    shared = os.path.join(fake_root, "etc", "shared")
    outside = os.path.join(fake_root, "outside")
    os.makedirs(os.path.join(shared, "default"))
    os.makedirs(os.path.join(shared, "victim"))
    os.makedirs(outside)
    os.makedirs(os.path.join(fake_root, "tmp"))
    # Stub verify-agent-conf: real managers run the C binary; here it just
    # has to accept valid XML (exit 0), which is what it does for valid input.
    bin_dir = os.path.join(fake_root, "bin")
    os.makedirs(bin_dir)
    stub = os.path.join(bin_dir, "verify-agent-conf")
    with open(stub, "w") as f:
        f.write("#!/bin/sh\nexit 0\n")
    os.chmod(stub, os.stat(stub).st_mode | stat.S_IEXEC)

    with open(os.path.join(shared, "victim", "agent.conf"), "w") as f:
        f.write("<agent_config><localfile><location>/var/log/victim.log</location>"
                "<log_format>syslog</log_format></localfile></agent_config>")
    with open(os.path.join(shared, "default", "agent.conf"), "w") as f:
        f.write("<agent_config><localfile><location>/var/log/syslog</location>"
                "<log_format>syslog</log_format></localfile></agent_config>")

    with mock.patch.object(core_common, "WAZUH_PATH", fake_root), \
         mock.patch.object(core_common, "SHARED_PATH", shared), \
         mock.patch.object(core_common, "OSSEC_TMP_PATH",
                           os.path.join(fake_root, "tmp")), \
         mock.patch.object(core_common, "wazuh_uid", lambda: os.getuid()), \
         mock.patch.object(core_common, "wazuh_gid", lambda: os.getgid()):
        # W1 — write outside etc/shared
        target = os.path.join(outside, "agent.conf")
        try:
            msg = configuration.upload_group_configuration(
                group_id="../../outside", file_content=VALID_XML)
            written = os.path.exists(target)
            leaked = written and "pwned" in open(target).read()
            report("W1 upload traversal write outside shared", not leaked,
                   f"returned {msg!r}; {target} written={written}")
        except Exception as e:
            report("W1 upload traversal write outside shared",
                   not os.path.exists(target),
                   f"rejected with {type(e).__name__}: {str(e)[:120]}")

        # W2 — write three levels up, at the install root (an existing dir)
        root_target = os.path.join(tmp_root, "agent.conf")
        try:
            msg = configuration.upload_group_configuration(
                group_id="../../..", file_content=VALID_XML)
            written = os.path.exists(root_target)
            leaked = written and "pwned" in open(root_target).read()
            report("W2 upload traversal write at install root", not leaked,
                   f"returned {msg!r}; {root_target} written={written}")
        except Exception as e:
            report("W2 upload traversal write at install root",
                   not os.path.exists(root_target),
                   f"rejected with {type(e).__name__}: {str(e)[:120]}")

        # W3 — legitimate control must still work
        try:
            msg = configuration.upload_group_configuration(
                group_id="default", file_content=VALID_XML)
            ok = "pwned" in open(os.path.join(shared, "default", "agent.conf")).read()
            report("W3 legitimate default-group upload", ok,
                   f"returned {msg!r}")
        except Exception as e:
            report("W3 legitimate default-group upload", False,
                   f"raised {type(e).__name__}: {str(e)[:120]}")

    print("\nSummary:", {k: ("secure" if v else "VULNERABLE") for k, v in RESULTS.items()})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
