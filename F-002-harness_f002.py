#!/usr/bin/env python3
"""
F-002 validation — group-path containment, DAPI threat model.

Usage: harness_f002.py <tree>   # wazuh-4.14.10-release or wazuh-4.14

Threat model (established by published CVE-2026-74043 / GHSA-cw26-jj8q-x7w5,
fixed in 4.14.8): an attacker holding the cluster key can send DistributedAPI
requests naming framework functions directly, bypassing the REST controller's
Connexion `group_names` format validation. Framework functions must therefore
validate group_id themselves. The 4.14.12 dev branch adds exactly that
(InputValidator().group() + commonpath vs SHARED_PATH).

Tests, against the REAL configuration.py of each tree, in a fake WAZUH_PATH:
  T1  get_file_conf(raw=True) with group_id='../../outside', filename='secret.txt'
      — file lives OUTSIDE etc/shared. Secure = rejected, not returned.
  T2  get_agent_conf with group_id='../../outside', filename='agent.conf'
      — XML file outside etc/shared parsed as group config. Secure = rejected.
  T3  get_agent_conf_multigroup with multigroup_id='../../outside'
      — Secure = rejected.
  T4  Legitimate control: get_file_conf(raw=True) for group 'default',
      filename='agent.conf' — must still work on both trees.

PASS = secure behaviour, FAIL = vulnerable behaviour observed.
"""
import os
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


def report(test, secure, detail):
    RESULTS[test] = secure
    print(f"{test}: {'PASS (secure)' if secure else 'FAIL (vulnerable)'} — {detail}")


def main():
    tmp_root = tempfile.mkdtemp(prefix="wazuh_f002_")
    fake_root = os.path.join(tmp_root, "ossec")
    shared = os.path.join(fake_root, "etc", "shared")
    outside = os.path.join(fake_root, "outside")
    os.makedirs(os.path.join(shared, "default"))
    os.makedirs(outside)
    # var/multigroups must exist as a real directory, otherwise the kernel
    # cannot resolve '..' through it (os.path.exists returns False).
    os.makedirs(os.path.join(fake_root, "var", "multigroups"))
    with open(os.path.join(shared, "default", "agent.conf"), "w") as f:
        f.write("<agent_config><localfile><location>/var/log/syslog</location>"
                "<log_format>syslog</log_format></localfile></agent_config>")
    with open(os.path.join(outside, "secret.txt"), "w") as f:
        f.write("TOPSECRET-OUTSIDE-SHARED")
    with open(os.path.join(outside, "agent.conf"), "w") as f:
        f.write("<agent_config><localfile><location>/etc/shadow</location>"
                "<log_format>syslog</log_format></localfile></agent_config>")

    with mock.patch.object(core_common, "WAZUH_PATH", fake_root), \
         mock.patch.object(core_common, "SHARED_PATH", shared), \
         mock.patch.object(core_common, "MULTI_GROUPS_PATH",
                           os.path.join(fake_root, "var", "multigroups")):
        # T1 — raw read outside shared
        try:
            data = configuration.get_file_conf(
                filename="secret.txt", group_id="../../outside", raw=True)
            leaked = isinstance(data, str) and "TOPSECRET" in data
            report("T1 get_file_conf raw traversal read", not leaked,
                   f"returned {data!r}" if leaked else f"returned {str(data)[:80]!r}")
        except Exception as e:
            report("T1 get_file_conf raw traversal read", True,
                   f"rejected with {type(e).__name__}: {str(e)[:120]}")

        # T2 — agent.conf parsed from outside shared
        try:
            data = configuration.get_agent_conf(
                group_id="../../outside", filename="agent.conf")
            leaked = isinstance(data, dict) and "shadow" in str(data)
            report("T2 get_agent_conf traversal read", not leaked,
                   f"parsed outside file: {str(data)[:160]!r}")
        except Exception as e:
            report("T2 get_agent_conf traversal read", True,
                   f"rejected with {type(e).__name__}: {str(e)[:120]}")

        # T3 — multigroup traversal (no containment check at all in release)
        try:
            data = configuration.get_agent_conf_multigroup(
                multigroup_id="../../outside", filename="agent.conf")
            leaked = isinstance(data, dict)
            report("T3 get_agent_conf_multigroup traversal", not leaked,
                   f"parsed outside file: {str(data)[:160]!r}")
        except Exception as e:
            report("T3 get_agent_conf_multigroup traversal", True,
                   f"rejected with {type(e).__name__}: {str(e)[:120]}")

        # T4 — legitimate control must still work
        try:
            data = configuration.get_file_conf(
                filename="agent.conf", group_id="default", raw=True)
            ok = isinstance(data, str) and "syslog" in data
            report("T4 legitimate default-group read", ok,
                   f"returned {str(data)[:80]!r}")
        except Exception as e:
            report("T4 legitimate default-group read", False,
                   f"raised {type(e).__name__}: {str(e)[:120]}")

    print("\nSummary:", {k: ("secure" if v else "VULNERABLE") for k, v in RESULTS.items()})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
