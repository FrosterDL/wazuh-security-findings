#!/usr/bin/env python3
"""
F-004 validation — agentless <arguments> bypasses the upload_configuration
remote-commands policy (same policy F-003 tested, different vector).

Usage: harness_f004.py <tree>   # wazuh-4.14.10-release or wazuh-4.14
Run with: tools/venv/bin/python harness_f004.py <tree>

Threat model / policy: same as F-003 — an API user with
manager:update_config can replace ossec.conf via
wazuh.manager.update_ossec_conf -> validate_wazuh_xml(config_file=True)
-> check_remote_commands(). The api.yaml upload_configuration.remote_commands
policy exists so an admin can delegate config upload WITHOUT granting
command execution. In 4.14.10 AND in the 4.14.12 dev branch,
check_remote_commands only covers localfile, wodle and (dev only)
syscheck prefilter_cmd. It does NOT cover <agentless>.

Why agentless <arguments> is command execution, not just a config value:
  * src/config/agentlessd-config.c Read_CAgentless: <type>, <host>,
    <state>, <frequency> and <arguments> are read verbatim; <type> is
    only checked for parent-folder traversal and existence under
    AGENTLESSDIR (var/agentless/).
  * src/agentlessd/agentlessd.c command_args(): argv = [AGENTLESSDIR/type,
    use_su/use_sudo?, host, <arguments> split on spaces]; run_periodic_cmd
    runs it with wpopenv() on the configured schedule (frequency, default
    86400s, attacker-settable).
  * The shipped expect scripts take $args = argv after the hostname and
    send it verbatim to the remote host over ssh, e.g.
    src/agentlessd/scripts/ssh_generic_diff: `send "$args\\r"` after
    `spawn ssh $hostname`; ssh_integrity_check_linux interpolates $args
    into a remote shell command line. So <arguments> is an arbitrary
    command executed on the agentless host as the ssh user whose password
    the manager already stores in agentless/.passlist.
  * <run_command> itself is NOT the vector: it is only reported via
    getAgentlessConfig() JSON. The vector is <arguments> with a shipped
    script type such as ssh_generic_diff.

Tests, against the REAL core/utils.py of each tree:
  T1  both remote_commands disallowed, agentless entry added
      — Secure = rejected with 1124.
  T2  only localfile disallowed (wodle allowed), agentless entry added
      — Secure = rejected.
  T3  control: localfile full_command added, both disallowed
      — Secure = rejected with 1124 on BOTH trees (policy works for
        the vectors it already covers).
  T4  legitimate control: agentless entry unchanged, both disallowed
      — must NOT raise on either tree.
  T5  defaults (both allowed), agentless entry added
      — no raise on either tree: the policy is opt-in, so this is the
        documented default, not a bypass. Recorded as a bound.

PASS = secure behaviour, FAIL = vulnerable behaviour observed.
"""
import copy
import os
import sys

TREE = sys.argv[1] if len(sys.argv) > 1 else "wazuh-4.14.10-release"
BASE = os.path.join(os.path.dirname(__file__), "..", "..", "targets", TREE)
sys.path.insert(0, os.path.join(BASE, "framework"))
sys.path.insert(0, os.path.join(BASE, "api"))

from wazuh.core import utils  # noqa: E402
# NOTE: utils does `from api import configuration` — api_conf lives there,
# not on wazuh.core.configuration.
configuration = utils.configuration  # noqa: E402

RESULTS = {}

ORIG = ("<ossec_config><global><jsonout_output>yes</jsonout_output></global>"
        "</ossec_config>")
AGENTLESS = ("<ossec_config><global><jsonout_output>yes</jsonout_output></global>"
             "<agentless><type>ssh_generic_diff</type><frequency>60</frequency>"
             "<host>monitored-host</host><state>periodic</state>"
             "<arguments>id; cat /etc/passwd</arguments></agentless></ossec_config>")
LOCALFILE_CMD = ("<ossec_config><localfile><log_format>full_command</log_format>"
                 "<command>id</command></localfile></ossec_config>")
ORIG_LOCALFILE = ("<ossec_config><localfile><log_format>syslog</log_format>"
                  "<location>/var/log/test.log</location></localfile></ossec_config>")


def report(test, secure, detail):
    RESULTS[test] = secure
    print(f"{test}: {'PASS (secure)' if secure else 'FAIL (vulnerable)'} — {detail}")


def check(new_xml, orig_xml, allow_localfile, allow_wodle):
    """Run check_remote_commands under a given api.yaml policy. Returns
    (raised_1124: bool, detail: str)."""
    api_conf = copy.deepcopy(configuration.api_conf)
    api_conf["upload_configuration"]["remote_commands"] = {
        "localfile": {"allow": allow_localfile, "exceptions": []},
        "wodle_command": {"allow": allow_wodle, "exceptions": []},
    }
    orig_conf = configuration.api_conf
    try:
        configuration.api_conf = api_conf
        new = utils.load_wazuh_xml(None, new_xml)
        orig = utils.load_wazuh_xml(None, orig_xml)
        try:
            utils.check_remote_commands(new, orig)
            return False, "accepted (no error raised)"
        except Exception as e:
            code = "1124" in str(e)
            return code, f"raised {type(e).__name__}: {str(e)[:120]}"
    finally:
        configuration.api_conf = orig_conf


def main():
    raised, detail = check(AGENTLESS, ORIG, False, False)
    report("T1 agentless added, both remote cmds disallowed", raised, detail)

    raised, detail = check(AGENTLESS, ORIG, False, True)
    report("T2 agentless added, only localfile disallowed", raised, detail)

    raised, detail = check(LOCALFILE_CMD, ORIG_LOCALFILE, False, False)
    report("T3 control: localfile command, both disallowed", raised, detail)

    raised, detail = check(AGENTLESS, AGENTLESS, False, False)
    report("T4 control: agentless unchanged, both disallowed", not raised, detail)

    raised, detail = check(AGENTLESS, ORIG, True, True)
    report("T5 agentless added, defaults (both allowed)", not raised,
           detail + " — expected: policy is opt-in")

    print("\nSummary:", {k: ("secure" if v else "VULNERABLE") for k, v in RESULTS.items()})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
