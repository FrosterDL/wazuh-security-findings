#!/usr/bin/env python3
"""
F-003 validation — syscheck prefilter_cmd bypass of the upload_configuration
remote-commands policy.

Usage: harness_f003.py <tree>   # wazuh-4.14.10-release or wazuh-4.14
Run with: tools/venv/bin/python harness_f003.py <tree>

Threat model / policy: an API user with manager:update_config can replace
ossec.conf via wazuh.manager.update_ossec_conf -> validate_wazuh_xml(
config_file=True) -> check_remote_commands(). The api.yaml
upload_configuration.remote_commands policy exists so an admin can delegate
config upload WITHOUT granting command execution: when localfile / wodle
remote commands are disallowed, adding one raises WazuhError 1124.
The 4.14.12 dev branch extends that policy to syscheck <prefilter_cmd>;
release 4.14.10 does not.

Why prefilter_cmd is command execution, not just a config value:
  * src/config/syscheck-config.c: a <prefilter_cmd> in the manager's own
    ossec.conf is accepted (it is not CAGENT_CONFIG, so the
    allow_remote_prefilter_cmd gate does not apply).
  * src/syscheckd/src/create_db.c:1424: file hashing calls
    OS_MD5_SHA1_SHA256_File(file, syscheck.prefilter_cmd, ...).
  * src/os_crypto/md5_sha1_sha256/md5_sha1_sha256_op.c: the prefilter
    command is split on spaces, the hashed filename appended, and run
    via wpopenv() — i.e. executed by syscheckd (root on a standard
    manager) for every hashed file. prefilter_cmd="/bin/sh -c id"
    therefore runs a shell command.

Tests, against the REAL core/utils.py of each tree:
  T1  both remote_commands disallowed, prefilter_cmd added
      — Secure = rejected with 1124.
  T2  only localfile disallowed (wodle allowed), prefilter_cmd added
      — Secure = rejected (dev rule: ANY disabled setting protects it).
  T3  control: localfile full_command added, both disallowed
      — Secure = rejected with 1124 on BOTH trees (policy works for
        the vectors it already covers).
  T4  legitimate control: prefilter_cmd unchanged, both disallowed
      — must NOT raise on either tree.
  T5  defaults (both allowed), prefilter_cmd added
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

ORIG = ("<ossec_config><syscheck><frequency>43200</frequency></syscheck>"
        "</ossec_config>")
PREFILTER = ("<ossec_config><syscheck><frequency>43200</frequency>"
             "<prefilter_cmd>/tmp/pwn.sh</prefilter_cmd></syscheck></ossec_config>")
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
    raised, detail = check(PREFILTER, ORIG, False, False)
    report("T1 prefilter added, both remote cmds disallowed", raised, detail)

    raised, detail = check(PREFILTER, ORIG, False, True)
    report("T2 prefilter added, only localfile disallowed", raised, detail)

    raised, detail = check(LOCALFILE_CMD, ORIG_LOCALFILE, False, False)
    report("T3 control: localfile command, both disallowed", raised, detail)

    raised, detail = check(PREFILTER, PREFILTER, False, False)
    report("T4 control: prefilter unchanged, both disallowed", not raised, detail)

    raised, detail = check(PREFILTER, ORIG, True, True)
    report("T5 prefilter added, defaults (both allowed)", not raised,
           detail + " — expected: policy is opt-in")

    print("\nSummary:", {k: ("secure" if v else "VULNERABLE") for k, v in RESULTS.items()})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
