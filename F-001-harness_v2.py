#!/usr/bin/env python3
"""
F-001 validation matrix — handler-level, against real Wazuh code.

Usage: harness_v2.py <tree>   where <tree> is the wazuh checkout dir name
       under targets/ (e.g. wazuh-4.14.10-release or wazuh-4.14)

Tests (all on ONE handler instance = one cluster connection's state):
  T1  Claim a staged file that was NEVER transferred, for task-B.
  T2  Legitimately transfer a file (receive_file/update_file/end_file with
      correct SHA256) intended for task-A, then claim it for task-B
      (cross-task claim of a genuinely transferred file).
  T3  Claim an existing file for task-B, then send error_receiving_file for
      task-B and observe whether the claimed file is deleted.
  T4  Build a valid Wazuh sync archive and run the real consumer-side
      decompress_files() on it (would a claimed stale archive be processed?).

Prints PASS/FAIL per test from the *defender's* perspective:
  PASS = secure behaviour (claim rejected / file preserved)
  FAIL = vulnerable behaviour observed
"""
import asyncio
import hashlib
import json
import os
import sys
import tempfile
import zlib
from unittest import mock

TREE = sys.argv[1] if len(sys.argv) > 1 else "wazuh-4.14.10-release"
BASE = os.path.join(os.path.dirname(__file__), "..", "..", "targets", TREE)
sys.path.insert(0, os.path.join(BASE, "framework"))
sys.path.insert(0, os.path.join(BASE, "api"))

from wazuh.core.cluster import common as c_common  # noqa: E402
from wazuh.core import common as core_common  # noqa: E402

RESULTS = {}


def report(test, secure, detail):
    RESULTS[test] = secure
    print(f"{test}: {'PASS (secure)' if secure else 'FAIL (vulnerable)'} — {detail}")


class FakeSyncTask:
    def __init__(self):
        self.filename = ""
        self.received_information = asyncio.Event()


import logging


class _Handler(c_common.Handler, c_common.WazuhCommon):
    """Real handlers (MasterHandler/WorkerHandler) combine Handler's file
    transfer state/methods with WazuhCommon's sync-task methods."""

    def get_logger(self, logger_tag=""):
        return logging.getLogger("harness")


def make_handler():
    h = object.__new__(_Handler)
    h.sync_tasks = {}
    h.in_file = {}
    # Dev branch tracks received files on Handler.__init__; mirror its default.
    h.received_files = set()
    return h


def new_task(h, name):
    h.sync_tasks[name] = FakeSyncTask()
    return h.sync_tasks[name]


def main():
    tmp_root = tempfile.mkdtemp(prefix="wazuh_matrix_")
    fake_root = os.path.join(tmp_root, "ossec")
    queue_cluster = os.path.join(fake_root, "queue", "cluster")
    os.makedirs(queue_cluster)
    allowed = (os.path.join(fake_root, "queue/cluster"),)

    h = make_handler()

    with mock.patch.object(core_common, "WAZUH_PATH", fake_root), \
         mock.patch.object(c_common, "_ALLOWED_PREFIXES", allowed):

        # ---------- T1: claim with no transfer at all ----------
        staged = os.path.join(queue_cluster, "staged_never_sent.zip")
        with open(staged, "wb") as f:
            f.write(b"staged-bytes")
        new_task(h, "task-B")
        try:
            res, _ = h.end_receiving_file(
                "task-B queue/cluster/staged_never_sent.zip")
            accepted = res == b"ok"
        except Exception as e:
            accepted = False
            res = type(e).__name__
        report("T1 no-transfer claim", not accepted,
               f"end_receiving_file -> {res!r}, task-B.filename="
               f"{h.sync_tasks['task-B'].filename!r}")

        # ---------- T2: real transfer for A, claimed by B ----------
        content = b"archive-for-task-A"
        rel = "queue/cluster/for_task_a.zip"
        name_b = rel.encode()
        r1, _ = h.receive_file(name_b)
        r2, _ = h.update_file(name_b + b" " + content)
        digest = hashlib.sha256(content).digest()
        r3, _ = h.end_file(name_b + b" " + digest)
        transfer_ok = (r1.strip() == b"ok" and r3 == b"ok")
        new_task(h, "task-A")
        new_task(h, "task-B2")
        try:
            res, _ = h.end_receiving_file(f"task-B2 {rel}")
            accepted_b = res == b"ok"
        except Exception as e:
            accepted_b = False
            res = type(e).__name__
        report("T2 cross-task claim of transferred file",
               not accepted_b,
               f"transfer ok={transfer_ok} ({r1!r}/{r3!r}); claim by task-B2 -> {res!r}")

        # ---------- T3: claim then error -> deletion ----------
        victim = os.path.join(queue_cluster, "victim_file.zip")
        with open(victim, "wb") as f:
            f.write(b"needed-by-another-task")
        new_task(h, "task-C")
        try:
            h.end_receiving_file("task-C queue/cluster/victim_file.zip")
            claimed = h.sync_tasks["task-C"].filename == victim
        except Exception:
            claimed = False
        existed_before = os.path.exists(victim)
        if claimed:
            try:
                h.error_receiving_file('task-C {"error": "peer reported failure"}')
            except Exception as e:
                print(f"    (error_receiving_file raised {type(e).__name__}: {e})")
        deleted = claimed and existed_before and not os.path.exists(victim)
        report("T3 claim-then-error deletes file", not deleted,
               f"claimed={claimed}, file existed before={existed_before}, "
               f"exists after error={os.path.exists(victim)}")

        # ---------- T4: stale archive is processable by consumer ----------
        try:
            from wazuh.core.cluster import cluster as cl
            metadata = {"etc/shared/agent.conf": {"merged": False, "cluster_item_key": "etc/shared"}}
            archive = os.path.join(queue_cluster, "stale_archive.zip")
            with open(archive, "wb") as wf:
                wf.write(b"etc/shared/agent.conf" + cl.PATH_SEP.encode()
                         + zlib.compress(b"<agent_config/>") + cl.FILE_SEP.encode())
                wf.write(b"files_metadata.json" + cl.PATH_SEP.encode()
                         + zlib.compress(json.dumps(metadata).encode()))
            ko_files, decompress_dir = cl.decompress_files(archive)
            processed = isinstance(ko_files, dict) and "etc/shared/agent.conf" in ko_files
            report("T4 stale archive processed by decompress_files", not processed,
                   f"ko_files keys={list(ko_files) if isinstance(ko_files, dict) else ko_files!r}")
        except Exception as e:
            print(f"T4: NOT EXECUTED — {type(e).__name__}: {str(e)[:200]}")

    print("\nSummary:", {k: ("secure" if v else "VULNERABLE") for k, v in RESULTS.items()})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
