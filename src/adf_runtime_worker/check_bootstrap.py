"""Trusted single-threaded resource setup before exec of the checker namespace."""
from __future__ import annotations

import json
import os
import resource
import sys


def main() -> None:
    argv = json.loads(sys.argv[1])
    timeout = max(1, min(1800, int(sys.argv[2])))
    disk = max(1, min(64 * 1024 * 1024, int(sys.argv[3])))
    # Namespace entry applies seccomp after bwrap's trusted setup: project code
    # cannot create any task. Do not alter host-UID RLIMIT_NPROC in nested WSL.
    for kind, limit in ((resource.RLIMIT_AS, 128 * 1024 * 1024),
                        (resource.RLIMIT_NOFILE, 64), (resource.RLIMIT_CORE, 0), (resource.RLIMIT_MEMLOCK, 0),
                        (resource.RLIMIT_FSIZE, disk), (resource.RLIMIT_CPU, timeout)):
        resource.setrlimit(kind, (limit, limit))
    # Closed worker-generated argv starts with the previously hash-verified
    # operator launcher; no model command or shell is accepted here.
    os.execve(argv[0], argv, {"LANG": "C.UTF-8"})  # noqa: S606


if __name__ == "__main__":
    main()
