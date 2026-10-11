"""Trusted namespace entry: prohibit task creation before executing project code.

Linux x86-64 only, fail closed. This file is mounted read-only by the supervisor;
it imports no project modules. No seccomp policy or OS setting is changed globally.
"""
from __future__ import annotations

import ctypes
import json
import os
import platform
import sys


class Filter(ctypes.Structure):
    _fields_ = [("code", ctypes.c_ushort), ("jt", ctypes.c_ubyte), ("jf", ctypes.c_ubyte), ("k", ctypes.c_uint)]


class Program(ctypes.Structure):
    _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.POINTER(Filter))]


def restrict_tasks() -> None:
    if sys.platform != "linux" or platform.machine() != "x86_64":
        raise RuntimeError("Checker requires Linux x86-64 seccomp")
    # seccomp_data: arch at byte 4, syscall number at byte 0. Reject a
    # different ABI and x32 numbers. The namespace supplies filesystem/network
    # isolation; this supplemental filter denies task/kernel-worker creation,
    # host-UID keyrings, cross-process handles and namespace reconfiguration.
    instructions = [Filter(0x20, 0, 0, 4), Filter(0x15, 1, 0, 0xC000003E), Filter(0x06, 0, 0, 0x80000000),
                    Filter(0x20, 0, 0, 0), Filter(0x35, 0, 1, 0x40000000), Filter(0x06, 0, 0, 0x80000000)]
    denied = (56, 57, 58, 435, 425, 426, 427, 206, 207, 208, 209, 210, 333,
              248, 249, 250, 101, 310, 311, 438, 298, 321, 323,
              165, 166, 272, 308, 428, 429, 430, 431, 432, 433, 442,
              319, 447, 29, 30, 31, 67, 64, 65, 66, 68, 69, 70, 71, 220,
              240, 241, 242, 243, 244, 245, 41, 53)
    for number in denied:
        instructions += [Filter(0x15, 0, 1, number), Filter(0x06, 0, 0, 0x00050001)]  # EPERM
    instructions.append(Filter(0x06, 0, 0, 0x7FFF0000))  # SECCOMP_RET_ALLOW
    vector = (Filter * len(instructions))(*instructions)
    program = Program(len(instructions), vector)
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(38, 1, 0, 0, 0) != 0 or libc.prctl(22, 2, ctypes.byref(program), 0, 0) != 0:
        raise RuntimeError("Checker seccomp could not be enforced")


def main() -> None:
    try:
        argv = json.loads(sys.argv[1])
        # No launcher helper descriptor may cross the project-code boundary.
        # The trusted bootstrap hard-caps NOFILE=64 before namespace setup.
        os.closerange(3, 64)
        restrict_tasks()
        os.execve(argv[0], argv, dict(os.environ))  # noqa: S606 -- trusted registered Python argv, no shell
    except (OSError, ValueError, RuntimeError):
        print("ADF_CHECKER_SETUP_FAILED", file=sys.stderr)
        raise SystemExit(125) from None


if __name__ == "__main__":
    main()
