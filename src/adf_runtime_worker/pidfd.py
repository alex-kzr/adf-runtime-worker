"""Fixed Linux pidfd ABI fallback for CPython builds without pidfd bindings."""
from __future__ import annotations

import ctypes
import errno
import os
import platform
import signal
import sys
from functools import lru_cache
from typing import Any


def _guard_abi() -> None:
    if sys.platform != "linux" or platform.machine() not in {"x86_64", "aarch64"} or ctypes.sizeof(ctypes.c_void_p) != 8 or ctypes.sizeof(ctypes.c_long) != 8:
        raise OSError(errno.ENOSYS, "Unsupported Linux pidfd ABI")


@lru_cache(maxsize=1)
def _syscall() -> Any:
    # Linux v6.8 x86 syscall_64.tbl and asm-generic/unistd.h: 424 / 434.
    # libc need not export named wrappers; its variadic syscall has a long result.
    function = ctypes.CDLL(None, use_errno=True).syscall
    function.restype = ctypes.c_long
    return function


def _result(value: int) -> int:
    if value == -1:
        number = ctypes.get_errno()
        raise OSError(number, os.strerror(number))
    return value


def pidfd_open(pid: int) -> int:
    _guard_abi()
    if type(pid) is not int or not 0 < pid < 2**31:
        raise OSError(errno.EINVAL, "Invalid process identifier")
    native = getattr(os, "pidfd_open", None)
    if native is not None:
        return int(native(pid, 0))
    return _result(int(_syscall()(ctypes.c_long(434), ctypes.c_int(pid), ctypes.c_uint(0))))


def pidfd_send_signal(fd: int, signum: int) -> None:
    _guard_abi()
    if type(fd) is not int or not 0 <= fd < 2**31 or signum not in {0, signal.SIGTERM, signal.SIGKILL}:
        raise OSError(errno.EINVAL, "Invalid owned-session signal")
    native = getattr(signal, "pidfd_send_signal", None)
    if native is not None:
        native(fd, signum, None, 0)
        return
    _result(int(_syscall()(ctypes.c_long(424), ctypes.c_int(fd), ctypes.c_int(signum), ctypes.c_void_p(), ctypes.c_uint(0))))
