"""Diagnostic tools for SSH connections, kernel version, ethtool, reboot.

All public ``_impl`` functions accept a live ``paramiko.SSHClient``
and return a plain dict (never raise).
"""

from __future__ import annotations

import shlex
import socket
import time
from typing import Literal, Optional

import paramiko  # type: ignore[import-untyped]

from ._helpers import run_ssh, sudo_wrap, error_result, get_logger

_log = get_logger("mcp_ssh_server.diagnostics")


# ── ssh_exec ──────────────────────────────────────────────────────

def ssh_exec_impl(
    client: paramiko.SSHClient,
    command: str,
    timeout_seconds: int = 30,
    output_encoding: Literal["utf-8", "latin-1"] = "utf-8",
) -> dict:
    """Execute any shell command over SSH."""
    code, out, err, dur = run_ssh(
        client, command, timeout=timeout_seconds, encoding=output_encoding,
    )
    if code == -1:
        return error_result(err, "SSHException", duration_ms=dur)
    return {
        "stdout": out,
        "stderr": err,
        "exit_code": code,
        "duration_ms": dur,
    }


# ── check_connection ─────────────────────────────────────────────

def check_connection_impl(
    client: paramiko.SSHClient,
    timeout_seconds: int = 5,
) -> dict:
    """SSH connection liveness check (exec probe only)."""
    try:
        transport = client.get_transport()
        transport_active = bool(transport and transport.is_active())
    except Exception as exc:
        return {
            "alive": False,
            "transport_active": False,
            "latency_ms": None,
            "reason": "transport-check-exception",
            "error": str(exc),
            "type": exc.__class__.__name__,
        }

    code, out, err, latency_ms = run_ssh(
        client, "bash -lc 'echo OK'", timeout=timeout_seconds,
    )

    ok = (code == 0) and ("OK" in out)
    alive = ok and transport_active
    reason = None
    if not alive:
        if not transport_active:
            reason = "transport-inactive"
        elif not ok:
            reason = "exec-failed"
    return {
        "alive": alive,
        "transport_active": transport_active,
        "latency_ms": latency_ms,
        "stdout": out,
        "stderr": err,
        "exit_code": code,
        "reason": reason,
    }


# ── kernel_version ───────────────────────────────────────────────

def kernel_version_impl(
    client: paramiko.SSHClient,
    timeout_seconds: int = 5,
) -> dict:
    """Retrieve the remote kernel version using ``uname -rs``."""
    code, out, err, _ = run_ssh(
        client, "uname -rs", timeout=timeout_seconds,
    )
    out = out.strip()
    err = err.strip()
    kernel_name = release = None
    if out:
        parts = out.split()
        if len(parts) >= 2:
            kernel_name, release = parts[0], parts[1]
    return {
        "stdout": out,
        "stderr": err,
        "exit_code": code,
        "kernel_name": kernel_name,
        "release": release,
    }


# ── ethtool stats ────────────────────────────────────────────────

def _detect_default_interface(client: paramiko.SSHClient) -> str:
    """Best-effort auto-detect of the default NIC interface name.

    Falls back to ``eth0`` if detection fails.
    """
    code, out, _, _ = run_ssh(
        client,
        "bash -lc \"ip -o route get 8.8.8.8 2>/dev/null "
        "| awk '{print $5; exit}'\"",
        timeout=5,
    )
    iface = out.strip()
    if code == 0 and iface and " " not in iface:
        return iface
    return "eth0"


def get_ethtool_stats_impl(
    client: paramiko.SSHClient,
    interface: Optional[str] = None,
    command: Optional[str] = None,
    timeout_seconds: int = 20,
) -> dict:
    """Get ethtool stats or run a custom NIC command.

    If neither *command* nor *interface* is given the default NIC
    is auto-detected via ``ip route``.
    """
    if command:
        base_cmd = command
    else:
        iface = interface or _detect_default_interface(client)
        base_cmd = (
            f"(ethtool -S {shlex.quote(iface)}) || "
            f"echo 'ethtool not available or interface {iface} missing'"
        )

    try:
        transport = client.get_transport()
        before_active = bool(transport and transport.is_active())
    except Exception:
        before_active = False

    full_cmd = f"bash -lc {shlex.quote(base_cmd)}"

    start = time.time()
    stdout_txt = ""
    stderr_txt = ""
    exit_code = None
    panic = False
    panic_reason = None

    try:
        stdin, stdout, stderr = client.exec_command(
            full_cmd, timeout=timeout_seconds,
        )
        try:
            stdout_txt = stdout.read().decode("utf-8", errors="replace")
            stderr_txt = stderr.read().decode("utf-8", errors="replace")
        except Exception as re_err:
            panic = True
            panic_reason = f"read-exception:{re_err.__class__.__name__}"
        if not panic:
            try:
                exit_code = stdout.channel.recv_exit_status()
            except Exception as st_err:
                panic = True
                panic_reason = (
                    f"status-exception:{st_err.__class__.__name__}"
                )
    except (
        paramiko.SSHException, EOFError, OSError, socket.error,
    ) as exec_err:
        panic = True
        panic_reason = f"exec-exception:{exec_err.__class__.__name__}"
    except Exception as exc:
        duration_ms = int((time.time() - start) * 1000)
        try:
            after_active = bool(
                client.get_transport()
                and client.get_transport().is_active()
            )
        except Exception:
            after_active = False
        return {
            "panic": False,
            "panic_reason": None,
            "exit_code": exit_code,
            "stdout": stdout_txt,
            "stderr": stderr_txt,
            "transport_active_after": after_active,
            "duration_ms": duration_ms,
            "executed_command": base_cmd,
            "error": str(exc),
            "type": exc.__class__.__name__,
        }

    try:
        after_active = bool(
            client.get_transport() and client.get_transport().is_active()
        )
    except Exception:
        after_active = False

    if (
        not panic
        and before_active
        and not after_active
        and exit_code is None
    ):
        panic = True
        panic_reason = "transport-became-inactive"

    duration_ms = int((time.time() - start) * 1000)
    return {
        "panic": panic,
        "panic_reason": panic_reason,
        "exit_code": exit_code,
        "stdout": stdout_txt,
        "stderr": stderr_txt,
        "transport_active_after": after_active,
        "duration_ms": duration_ms,
        "executed_command": base_cmd,
        "interface": interface,
    }


# ── reboot_vm ────────────────────────────────────────────────────

def reboot_vm_impl(
    client: paramiko.SSHClient,
    sudo_password: Optional[str] = None,
    force: bool = False,
    delay_seconds: int = 1,
) -> dict:
    """Initiate an asynchronous reboot of the remote VM."""
    try:
        reboot_cmd = "reboot -f" if force else "reboot"
        if sudo_password:
            pw = shlex.quote(sudo_password)
            inner = (
                f"sleep {int(delay_seconds)}; "
                f"echo {pw} | sudo -S {reboot_cmd}"
            )
        else:
            inner = f"sleep {int(delay_seconds)}; sudo {reboot_cmd}"
        full_cmd = (
            f"nohup sh -c '{inner}' >/dev/null 2>&1 & echo REBOOTING"
        )
        stdin, stdout, stderr = client.exec_command(full_cmd, timeout=5)
        out = stdout.read().decode("utf-8", errors="replace").strip()
        err = stderr.read().decode("utf-8", errors="replace").strip()
        return {
            "started": True,
            "stdout": out,
            "stderr": err,
            "command": full_cmd,
            "force": force,
            "delay_seconds": delay_seconds,
        }
    except Exception as exc:
        return error_result(str(exc), exc.__class__.__name__)
