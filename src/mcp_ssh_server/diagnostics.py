"""Diagnostic tools for SSH connections, kernel version, ethtool, reboot."""
import socket
import shlex
import time
from typing import Optional, Literal
import paramiko  # type: ignore[import-untyped]


def ssh_exec_impl(
    client: paramiko.SSHClient,
    command: str,
    timeout_seconds: int = 30,
    output_encoding: Literal["utf-8", "latin-1"] = "utf-8",
) -> dict:
    """Execute any shell command over SSH."""
    try:
        start = time.time()
        stdin, stdout, stderr = client.exec_command(
            command, timeout=timeout_seconds
        )
        out = stdout.read().decode(output_encoding, errors="replace")
        err = stderr.read().decode(output_encoding, errors="replace")
        exit_status = stdout.channel.recv_exit_status()
        duration_ms = int((time.time()-start)*1000)
        return {
            "stdout": out,
            "stderr": err,
            "exit_code": exit_status,
            "duration_ms": duration_ms
        }
    except Exception as e:
        return {"error": str(e), "type": e.__class__.__name__}


def check_connection_impl(
    client: paramiko.SSHClient,
    timeout_seconds: int = 5,
) -> dict:
    """SSH connection liveness check (exec probe only)."""
    try:
        transport = client.get_transport()
        transport_active = bool(transport and transport.is_active())
    except Exception as e:
        return {
            "alive": False,
            "transport_active": False,
            "latency_ms": None,
            "reason": "transport-check-exception",
            "error": str(e),
            "type": e.__class__.__name__,
        }

    cmd = "bash -lc 'echo OK'"
    start = time.time()
    try:
        stdin, stdout, stderr = client.exec_command(
            cmd, timeout=timeout_seconds
        )
        out = stdout.read().decode("utf-8", errors="replace")
        err = stderr.read().decode("utf-8", errors="replace")
        exit_code = stdout.channel.recv_exit_status()
        latency_ms = int((time.time() - start) * 1000)
        ok = (exit_code == 0) and ("OK" in out)
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
            "exit_code": exit_code,
            "reason": reason,
        }
    except Exception as e:
        return {
            "alive": False,
            "transport_active": transport_active,
            "latency_ms": None,
            "reason": "exec-exception",
            "error": str(e),
            "type": e.__class__.__name__,
        }


def kernel_version_impl(
    client: paramiko.SSHClient,
    timeout_seconds: int = 5,
) -> dict:
    """Retrieve the remote kernel version using `uname -rs`."""
    try:
        stdin, stdout, stderr = client.exec_command(
            "uname -rs", timeout=timeout_seconds
        )
        out = stdout.read().decode("utf-8", errors="replace").strip()
        err = stderr.read().decode("utf-8", errors="replace").strip()
        exit_status = stdout.channel.recv_exit_status()
        kernel_name = None
        release = None
        if out:
            parts = out.split()
            if len(parts) >= 2:
                kernel_name, release = parts[0], parts[1]
        return {
            "stdout": out,
            "stderr": err,
            "exit_code": exit_status,
            "kernel_name": kernel_name,
            "release": release,
        }
    except Exception as e:
        return {"error": str(e), "type": e.__class__.__name__}


def get_ethtool_stats_impl(
    client: paramiko.SSHClient,
    interface: str | None = None,
    command: str | None = None,
    timeout_seconds: int = 20,
) -> dict:
    """Get ethtool stats for MANA NIC or run custom command."""
    # Decide command preference order.
    if command:
        base_cmd = command
    else:
        # Ensure a concrete interface (default to the user's
        # requested one if none provided)
        iface = interface or "enP30832s1"
        # ethtool -S provides per-NIC statistics; degrade
        # gracefully if ethtool or iface absent.
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
            full_cmd, timeout=timeout_seconds
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
        paramiko.SSHException,
        EOFError,
        OSError,
        socket.error,
    ) as exec_err:
        panic = True
        panic_reason = f"exec-exception:{exec_err.__class__.__name__}"
    except Exception as e:
        # Unexpected local error (not necessarily panic)
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
            "error": str(e),
            "type": e.__class__.__name__,
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
        and (not after_active)
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
            # Use shlex.quote to reduce risk of shell interpretation issues.
            pw = shlex.quote(sudo_password)
            inner = (
                f"sleep {int(delay_seconds)}; "
                f"echo {pw} | sudo -S {reboot_cmd}"
            )
        else:
            inner = f"sleep {int(delay_seconds)}; sudo {reboot_cmd}"
        # Run in background so we can return before connection is severed.
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
    except Exception as e:
        return {"error": str(e), "type": e.__class__.__name__}
