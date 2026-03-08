"""Shared helpers and constants for MCP SSH Server.

Provides reusable utilities across all server modules:
- SSH command execution with consistent error handling
- Shell command builders (sudo wrappers, path expansion)
- Standardised response-dict constructors
- Default constants and configuration values

Import examples:
    from _helpers import run_ssh, remote_path, sudo_wrap
    from _helpers import DEFAULT_REPO_PATH, DEV_PACKAGES
"""

from __future__ import annotations

import logging
import re
import shlex
import time
from typing import Any, Optional, Tuple

import paramiko  # type: ignore[import-untyped]

__all__ = [
    # execution
    "run_ssh",
    # shell helpers
    "remote_path",
    "sudo_wrap",
    "build_sudo_runner_snippet",
    "sanitise_name",
    # response builders
    "error_result",
    "not_found_result",
    # logging
    "get_logger",
    # constants
    "DEFAULT_REPO_PATH",
    "DEFAULT_PATCH_FILENAME",
    "DEFAULT_GIT_URL",
    "DEFAULT_GIT_URL_HTTPS",
    "DEFAULT_CRASH_ROOT",
    "DEV_PACKAGES",
    "KERNEL_CONFIG_DISABLES",
    "KERNEL_CONFIG_UNDEFINES",
]


# ── Logging ───────────────────────────────────────────────────────

def get_logger(name: str = "mcp_ssh_server") -> logging.Logger:
    """Get or create a module-level logger with a sensible default
    format.  Idempotent — calling twice returns the same logger."""
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(
            logging.Formatter(
                "%(asctime)s %(levelname)s %(name)s: %(message)s"
            )
        )
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
    return logger


# ── Defaults & Constants ──────────────────────────────────────────

DEFAULT_REPO_PATH: str = "~/repos/net-next"
DEFAULT_PATCH_FILENAME: str = "debugAgent.patch"
DEFAULT_GIT_URL: str = (
    "git://git.kernel.org/pub/scm/linux/kernel/git/netdev/net-next.git"
)
DEFAULT_GIT_URL_HTTPS: str = (
    "https://git.kernel.org/pub/scm/linux/kernel/git/"
    "netdev/net-next.git"
)
DEFAULT_CRASH_ROOT: str = "/var/crash"

DEV_PACKAGES: list[str] = [
    "build-essential",
    "libncurses-dev",
    "bison",
    "flex",
    "libssl-dev",
    "libelf-dev",
    "ssh",
    "git",
    "vim",
    "net-tools",
    "zstd",
    "universal-ctags",
    "libdw-dev",
]

# Kernel config options to disable for reproducible builds
KERNEL_CONFIG_DISABLES: list[str] = [
    "SYSTEM_TRUSTED_KEYS",
    "SYSTEM_REVOCATION_KEYS",
    "MODULE_SIG",
    "MODULE_SIG_ALL",
    "MODULE_SIG_SHA512",
]
KERNEL_CONFIG_UNDEFINES: list[str] = [
    "MODULE_SIG_KEY",
]


# ── SSH Command Execution ────────────────────────────────────────

def run_ssh(
    client: paramiko.SSHClient,
    command: str,
    timeout: int = 300,
    encoding: str = "utf-8",
) -> Tuple[int, str, str, int]:
    """Execute *command* over an SSH connection.

    Returns
    -------
    (exit_code, stdout, stderr, duration_ms)
        On exception exit_code is ``-1`` and stderr contains the
        error message.  This function **never raises**.
    """
    start = time.time()
    try:
        stdin, stdout, stderr = client.exec_command(
            command, timeout=timeout
        )
        out = stdout.read().decode(encoding, errors="replace")
        err = stderr.read().decode(encoding, errors="replace")
        code = stdout.channel.recv_exit_status()
        duration_ms = int((time.time() - start) * 1000)
        return code, out, err, duration_ms
    except Exception as e:
        duration_ms = int((time.time() - start) * 1000)
        return -1, "", f"{e.__class__.__name__}: {e}", duration_ms


# ── Shell Helpers ─────────────────────────────────────────────────

def remote_path(path: str) -> str:
    """Convert a user-supplied path to a shell-safe remote path.

    ``~/foo``       → ``${HOME}/foo``  (variable expansion)
    ``$HOME/foo``   → ``${HOME}/foo``
    ``/abs/path``   → ``'/abs/path'``  (shlex-quoted)
    """
    for prefix in ("~/", "$HOME/", "${HOME}/"):
        if path.startswith(prefix):
            tail = path[len(prefix):]
            return f"${{HOME}}/{tail}"
    if path == "~":
        return "${HOME}"
    return shlex.quote(path)


def sudo_wrap(
    command: str,
    sudo_password: Optional[str] = None,
) -> str:
    """Wrap a shell command string with sudo.

    If *sudo_password* is given, pipes it via stdin with ``-S`` flag.
    Always uses ``shlex.quote`` for safety.
    """
    if sudo_password:
        pw = shlex.quote(sudo_password)
        return (
            f"echo {pw} | sudo -S bash -lc {shlex.quote(command)}"
        )
    return f"sudo bash -lc {shlex.quote(command)}"


def build_sudo_runner_snippet(
    sudo_password: Optional[str] = None,
) -> str:
    """Return a bash snippet defining a ``run_sudo()`` function.

    Embed this in a larger bash script::

        {build_sudo_runner_snippet(pw)}
        run_sudo "make install"
    """
    pw = shlex.quote(sudo_password or "")
    return (
        f"SUDO_PW={pw}\n"
        "run_sudo() {\n"
        '    if [ -n "$SUDO_PW" ]; then\n'
        '        echo "$SUDO_PW" | sudo -S bash -lc "$1"\n'
        "    else\n"
        '        sudo bash -lc "$1"\n'
        "    fi\n"
        "}"
    )


def sanitise_name(name: str) -> str:
    """Strip a name (e.g. repo basename) to safe filesystem chars."""
    return re.sub(r"[^a-zA-Z0-9._-]", "_", name)


# ── Response Builders ────────────────────────────────────────────

def error_result(
    message: str,
    error_type: str = "Error",
    **extra: Any,
) -> dict:
    """Build a standardised error response dict."""
    return {"error": message, "type": error_type, **extra}


def not_found_result(connection_id: str) -> dict:
    """Standard error when *connection_id* is unknown or expired."""
    return {
        "error": (
            f"Unknown or expired connection_id: {connection_id}"
        ),
        "type": "NotFound",
    }
