"""Git operations for kernel source management.

Provides:
- SFTP patch upload
- ``git am`` / ``git apply`` patch application
- ``git clone`` for kernel source trees

All user-supplied values are shell-quoted with ``shlex.quote``.
"""

from __future__ import annotations

import os
import posixpath
import shlex
import time
from typing import Optional

import paramiko  # type: ignore[import-untyped]

from ._helpers import (
    run_ssh,
    remote_path,
    sanitise_name,
    error_result,
    get_logger,
    DEFAULT_REPO_PATH,
    DEFAULT_PATCH_FILENAME,
    DEFAULT_GIT_URL,
)

_log = get_logger("mcp_ssh_server.git_operations")


# ── Private helpers ───────────────────────────────────────────────

def _expand_remote_path(sftp: paramiko.SFTPClient, path: str) -> str:
    """Expand '~' on remote using SFTP's view of remote home."""
    if not path:
        return path
    if path == "~":
        return sftp.normalize(".")
    if path.startswith("~/"):
        home = sftp.normalize(".")
        return posixpath.join(home, path[2:])
    return path


# ── SFTP upload ───────────────────────────────────────────────────

def sftp_patch_file_impl(
    client: paramiko.SSHClient,
    local_path: str,
    remote_path_arg: Optional[str] = None,
) -> dict:
    """Upload a local patch file to the remote VM via SFTP."""
    try:
        lpath = os.path.expanduser(os.path.expandvars(local_path))
        # Strip chat-style surrounding quotes
        if (
            (lpath.startswith('"') and lpath.endswith('"'))
            or (lpath.startswith("'") and lpath.endswith("'"))
        ):
            lpath = lpath[1:-1]
        lpath = os.path.normpath(lpath)

        if not os.path.isfile(lpath):
            return error_result(
                f"Local file not found: {lpath}", "FileNotFound",
            )

        default_remote = f"{DEFAULT_REPO_PATH}/{DEFAULT_PATCH_FILENAME}"
        rpath_in = remote_path_arg or default_remote

        if rpath_in.endswith("/"):
            rpath_in = posixpath.join(rpath_in, os.path.basename(lpath))

        sftp = client.open_sftp()
        try:
            rpath = _expand_remote_path(sftp, rpath_in)
            size_bytes = os.path.getsize(lpath)
            start = time.time()
            sftp.put(lpath, rpath)
            try:
                sftp.chmod(rpath, 0o644)
            except Exception:
                pass
            duration_ms = int((time.time() - start) * 1000)
        finally:
            sftp.close()

        return {
            "ok": True,
            "local_path": lpath,
            "remote_path": rpath,
            "bytes": size_bytes,
            "duration_ms": duration_ms,
        }
    except Exception as exc:
        return error_result(str(exc), exc.__class__.__name__)


# ── Patch application ────────────────────────────────────────────

def git_apply_patch_file_impl(
    client: paramiko.SSHClient,
    repo_path: str = DEFAULT_REPO_PATH,
    patch_path: str = f"{DEFAULT_REPO_PATH}/{DEFAULT_PATCH_FILENAME}",
    timeout_seconds: int = 600,
) -> dict:
    """Apply patch to kernel repo using ``git am`` or ``git apply``.

    Auto-detects mailbox-style patches (``From <40hex> …``) and
    uses ``git am -3``; otherwise uses ``git apply`` + explicit commit.
    """
    rpath = remote_path(repo_path)
    ppath = remote_path(patch_path)

    script = f"""
    set -e
    cd {rpath}
    git rev-parse --is-inside-work-tree >/dev/null
    [ -f {ppath} ] || (echo 'patch file not found' >&2; exit 2)

    if head -n1 {ppath} | grep -E -q '^From [0-9a-f]{{40}} ' ; then
        GIT_COMMITTER_NAME="Debug Agent" \\
        GIT_COMMITTER_EMAIL="debugagent@example.invalid" \\
        git -c user.name="Debug Agent" \\
            -c user.email="debugagent@example.invalid" \\
            am -3 {ppath}
    else
        git apply {ppath}
        git -c user.name="Debug Agent" \\
            -c user.email="debugagent@example.invalid" \\
            commit -a -m "Apply patch: $(basename {ppath})"
    fi
    """
    cmd = f"bash -lc {shlex.quote(script)}"
    code, out, err, dur = run_ssh(client, cmd, timeout=timeout_seconds)
    return {
        "exit_code": code,
        "duration_ms": dur,
        "stdout": out,
        "stderr": err,
        "repo_path": repo_path,
        "patch_path": patch_path,
    }


# ── Clone kernel source ─────────────────────────────────────────

def clone_linux_source_tree_impl(
    client: paramiko.SSHClient,
    git_url: Optional[str] = None,
    destination_path: Optional[str] = None,
    branch: Optional[str] = None,
    timeout_seconds: int = 1200,
) -> dict:
    """Clone a Linux kernel source tree into the VM.

    All user-supplied strings (git_url, branch, destination_path)
    are shell-quoted to prevent injection.
    """
    url = git_url or DEFAULT_GIT_URL

    # Derive repo name safely
    repo_name = sanitise_name(
        url.rstrip("/").split("/")[-1].removesuffix(".git")
    )
    dest = destination_path or f"~/repos/{repo_name}"

    # Use remote_path for dest (handles ~ expansion), shlex.quote for url/branch
    parts = ["git clone"]
    if branch:
        parts.append(f"--branch {shlex.quote(branch)}")
    parts.append(shlex.quote(url))
    parts.append(remote_path(dest))
    cmd = " ".join(parts)

    code, out, err, dur = run_ssh(client, cmd, timeout=timeout_seconds)
    return {
        "stdout": out,
        "stderr": err,
        "exit_code": code,
        "duration_ms": dur,
        "command": cmd,
        "destination_path": dest,
    }
