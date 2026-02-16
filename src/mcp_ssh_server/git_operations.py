"""Git operations for kernel source management."""
import os
import posixpath
import shlex
import time
from typing import Optional
import paramiko  # type: ignore[import-untyped]


def _expand_remote_path(sftp: paramiko.SFTPClient, path: str) -> str:
    """Expand '~' on remote using SFTP's view of remote home directory."""
    if not path:
        return path
    if path == "~":
        return sftp.normalize(".")
    if path.startswith("~/"):
        home = sftp.normalize(".")
        return posixpath.join(home, path[2:])
    return path


def sftp_patch_file_impl(
    client: paramiko.SSHClient,
    local_path: str,
    remote_path: Optional[str] = None,
) -> dict:
    """Upload a local patch file to the remote VM via SFTP."""
    try:
        # Resolve local path on Windows host
        lpath = os.path.expanduser(os.path.expandvars(local_path))
        # Allow quoted paths from chat (strip matching quotes)
        if (lpath.startswith('"') and lpath.endswith('"')) or (
            lpath.startswith("'") and lpath.endswith("'")
        ):
            lpath = lpath[1:-1]
        lpath = os.path.normpath(lpath)

        if not os.path.isfile(lpath):
            return {
                "error": f"Local file not found: {lpath}",
                "type": "FileNotFound",
            }

        # Default remote path
        rpath_in = remote_path or "~/repos/net-next/debugAgent.patch"

        # If user passed a remote directory (trailing slash),
        # append local filename
        if rpath_in.endswith("/"):
            rpath_in = posixpath.join(rpath_in, os.path.basename(lpath))

        sftp = client.open_sftp()
        try:
            # Expand "~" to remote home
            rpath = _expand_remote_path(sftp, rpath_in)

            size_bytes = os.path.getsize(lpath)
            start = time.time()
            sftp.put(lpath, rpath)
            try:
                # best-effort sane perms (ignore errors)
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

    except Exception as e:
        return {"error": str(e), "type": e.__class__.__name__}


def git_apply_patch_file_impl(
    client: paramiko.SSHClient,
    repo_path: str = "~/repos/net-next",
    patch_path: str = "~/repos/net-next/debugAgent.patch",
    timeout_seconds: int = 600,
) -> dict:
    """Apply patch to kernel repo using git am or git apply."""
    script = f"""
    set -e
    cd {repo_path}
    git rev-parse --is-inside-work-tree >/dev/null
    [ -f {patch_path} ] || (echo 'patch file not found' >&2; exit 2)

    # Detect mailbox style patch: use grep -E with {{40}}
    # (extended regex) to avoid escaping braces complexity
    if head -n1 {patch_path} | grep -E -q '^From [0-9a-f]{{40}} ' ; then
    GIT_COMMITTER_NAME="Debug Agent" \
    GIT_COMMITTER_EMAIL="debugagent@example.invalid" \
    git -c user.name="Debug Agent" \
    -c user.email="debugagent@example.invalid" \
    am -3 {patch_path}
    else
    git apply {patch_path}
    git -c user.name="Debug Agent" \
    -c user.email="debugagent@example.invalid" \
    commit -a -m "Apply patch: $(basename {patch_path})"
    fi
    """
    try:
        cmd = f"bash -lc {shlex.quote(script)}"
        start = time.time()
        stdin, stdout, stderr = client.exec_command(
            cmd, timeout=timeout_seconds
        )
        out = stdout.read().decode("utf-8", errors="replace")
        err = stderr.read().decode("utf-8", errors="replace")
        code = stdout.channel.recv_exit_status()
        duration_ms = int((time.time() - start) * 1000)
        return {
            "exit_code": code,
            "duration_ms": duration_ms,
            "stdout": out,
            "stderr": err,
            "repo_path": repo_path,
            "patch_path": patch_path,
        }
    except Exception as e:
        return {"error": str(e), "type": e.__class__.__name__}


def clone_linux_source_tree_impl(
    client: paramiko.SSHClient,
    git_url: Optional[str] = None,
    destination_path: Optional[str] = None,
    branch: Optional[str] = None,
    timeout_seconds: int = 1200,
) -> dict:
    """Clone a Linux kernel source tree into the VM."""
    try:
        if not git_url:
            git_url = (
                "git://git.kernel.org/pub/scm/linux/kernel/git/"
                "netdev/net-next.git"
            )
        # Parse repo name from git_url
        repo_name = git_url.rstrip('/').split('/')[-1]
        if repo_name.endswith('.git'):
            repo_name = repo_name[:-4]
        if not destination_path:
            destination_path = f"~/repos/{repo_name}"
        if branch:
            cmd = (
                f"git clone --branch {branch} {git_url} {destination_path}"
            )
        else:
            cmd = f"git clone {git_url} {destination_path}"
        start = time.time()
        stdin, stdout, stderr = client.exec_command(
            cmd, timeout=timeout_seconds
        )
        out = stdout.read().decode("utf-8", errors="replace")
        err = stderr.read().decode("utf-8", errors="replace")
        exit_status = stdout.channel.recv_exit_status()
        duration_ms = int((time.time()-start)*1000)
        return {
            "stdout": out,
            "stderr": err,
            "exit_code": exit_status,
            "duration_ms": duration_ms,
            "command": cmd,
            "destination_path": destination_path
        }
    except Exception as e:
        return {"error": str(e), "type": e.__class__.__name__}
