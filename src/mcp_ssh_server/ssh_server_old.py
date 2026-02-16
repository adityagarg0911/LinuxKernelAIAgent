import base64
import io
import os
import time
import uuid
import socket
from datetime import datetime, timedelta
from typing import Optional, Literal, Dict
import paramiko  # type: ignore[import-untyped]
from mcp.server.fastmcp import FastMCP  # type: ignore[import-not-found]
import posixpath
import shlex
import re

mcp = FastMCP("SSH")

_connections: Dict[str, paramiko.SSHClient] = {}


def _build_pkey(private_key: str, passphrase: Optional[str]) -> paramiko.PKey:
    key_data = private_key.strip()
    if "-----BEGIN" not in key_data:
        try:
            key_data = base64.b64decode(key_data).decode("utf-8")
        except Exception:
            pass
    last_error = None
    for key_cls in (
        paramiko.RSAKey,
        paramiko.ECDSAKey,
        paramiko.Ed25519Key,
        getattr(paramiko, "DSSKey", None),
    ):
        if key_cls is None:
            continue
        try:
            return key_cls.from_private_key(
                io.StringIO(key_data), password=passphrase
            )
        except Exception as e:
            last_error = e
            continue
    raise ValueError(f"Could not parse private key: {last_error}")


def _make_client(accept_unknown_host: bool) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    if accept_unknown_host:
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    else:
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
    return client


def _expand_remote_path(sftp: paramiko.SFTPClient, path: str) -> str:
    """
    Expand '~' on the remote using SFTP's view of the remote home directory.
    """
    if not path:
        return path
    if path == "~":
        return sftp.normalize(".")           # usually /home/<user>
    if path.startswith("~/"):
        home = sftp.normalize(".")
        return posixpath.join(home, path[2:])
    return path


@mcp.tool()
def ssh_connect(
    host: str,
    username: str,
    port: int = 22,
    password: Optional[str] = None,
    private_key: Optional[str] = None,
    passphrase: Optional[str] = None,
    timeout_seconds: int = 30,
    accept_unknown_host: bool = True,
) -> dict:
    """Establish and cache a persistent SSH connection.

    NOTE: Do NOT invoke unless the user explicitly requests a new
    connection (reuse existing connection_id when possible).
    Provide exactly one of password or private_key. Returns a
    connection_id you can use with ssh_exec/ssh_close.
    Dont call any extra function after this unless explicitly
    requested by the user.
    """
    if (password is None) == (private_key is None):
        raise ValueError("Provide exactly one of password or private_key")

    client = _make_client(accept_unknown_host)
    pkey_obj = _build_pkey(private_key, passphrase) if private_key else None
    try:
        start = time.time()
        client.connect(
            hostname=host,
            port=port,
            username=username,
            password=password,
            pkey=pkey_obj,
            timeout=timeout_seconds,
            banner_timeout=timeout_seconds,
            auth_timeout=timeout_seconds,
        )
        conn_id = str(uuid.uuid4())
        _connections[conn_id] = client
        return {
            "connection_id": conn_id,
            "host": host,
            "port": port,
            "username": username,
            "connect_ms": int((time.time() - start) * 1000),
        }
    except Exception as e:
        client.close()
        return {"error": str(e), "type": e.__class__.__name__}


@mcp.tool()
def ssh_close(connection_id: str) -> dict:
    """Close a previously established SSH connection."""
    client = _connections.pop(connection_id, None)
    if client is None:
        return {"error": "Unknown connection_id", "type": "NotFound"}
    try:
        client.close()
        return {"closed": True}
    except Exception as e:
        return {"error": str(e), "type": e.__class__.__name__}


@mcp.tool()
def ssh_list() -> dict:
    """List active SSH connection IDs."""
    return {"connections": list(_connections.keys())}


@mcp.tool()
def install_developer_tools(
    connection_id: str,
    sudo_password: Optional[str] = None,
    timeout_seconds: int = 120,
) -> dict:
    """Install basic developer tools on the remote VM using sudo
    apt-get install. Optionally provide sudo_password.
    """
    client = _connections.get(connection_id)
    if client is None:
        return {"error": "Unknown connection_id", "type": "NotFound"}
    try:
        if sudo_password:
            cmd = (
                f"echo {sudo_password} | sudo -S apt update && "
                f"echo {sudo_password} | sudo -S apt install -y "
                f"build-essential libncurses-dev bison flex "
                f"libssl-dev libelf-dev ssh git vim net-tools "
                f"zstd universal-ctags"
            )
        else:
            cmd = (
                "sudo apt update && "
                "sudo apt install -y build-essential libncurses-dev "
                "bison flex libssl-dev libelf-dev ssh git vim "
                "net-tools zstd universal-ctags"
            )
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
            "command": cmd
        }
    except Exception as e:
        return {"error": str(e), "type": e.__class__.__name__}


@mcp.tool()
def clone_linux_source_tree(
    connection_id: str,
    git_url: Optional[str] = None,
    destination_path: Optional[str] = None,
    branch: Optional[str] = None,
    timeout_seconds: int = 1200,
) -> dict:
    """
    Clone a Linux kernel source tree in the VM using the active SSH
    connection.

    Use this tool when the user asks to clone a Linux kernel source
    tree (e.g., net-next or any other kernel repo).
    By default, this tool clones the net-next tree (mainline
    networking development) into ~/repos/net-next.
    If the user provides a specific git_url, that repository will be
    cloned instead, into ~/repos/{repo-name} unless a custom
    destination_path is given.

    When to invoke:
    - Use this tool for requests like "clone net-next", "clone kernel
      source", "clone linux tree", etc.
    - If no git_url is specified, the net-next tree will be cloned by default.
    - If you want a different tree, provide the git_url explicitly.
    """
    client = _connections.get(connection_id)
    if client is None:
        return {"error": "Unknown connection_id", "type": "NotFound"}
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
            cmd = f"git clone --branch {branch} {git_url} {destination_path}"
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


@mcp.tool()
def sftp_patch_file(
    connection_id: str,
    local_path: str,
    remote_path: Optional[str] = None,
) -> dict:
    """
    Upload a local .patch file (from the machine running this MCP
    server) to the remote VM via SFTP.

    - If remote_path is omitted, it defaults to:
      ~/repos/net-next/debugAgent.patch
    - If remote_path ends with '/', the file will be uploaded with
      the same basename into that directory.
    """
    client = _connections.get(connection_id)
    if client is None:
        return {"error": "Unknown connection_id", "type": "NotFound"}

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
            # Expand "~" to remote home and ensure parent directory exists
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


@mcp.tool()
def git_apply_patch_file(
        connection_id: str,
        repo_path: str = "~/repos/net-next",
        patch_path: str = "~/repos/net-next/debugAgent.patch",
        timeout_seconds: int = 600,
) -> dict:
    """Apply patch to kernel repo (net-next by default).

    TRIGGER KEYWORDS: apply patch | apply git patch | git am |
    git apply | apply debugAgent.patch | apply diff

    Simple logic:
        - cd repo (default: ~/repos/net-next)
        - mailbox patch? (first line 'From <40hex> ') => git am -3 patch
        - else => git apply patch && git commit -a -m "Apply patch: <filename>"

    Use this instead of generic ssh_exec when user asks to apply a patch.
    Parameters: connection_id, repo_path?, patch_path?
    Returns: exit_code, stdout, stderr, repo_path, patch_path.
    """
    client = _connections.get(connection_id)
    if client is None:
        return {"error": "Unknown connection_id", "type": "NotFound"}

    script = f"""
    set -e
    cd {repo_path}
    git rev-parse --is-inside-work-tree >/dev/null
    [ -f {patch_path} ] || (echo 'patch file not found' >&2; exit 2)

    # Detect mailbox style patch: use grep -E with {40}
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


@mcp.tool()
def reboot_vm(
    connection_id: str,
    sudo_password: Optional[str] = None,
    force: bool = False,
    delay_seconds: int = 1,
) -> dict:
    """Initiate an asynchronous reboot of the remote VM.

    Behavior:
    - Uses an existing SSH connection (required).
    - Spawns a background `nohup` shell that sleeps briefly, then runs reboot.
    - Returns immediately before the SSH session is terminated by the reboot.
    - If `sudo_password` is provided, uses it via `echo <pw> | sudo -S`.
    - If `force` is True, uses `reboot -f` (force immediate reboot).
    - `delay_seconds` lets the background shell finish writing response
      before network drop.

    Notes:
    - After a successful response, the VM will go down shortly; further
      commands on the same connection will fail.
    - This tool does not verify that the VM came back up; that must be
      done separately by attempting a new ssh_connect later.
    """
    client = _connections.get(connection_id)
    if client is None:
        return {"error": "Unknown connection_id", "type": "NotFound"}
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
        full_cmd = f"nohup sh -c '{inner}' >/dev/null 2>&1 & echo REBOOTING"
        stdin, stdout, stderr = client.exec_command(full_cmd, timeout=5)
        out = stdout.read().decode("utf-8", errors="replace").strip()
        err = stderr.read().decode("utf-8", errors="replace").strip()
        # Remove the connection from the active pool since it will
        # shortly be invalid.
        _connections.pop(connection_id, None)
        return {
            "started": True,
            "stdout": out,
            "stderr": err,
            "command": full_cmd,
            "force": force,
            "delay_seconds": delay_seconds,
            "connection_removed": True,
            "connection_id": connection_id,
        }
    except Exception as e:
        return {"error": str(e), "type": e.__class__.__name__}


@mcp.tool()
def kernel_version(
    connection_id: str,
    timeout_seconds: int = 5,
) -> dict:
    """Retrieve the remote kernel version using `uname -rs`.

    TRIGGER KEYWORDS: kernel version | uname -r | uname -rs | check kernel
    Returns both the raw output and parsed fields.
    """
    client = _connections.get(connection_id)
    if client is None:
        return {"error": "Unknown connection_id", "type": "NotFound"}
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


@mcp.tool()
def check_connection(
    connection_id: str,
    timeout_seconds: int = 5,
) -> dict:
    """SSH connection liveness check (exec probe only).

    Always runs a minimal remote command `echo OK` to verify a full
    round-trip (transport + channel + command execution) and measures
    latency. Use this after any failing operation to confirm whether the
    remote VM / kernel is still responsive.
    If the connection is not alive, do ssh_close and ssh_connect again.

    Returns:
      - alive: bool
      - transport_active: bool
      - latency_ms: int | None
      - stdout / stderr / exit_code
      - reason (when not alive): exec-failed | transport-inactive |
        exec-exception
      - error / type (if exception)
    """
    client = _connections.get(connection_id)
    if client is None:
        return {"error": "Unknown connection_id", "type": "NotFound"}

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


@mcp.tool()
def get_ethtool_stats(
    connection_id: str,
    interface: str | None = None,
    command: str | None = None,
    timeout_seconds: int = 20,
) -> dict:
    """Get Ethtool stats for MANA NIC
    Run ethtool statistics (default: `ethtool -S <iface>`) or a
    custom command and apply a quick panic heuristic.

    Updated behavior:
        - Primary intent is to fetch NIC statistics via `ethtool -S`
          (was previously using other ethtool subcommands).
        - If 'command' is supplied, it is executed verbatim (via
          bash -lc) instead of the stats command.
        - If no 'command' and an 'interface' is provided:
          run `ethtool -S <interface>`.
        - If neither 'command' nor 'interface' is given: default
          interface 'enP30832s1' is used.

    Panic heuristic (unchanged, coarse):
        - SSH exec exceptions (SSHException/EOFError/OSError/
          socket.error) => panic=True
        - Exceptions while reading stdout/stderr or retrieving
          exit status => panic=True
        - Transport becomes inactive after command with no
          exit_code => panic=True

    Returns dict:
        {
            panic, panic_reason, exit_code, stdout, stderr, duration_ms,
            executed_command, interface, transport_active_after
        }
    If panic occurs, LLM should run command for check ssh connection,
    close ssh, ssh_connect, analyze_latest_crash_dmesg. It should not
    rerun this same command without user asking.
    """
    client = _connections.get(connection_id)
    if client is None:
        return {"error": "Unknown connection_id", "type": "NotFound"}

    # Decide command
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
                panic_reason = f"status-exception:{st_err.__class__.__name__}"
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


@mcp.tool()
def analyze_dmesg_tail(
    connection_id: str,
    lines: int = 100,
    sudo_password: str | None = None,
    timeout_seconds: int = 8,
) -> dict:
    """Fetch and heuristically analyze the tail of dmesg for recent problems.

    Parameters:
      lines (int): How many lines from the end of dmesg to inspect
        (default 100).
      sudo_password (optional): If provided, will attempt `sudo dmesg`
        if plain dmesg fails.

    Heuristics:
      Scans tail for common critical markers (case-insensitive where relevant):
        - panic
        - oops
        - BUG:
        - WARNING:
        - Call Trace:
        - RIP: / CR2: (arch crash context)
        - segfault
        - soft lockup / hard lockup
        - general protection fault

    Returns:
      - stdout / stderr / exit_code (from successful retrieval)
      - lines_requested / lines_returned
      - issues_detected (bool)
      - indicators (counts dict)
      - events (list of {kind, line_index, text})
      - last_event (kind or None)
      - raw_tail (the joined tail text)
      - used_sudo (bool) whether sudo was used

    LLM finally gives a crisp and short analysis of the crash, steps
    to mitigate, update in patch if possible or needed.
    """
    client = _connections.get(connection_id)
    if client is None:
        return {"error": "Unknown connection_id", "type": "NotFound"}

    if lines <= 0:
        return {"error": "lines must be > 0", "type": "ValueError"}

    # Always attempt via sudo (per updated requirement).
    # If sudo_password provided, feed it; otherwise rely on sudo
    # permissions.
    base_cmd = f"dmesg | tail -n {int(lines)}"
    if sudo_password:
        full_cmd = (
            f"echo {shlex.quote(sudo_password)} | sudo -S bash -lc "
            f"{shlex.quote(base_cmd)}"
        )
    else:
        full_cmd = f"sudo bash -lc {shlex.quote(base_cmd)}"
    used_sudo = True
    try:
        stdin, stdout, stderr = client.exec_command(
            full_cmd, timeout=timeout_seconds
        )
        out = stdout.read().decode("utf-8", errors="replace")
        err = stderr.read().decode("utf-8", errors="replace")
        exit_code = stdout.channel.recv_exit_status()
    except Exception as e:
        return {
            "error": str(e),
            "type": e.__class__.__name__,
            "used_sudo": used_sudo,
        }

    lines_list = out.splitlines()
    indicators = {
        "panic": 0,
        "oops": 0,
        "bug": 0,
        "warning": 0,
        "call_trace": 0,
        "segfault": 0,
        "lockup": 0,
        "gp_fault": 0,
    }
    events = []
    pattern_map = [
        ("panic", re.compile(r"kernel panic", re.IGNORECASE)),
        ("oops", re.compile(r"oops", re.IGNORECASE)),
        ("bug", re.compile(r"BUG: ", re.IGNORECASE)),
        ("warning", re.compile(r"WARNING:", re.IGNORECASE)),
        ("call_trace", re.compile(r"Call Trace:", re.IGNORECASE)),
        ("segfault", re.compile(r"segfault", re.IGNORECASE)),
        ("lockup", re.compile(r"(soft|hard) lockup", re.IGNORECASE)),
        ("gp_fault", re.compile(r"general protection fault", re.IGNORECASE)),
    ]

    for idx, line in enumerate(lines_list):
        for kind, pat in pattern_map:
            if pat.search(line):
                indicators[kind] += 1
                events.append({
                    "kind": kind,
                    "line_index": idx,
                    "text": line.strip()[:500],
                })
                break

    issues_detected = any(v > 0 for v in indicators.values())
    last_event = events[-1]["kind"] if events else None

    return {
        "stdout": out,
        "stderr": err,
        "exit_code": exit_code,
        "lines_requested": lines,
        "lines_returned": len(lines_list),
        "issues_detected": issues_detected,
        "indicators": indicators,
        "events": events,
        "last_event": last_event,
        "raw_tail": out,
        "used_sudo": used_sudo,
    }


def _analyze_dmesg_text_light(raw: str) -> dict:
    """Lightweight kernel crash / fault heuristic analyzer for dmesg text.

    Extracts:
      event_type: panic | null_deref | bug | oops | none
      fault_address (CR2) if present
      suspected_function (from first call trace entry)
      call_trace (list)
      modules_line (if present)
      short_summary
      recommended_actions (list)
    """
    lines = raw.splitlines()
    event_type = None
    fault_addr = None
    call_trace = []
    capturing_trace = False
    modules_line = None
    suspected_function = None

    re_bug = re.compile(
        r"BUG: (kernel )?NULL pointer dereference, "
        r"address: (0x?[0-9a-fA-F]+)"
    )
    re_panic = re.compile(r"kernel panic", re.IGNORECASE)
    re_oops = re.compile(r"Oops:")
    re_cr2 = re.compile(r"CR2: *(0x?[0-9a-fA-F]+)")
    re_calltrace = re.compile(r"Call Trace:")
    re_modules = re.compile(r"^Modules linked in: (.*)")

    for line in lines:
        if event_type != "panic" and re_panic.search(line):
            event_type = "panic"
        bug_m = re_bug.search(line)
        if bug_m:
            event_type = "null_deref"
            fault_addr = bug_m.group(2)
        if event_type not in ("panic", "null_deref") and re_oops.search(line):
            event_type = event_type or "oops"
        cr2_m = re_cr2.search(line)
        if cr2_m and not fault_addr:
            fault_addr = cr2_m.group(1)
        if re_calltrace.search(line):
            capturing_trace = True
            continue
        if capturing_trace:
            if not line.strip():
                capturing_trace = False
            else:
                call_trace.append(line.strip())
        # if line.startswith("RIP:"):
        #     rip_line = line
        if re_modules.match(line):
            modules_line = line

    # Suspected function from first call trace entry
    for entry in call_trace:
        if not entry:
            continue
        token = entry.split()[0]
        if token.startswith("?"):
            continue
        # token like function+0xNN/0xMM
        suspected_function = token.split('+')[0]
        break

    if not event_type:
        event_type = "bug" if "BUG:" in raw else "none"

    summary_bits = []
    match event_type:
        case "panic": summary_bits.append("Kernel panic")
        case "null_deref": summary_bits.append("NULL pointer dereference")
        case "oops": summary_bits.append("Kernel oops")
        case "bug": summary_bits.append("Kernel bug indication")
        case _: summary_bits.append("No critical signature detected")
    if suspected_function:
        summary_bits.append(f"in {suspected_function}")
    if fault_addr:
        summary_bits.append(f"at {fault_addr}")
    short_summary = ": ".join(summary_bits[:1]) + (
        " - " + " ".join(summary_bits[1:])
        if len(summary_bits) > 1
        else ""
    )

    recs = []
    if event_type == "null_deref":
        recs.extend([
            "Validate pointer before dereference (add guard).",
            "Audit allocation / init path for lifetime issues.",
        ])
    if event_type in ("panic", "oops"):
        recs.append(
            "Inspect first warning/oops preceding the panic "
            "for root cause."
        )
    if suspected_function:
        recs.append(f"Review recent changes around {suspected_function}.")
    if not recs:
        recs.append(
            "No severe indicators; consider extended tracing "
            "(ftrace/bpf)."
        )

    return {
        "event_type": event_type,
        "fault_address": fault_addr,
        "suspected_function": suspected_function,
        "call_trace": call_trace,
        "modules_line": modules_line,
        "short_summary": short_summary,
        "recommended_actions": recs,
    }


@mcp.tool()
def analyze_latest_crash_dmesg(
    connection_id: str,
    crash_root: str = "/var/crash",
    sudo_password: str | None = None,
    max_bytes: int = 500_000,
    timeout_seconds: int = 20,
) -> dict:
    """Locate the newest crash directory (/var/crash/YYYYMMDDHHMM) and
    analyze its dmesg.<timestamp> file.

    Directory naming convention assumed: 12-digit UTC timestamp YYYYMMDDHHMM.
    We:
      1. List candidate directories matching ^[0-9]{12}$ under crash_root.
      2. Pick the latest lexicographically (correct for this timestamp format).
      3. Read dmesg.<timestamp> (fallback: first file starting with dmesg.).
      4. Run lightweight heuristic analysis (_analyze_dmesg_text_light).
      5. Convert UTC timestamp to IST (+05:30) for convenience.

    Returns fields:
      - crash_dir, timestamp_utc, timestamp_ist
      - dmesg_path, retrieved_bytes, truncated (bool)
      - analysis (nested dict: event_type, short_summary, ...)
      - raw_excerpt (tail ~40 lines)
      - stdout/stderr/exit_code from retrieval (for debugging) if error

    LLM finally gives a crisp and short analysis of the crash, steps
    to mitigate, update in patch if possible or needed.
    """
    client = _connections.get(connection_id)
    if client is None:
        return {"error": "Unknown connection_id", "type": "NotFound"}

    # Step 1: list directories
    list_cmd = (
        f"bash -lc 'ls -1 {shlex.quote(crash_root)} 2>/dev/null | "
        f"grep -E " + "'^[0-9]{12}$'" + " | sort'"
    )
    try:
        stdin, stdout, stderr = client.exec_command(
            list_cmd, timeout=timeout_seconds
        )
        dirs_out = stdout.read().decode("utf-8", errors="replace")
        dirs_err = stderr.read().decode("utf-8", errors="replace")
        _ = stdout.channel.recv_exit_status()
    except Exception as e:
        return {"error": str(e), "type": e.__class__.__name__, "stage": "list"}

    candidates = [d.strip() for d in dirs_out.splitlines() if d.strip()]
    candidates = [d for d in candidates if len(d) == 12 and d.isdigit()]
    if not candidates:
        return {
            "error": "No crash directories found",
            "type": "NotFound",
            "crash_root": crash_root,
            "stdout": dirs_out,
            "stderr": dirs_err,
        }

    latest = candidates[-1]
    utc_ts = latest
    # Parse timestamp
    try:
        dt_utc = datetime.strptime(utc_ts, "%Y%m%d%H%M")
        dt_ist = dt_utc + timedelta(hours=5, minutes=30)
        ts_utc_iso = dt_utc.isoformat() + "Z"
        ts_ist_iso = dt_ist.isoformat()
    except Exception:
        ts_utc_iso = utc_ts
        ts_ist_iso = None

    # Determine dmesg file path
    dmesg_path = f"{crash_root}/{latest}/dmesg.{latest}"
    # Fallback command: if direct cat fails, list files starting with dmesg.
    if sudo_password:
        cat_cmd = (
            f"echo {shlex.quote(sudo_password)} | sudo -S bash -lc "
            f"'cat {shlex.quote(dmesg_path)}'"
        )
    else:
        cat_cmd = f"bash -lc 'cat {shlex.quote(dmesg_path)}'"

    try:
        stdin, stdout, stderr = client.exec_command(
            cat_cmd, timeout=timeout_seconds
        )
        raw_bytes = stdout.read()[:max_bytes+1]
        err_text = stderr.read().decode("utf-8", errors="replace")
        exit_code = stdout.channel.recv_exit_status()
        if exit_code != 0 or not raw_bytes:
            # fallback list
            list_dmesg_cmd = (
                f"bash -lc 'ls -1 {shlex.quote(crash_root)}/{latest} "
                f"2>/dev/null | grep ^dmesg'"
            )
            if sudo_password:
                list_dmesg_cmd = (
                    f"echo {shlex.quote(sudo_password)} | sudo -S "
                    f"{list_dmesg_cmd}"
                )
            stdin2, stdout2, stderr2 = client.exec_command(
                list_dmesg_cmd, timeout=timeout_seconds
            )
            files_list = stdout2.read().decode(
                "utf-8", errors="replace"
            ).splitlines()
            err2 = stderr2.read().decode("utf-8", errors="replace")
            # Pick first file
            alt = files_list[0].strip() if files_list else None
            if alt:
                dmesg_path = f"{crash_root}/{latest}/{alt}"
                if sudo_password:
                    cat_cmd = (
                        f"echo {shlex.quote(sudo_password)} | "
                        f"sudo -S bash -lc 'cat {shlex.quote(dmesg_path)}'"
                    )
                else:
                    cat_cmd = f"bash -lc 'cat {shlex.quote(dmesg_path)}'"
                stdin3, stdout3, stderr3 = client.exec_command(
                    cat_cmd, timeout=timeout_seconds
                )
                raw_bytes = stdout3.read()[:max_bytes+1]
                err_text = stderr3.read().decode("utf-8", errors="replace")
                exit_code = stdout3.channel.recv_exit_status()
            else:
                return {
                    "error": "dmesg file not found in crash dir",
                    "type": "NotFound",
                    "crash_dir": latest,
                    "stderr": err_text + "\n" + err2,
                }
    except Exception as e:
        return {"error": str(e), "type": e.__class__.__name__, "stage": "read"}

    raw = raw_bytes.decode("utf-8", errors="replace")
    truncated = len(raw_bytes) > max_bytes
    analysis = _analyze_dmesg_text_light(raw)
    excerpt = "\n".join(raw.splitlines()[-40:])

    result = {
        "crash_dir": latest,
        "timestamp_utc": ts_utc_iso,
        "timestamp_ist": ts_ist_iso,
        "dmesg_path": dmesg_path,
        "retrieved_bytes": len(raw),
        "truncated": truncated,
        "analysis": analysis,
        "raw_excerpt": excerpt,
    }
    result.update(analysis)
    return result


@mcp.tool()
def build_kernel_from_source(
    connection_id: str,
    repo_path: str = "~/repos/net-next",
    sudo_password: str | None = None,
    install_deps: bool = True,
    jobs: int = 0,                # 0 => use all cores (nproc)
    timeout_seconds: int = 7200,  # long default; kernel builds can take time
) -> dict:
    """Build and install the kernel from the repo root (no reboot). If
    the build fails or code fixes are needed, do NOT edit files on the
    VM; instead: use git_reset_last_commit, edit the LOCAL patch
    (local_patch_edit), re-upload it with sftp_patch_file, re-apply
    with git_apply_patch_file, then run this tool again.

    Sequence:
      1. cp /boot/config-$(uname -r) .config
      2. make olddefconfig
      3. yes "" | make localmodconfig
      4. scripts/config --disable SYSTEM_TRUSTED_KEYS
      5. scripts/config --disable SYSTEM_REVOCATION_KEYS
      6. scripts/config --disable MODULE_SIG
      7. scripts/config --disable MODULE_SIG_ALL
      8. scripts/config --disable MODULE_SIG_SHA512
      9. scripts/config --undefine MODULE_SIG_KEY
     10. make olddefconfig
     11. sudo make -j$(nproc)   (or -j<jobs> if jobs>0)
     12. sudo make headers_install
     13. sudo make -j$(nproc) modules_install
     14. sudo make -j$(nproc) install
     15. sudo update-grub (fallback to update-grub2)

    Notes:
      - Parameter install_deps is currently ignored (no package install).
      - If /boot/config-$(uname -r) is missing the script aborts.
      - No reboot is performed; use reboot_vm separately if needed.
    Returns:
      - exit_code, stdout, stderr, log_path, kernelrelease
    """
    client = _connections.get(connection_id)
    if client is None:
        return {"error": "Unknown connection_id", "type": "NotFound"}

    jobs_flag = f"-j{jobs}" if jobs and jobs > 0 else "-j$(nproc)"
    pw = sudo_password or ""
    script = f"""
    set -euo pipefail
    LOG=/tmp/simple_kernel_build_$(date +%s).log
    exec > >(tee -a "$LOG") 2>&1

    echo "[info] repo: {repo_path}"
    cd {repo_path}
    git rev-parse --is-inside-work-tree >/dev/null

    echo "[step] copy base config"
    cp /boot/config-$(uname -r) .config
    echo "[step] olddefconfig"
    make olddefconfig
    echo "[step] localmodconfig"
    yes "" | make localmodconfig || true

    if [ -x scripts/config ]; then
      echo "[step] disabling keys & module signing"
      scripts/config --disable SYSTEM_TRUSTED_KEYS || true
      scripts/config --disable SYSTEM_REVOCATION_KEYS || true
      scripts/config --disable MODULE_SIG || true
      scripts/config --disable MODULE_SIG_ALL || true
      scripts/config --disable MODULE_SIG_SHA512 || true
      scripts/config --undefine MODULE_SIG_KEY || true
    fi

    echo "[step] second olddefconfig"
    make olddefconfig

    SUDO_PW={shlex.quote(pw)}
    run_sudo() {{
        if [ -n "$SUDO_PW" ]; then
            echo "$SUDO_PW" | sudo -S bash -lc "$1"
        else
            sudo bash -lc "$1"
        fi
    }}

    echo "[build] kernel {jobs_flag}"
    run_sudo "make {jobs_flag}"
    echo "[install] headers"
    run_sudo "make headers_install"
    echo "[install] modules {jobs_flag}"
    run_sudo "make {jobs_flag} modules_install"
    echo "[install] kernel {jobs_flag}"
    run_sudo "make {jobs_flag} install"
    echo "[grub] update"
    run_sudo "\
        (command -v update-grub && update-grub) || \
        (command -v update-grub2 && update-grub2) || true"

    KREL=$(make kernelrelease 2>/dev/null || uname -r || true)
    echo "[done] kernelrelease=$KREL"
    echo "$LOG"
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
        log_path = None
        for line in reversed(out.strip().splitlines()):
            if line.startswith("/tmp/simple_kernel_build_"):
                log_path = line.strip()
                break
        # extract kernelrelease from output if present
        kernelrelease = None
        for line in reversed(out.strip().splitlines()):
            if line.startswith("[done] kernelrelease="):
                kernelrelease = line.split("=", 1)[1]
                break
        return {
            "exit_code": code,
            "duration_ms": duration_ms,
            "stdout": out,
            "stderr": err,
            "repo_path": repo_path,
            "log_path": log_path,
            "kernelrelease": kernelrelease,
        }
    except Exception as e:
        return {"error": str(e), "type": e.__class__.__name__}

# @mcp.tool()
# def kdump_configure_crashkernel_grub(
#     connection_id: str,
#     size: str = "512M",
#     sudo_password: Optional[str] = None,
#     timeout_seconds: int = 180,
# ) -> dict:
#     """Configure crashkernel in GRUB (pre-reboot). If crashkernel is
#     missing in /proc/cmdline, append crashkernel=<size> to
#     GRUB_CMDLINE_LINUX_DEFAULT and run update-grub. After this tool,
#     call reboot_vm and then kdump_install_enable. Accepts optional
#     sudo_password."""
#     client = _connections.get(connection_id)
#     if client is None:
#         return {"error": "Unknown connection_id", "type": "NotFound"}

#     pw = sudo_password or ""
#     script = f"""
#     set -euo pipefail
#     SIZE={shlex.quote(size)}
#     SUDO_PW={shlex.quote(pw)}
#     run_sudo() {{
#         if [ -n "$SUDO_PW" ]; then
#             echo "$SUDO_PW" | sudo -S bash -lc "$1";
#         else
#             sudo bash -lc "$1";
#         fi
#     }}

#     CMDLINE=$(run_sudo "cat /proc/cmdline || true")
#     echo "CMDLINE:$CMDLINE"
#     if echo "$CMDLINE" | grep -q 'crashkernel='; then
#     echo "HAS_CRASHKERNEL=1"
#     exit 0
#     fi
#     echo "HAS_CRASHKERNEL=0"

#     # Ensure the GRUB default line contains crashkernel=<SIZE>
#     if grep -q '^GRUB_CMDLINE_LINUX_DEFAULT=' /etc/default/grub; then
#     run_sudo "sed -i -E \\\\\
#         \\"s/^(GRUB_CMDLINE_LINUX_DEFAULT=\\\\\\\\\
#             \\\\\\\"[^\\\\\\\"]*)\\\\\\\"/ \\\\\
#         \\\\\\\\1 crashkernel=$SIZE\\\\\\\"/\\" \\\\\
#         /etc/default/grub"
#     else
#     run_sudo "printf \\
#         '\\nGRUB_CMDLINE_LINUX_DEFAULT= \\
#         \\\"quiet splash crashkernel=$SIZE\\\"\\n' \\
#         >> /etc/default/grub"
#     fi

#     # Show the new line
#     NEW_LINE=$(grep '^GRUB_CMDLINE_LINUX_DEFAULT=' /etc/default/grub || true)
#     echo "GRUB_LINE:$NEW_LINE"

#     # Update GRUB
#     run_sudo "(command -v update-grub >/dev/null && \\
#         update-grub) || \\
#         (command -v update-grub2 >/dev/null && update-grub2)"
#     echo "REBOOT_REQUIRED=1"
#     """
#     try:
#         cmd = f"bash -lc {shlex.quote(script)}"
#         start = time.time()
#         stdin, stdout, stderr = client.exec_command(
#             cmd, timeout=timeout_seconds
#         )
#         out = stdout.read().decode("utf-8", "replace")
#         err = stderr.read().decode("utf-8", "replace")
#         code = stdout.channel.recv_exit_status()
#         has_ck = "HAS_CRASHKERNEL=1" in out
#         reboot_req = "REBOOT_REQUIRED=1" in out
#         grub_line = None
#         for line in out.splitlines():
#             if line.startswith("GRUB_LINE:"):
#                 grub_line = line.split("GRUB_LINE:", 1)[1].strip()
#                 break
#         return {
#             "exit_code": code,
#             "stdout": out,
#             "stderr": err,
#             "crashkernel_present": has_ck,
#             "reboot_required": (not has_ck) and reboot_req,
#             "grub_line": grub_line,
#             "size": size,
#         }
#     except Exception as e:
#         return {"error": str(e), "type": e.__class__.__name__}


# @mcp.tool()
# def kdump_install_enable(
#     connection_id: str,
#     coredir: str = "/var/crash",
#     sudo_password: Optional[str] = None,
#     timeout_seconds: int = 420,
# ) -> dict:
#     """Install and enable kdump after reboot. Installs linux-crashdump,
#     kdump-tools, makedumpfile, crash; sets USE_KDUMP=1 and
#     KDUMP_COREDIR; enables/starts kdump-tools; runs kdump-config
#     load/show. After this tool, call kdump_verify. Accepts optional
#     sudo_password."""
#     client = _connections.get(connection_id)
#     if client is None:
#         return {"error": "Unknown connection_id", "type": "NotFound"}

#     pw = sudo_password or ""
#     script = f"""
#     set -euo pipefail
#     SUDO_PW={shlex.quote(pw)}
#     COREDIR={shlex.quote(coredir)}
#     run_sudo() {{
#         if [ -n "$SUDO_PW" ]; then
#             echo "$SUDO_PW" | sudo -S bash -lc "$1";
#         else
#             sudo bash -lc "$1";
#         fi
#     }}

#     echo "[info] installing kdump packages"
#     run_sudo "apt-get update"
#     run_sudo "DEBIAN_FRONTEND=noninteractive \\
#         apt-get install -y linux-crashdump kdump-tools \\
#         makedumpfile crash || \\
#         apt-get install -y kdump-tools makedumpfile crash"

#     echo "[info] configuring /etc/default/kdump-tools"
#     run_sudo "bash -lc 'if grep -q ^USE_KDUMP= \\
#         /etc/default/kdump-tools; then \\
#         sed -i -E \\"s/^USE_KDUMP=.*/USE_KDUMP=1/\\" \\
#         /etc/default/kdump-tools; else \\
#         echo USE_KDUMP=1 >> /etc/default/kdump-tools; fi'"
#     run_sudo "bash -lc 'if grep -q ^KDUMP_COREDIR= \\
#         /etc/default/kdump-tools; then \\
#         sed -i -E \\\\\
#             \\"s#^KDUMP_COREDIR=.*#KDUMP_COREDIR=\\\\\\\\\
#             \\\\\\\"$COREDIR\\\\\\\"#\\" \\
#         /etc/default/kdump-tools; else \\
#         echo KDUMP_COREDIR=\\\\\\\"$COREDIR\\\\\\\" \\
#         >> /etc/default/kdump-tools; fi'"

#     echo "[info] enabling and starting kdump-tools"
#     run_sudo "systemctl enable kdump-tools || true"
#     run_sudo "systemctl start kdump-tools || true"

#     echo "[info] kdump-config load/show"
#     run_sudo "kdump-config load || true"
#     run_sudo "kdump-config show || true"

#     echo "[info] service status"
#     ACTIVE=$(run_sudo "systemctl is-active kdump-tools || true")
#     echo "KDUMP_TOOLS_ACTIVE:$ACTIVE"
#     """
#     try:
#         cmd = f"bash -lc {shlex.quote(script)}"
#         start = time.time()
#         stdin, stdout, stderr = client.exec_command(
#             cmd, timeout=timeout_seconds
#         )
#         out = stdout.read().decode("utf-8", "replace")
#         err = stderr.read().decode("utf-8", "replace")
#         code = stdout.channel.recv_exit_status()
#         active = None
#         for line in out.splitlines():
#             if line.startswith("KDUMP_TOOLS_ACTIVE:"):
#                 active = line.split(":", 1)[1].strip()
#                 break
#         return {
#             "exit_code": code,
#             "stdout": out,
#             "stderr": err,
#             "kdump_tools_active": active,
#             "coredir": coredir,
#         }
#     except Exception as e:
#         return {"error": str(e), "type": e.__class__.__name__}

# @mcp.tool()
# def kdump_verify(
#     connection_id: str,
#     sudo_password: Optional[str] = None,
#     timeout_seconds: int = 60,
# ) -> dict:
#     """Verify kdump. Confirms crashkernel in /proc/cmdline (via sudo),
#     shows *sudo* dmesg lines for crashkernel reservation, and returns
#     kdump-tools service state (via sudo). Accepts optional
#     sudo_password."""
#     client = _connections.get(connection_id)
#     if client is None:
#         return {"error": "Unknown connection_id", "type": "NotFound"}

#     pw = sudo_password or ""
#     script = f"""
#     set -euo pipefail
#     SUDO_PW={shlex.quote(pw)}
#     run_sudo() {{
#         if [ -n "$SUDO_PW" ]; then
#             echo "$SUDO_PW" | sudo -S bash -lc "$1";
#         else
#             sudo bash -lc "$1";
#         fi
#     }}

#     CMDLINE=$(run_sudo "cat /proc/cmdline || true")
#     echo "CMDLINE:$CMDLINE"
#     if echo "$CMDLINE" | grep -q 'crashkernel='; then
#     echo "HAS_CRASHKERNEL=1"
#     else
#     echo "HAS_CRASHKERNEL=0"
#     fi

#     echo "--- dmesg crash lines (via sudo) ---"
#     run_sudo "dmesg | grep -i crash || true"

#     STATE=$(run_sudo "systemctl is-active kdump-tools || true")
#     echo "KDUMP_TOOLS_ACTIVE:$STATE"
#     """
#     try:
#         cmd = f"bash -lc {shlex.quote(script)}"
#         start = time.time()
#         stdin, stdout, stderr = client.exec_command(
#             cmd, timeout=timeout_seconds
#         )
#         out = stdout.read().decode("utf-8", "replace")
#         err = stderr.read().decode("utf-8", "replace")
#         code = stdout.channel.recv_exit_status()
#         has_ck = "HAS_CRASHKERNEL=1" in out
#         active = None
#         for line in out.splitlines():
#             if line.startswith("KDUMP_TOOLS_ACTIVE:"):
#                 active = line.split(":", 1)[1].strip()
#                 break
#         return {
#             "exit_code": code,
#             "stdout": out,
#             "stderr": err,
#             "crashkernel_present": has_ck,
#             "kdump_tools_active": active,
#         }
#     except Exception as e:
#         return {"error": str(e), "type": e.__class__.__name__}


@mcp.tool()
def ssh_exec(
    connection_id: str,
    command: str,
    timeout_seconds: int = 30,
    output_encoding: Literal["utf-8", "latin-1"] = "utf-8",
) -> dict:
    """
    Execute any shell command over an existing SSH connection.

    Use this tool for generic shell commands that do not have a
    dedicated MCP tool.
    For example, do NOT use this for applying patches to the Linux
    kernel source trees—use git_apply_patch_file instead and cloning
    Linux kernel source trees—use clone_linux_subsystem_tree instead,
    editing source files.
    """
    # # --- Guardrail: block writey/edit/patch/build commands ---
    # lower = command.lower()

    # block_patterns = [
    #     r'\bgit\s+(am|apply|commit|reset|rebase|cherry-pick|'
    #     r'merge|checkout\s+-b|\bpush\b)\b',
    #     r'\bmake(\s|$)', r'\bupdate-grub2?\b',
    #     r'\bheaders_install\b', r'\bmodules_install\b',
    #     r'\bscripts/config\b', r'\bdepmod\b', r'\bmodprobe\b',
    #     r'\bapt(-get)?\s+(install|remove|purge|upgrade|'
    #     r'dist-upgrade)\b', r'\bdpkg\s+-i\b',
    #     r'\byum\s+(install|remove|update)\b',
    #     r'\bdnf\s+(install|remove|upgrade)\b',
    #     r'\bzypper\s+(install|remove|update)\b',
    #     r'\bsed\s+-i\b', r'\bperl\s+-pi\b',
    #     r'\bpython\s+-c\b.*open\(.*,[\'"]w', r'\btee\b',
    #     r'(^|[;&|])\s*echo\s+.*\s*>\s*',
    #     r'(^|[;&|])\s*echo\s+.*\s*>>\s*',   # redirections
    #     r'\btruncate\b', r'\bdd\s+if=', r'\brm\s+-rf?\b',
    #     r'\bchmod\b', r'\bchown\b', r'\bmv\b',
    #     r'\bcp\b.*\s[^-]\s',
    #     r'\bsysctl\s+-w\b',
    #     r'\breboot\b', r'\bshutdown\b', r'\bpoweroff\b',
    #     r'\bvi\b', r'\bnano\b', r'\bed\b', r'\bex\b',
    # ]
    # if any(re.search(p, lower) for p in block_patterns):
    #     return {
    #         "error": (
    #             "This command looks like a code-edit/apply/build "
    #             "operation. Use the dedicated tools instead: "
    #             "sftp_patch_file → git_apply_patch_file → "
    #             "build_kernel_from_source or reapply_patch_cycle."
    #         ),
    #         "type": "ToolMisuse"
    #     }
    # -----------------------------------------------------------
    client = _connections.get(connection_id)
    if client is None:
        return {"error": "Unknown connection_id", "type": "NotFound"}
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


def _test_kernel_compile(
    client, repo_path: str, sudo_password: str = ""
) -> bool:
    """Internal helper to test kernel compilation at current commit"""
    pw = sudo_password
    script = f"""
    set -euo pipefail
    cd {repo_path}

    make olddefconfig

    # Run compilation
    SUDO_PW={shlex.quote(pw)}
    if [ -n "$SUDO_PW" ]; then
        echo "$SUDO_PW" | sudo -S make -j$(nproc)
    else
        sudo make -j$(nproc)
    fi
    """

    try:
        stdin, stdout, stderr = client.exec_command(
            f"bash -c {shlex.quote(script)}", timeout=1800
        )
        out = stdout.read().decode('utf-8', errors='replace')
        err = stderr.read().decode('utf-8', errors='replace')
        exit_code = stdout.channel.recv_exit_status()

        # Compilation succeeded if exit code is 0 and no critical errors
        return exit_code == 0 and not any(x in (out + err).lower() for x in [
            "error:", "failed", "fatal error", "compilation terminated",
            "make: *** [", "no rule to make target"
        ])
    except Exception:
        return False


@mcp.tool()
def find_compile_regression(
    connection_id: str,
    good_commit: str = "v6.8",
    bad_commit: str = "HEAD",
    repo_path: str = "~/repos/net-next",
    sudo_password: str = ""
) -> dict:
    """
    Automated git bisect to find compilation regression in Linux kernel.
    Uses binary search with robust compilation testing to find the
    exact commit that broke the build.
    """
    client = _connections.get(connection_id)
    if not client:
        return {"error": "SSH connection not found"}

    def run_cmd(cmd):
        try:
            stdin, stdout, stderr = client.exec_command(
                f"cd {repo_path} && {cmd}", timeout=60
            )
            out = stdout.read().decode('utf-8', errors='replace')
            err = stderr.read().decode('utf-8', errors='replace')
            return out + err
        except Exception as e:
            return f"Error: {e}"

    steps: list[dict] = []
    culprit = None

    try:
        # Start git bisect
        run_cmd("git bisect reset")
        run_cmd("git bisect start")
        run_cmd(f"git bisect bad {bad_commit}")
        run_cmd(f"git bisect good {good_commit}")

        # Bisect loop
        while len(steps) < 20:  # Safety limit
            # Get current commit info
            current = run_cmd("git rev-parse HEAD").strip()
            if not current or len(current) < 8:
                break

            msg = run_cmd(f"git log -1 --format='%s' {current}").strip()

            # Test compilation using robust method
            compile_ok = _test_kernel_compile(client, repo_path, sudo_password)

            steps.append({
                "commit": current[:8],
                "message": msg[:50] + "..." if len(msg) > 50 else msg,
                "result": "PASS" if compile_ok else "FAIL"
            })

            # Continue bisect
            bisect_cmd = "git bisect good" if compile_ok else "git bisect bad"
            bisect_result = run_cmd(bisect_cmd)

            # Check if bisect is complete
            if "is the first bad commit" in bisect_result:
                culprit = current
                break
            elif ("There are only" in bisect_result and
                  "revisions left" in bisect_result):
                # Close to completion, continue
                continue
            elif not any(
                word in bisect_result.lower()
                for word in ["bisecting:", "checkout"]
            ):
                # Bisect appears to be done or stuck
                break

        # Clean up
        run_cmd("git bisect reset")

        return {
            "success": True,
            "culprit_commit": culprit[:8] if culprit else "Not found",
            "culprit_full": culprit if culprit else None,
            "steps_taken": len(steps),
            "bisect_log": steps,
            "summary": (
                f"Found regression in commit "
                f"{culprit[:8] if culprit else 'unknown'} "
                f"after {len(steps)} compilation tests"
            ),
            "repo_path": repo_path,
            "commit_range": f"{good_commit}..{bad_commit}"
        }

    except Exception as e:
        run_cmd("git bisect reset")  # Cleanup on error
        return {"error": str(e), "success": False}


if __name__ == "__main__":
    mcp.run()


# @mcp.tool()
# def analyze_dmesg(
#     connection_id: str,
#     sudo_password: Optional[str] = None,
#     max_bytes: int = 500_000,
#     timeout_seconds: int = 30,
# ) -> dict:
#     """Analyze a previously captured crash dmesg file at
#     /var/crash/dmesg_file.txt.

#     Usage intent: Call this when a user reports a crash; the
#     environment (outside this tool) is expected to have already copied
#     the relevant kernel log excerpt into the fixed path
#     /var/crash/dmesg_file.txt (e.g. from kdump initramfs, pstore,
#     or a post-boot collection script). This tool does NOT call
#     `dmesg`; it only reads that file (with sudo if required) and
#     performs heuristic root cause analysis:

#       - Detect latest panic / oops / BUG signature
#       - Extract fault address (CR2) and faulting instruction pointer
#         (RIP)
#       - Parse call trace lines
#       - Infer likely fault class (null_deref, panic, oops)
#       - Provide remediation recommendations

#     Returns structured fields: event_type, short_summary,
#     suspected_function, fault_address, faulting_ip, call_trace,
#     modules, recommended_actions, raw_excerpt, plus metadata.
#     Analyse this raw dmesg text as well and return a short and crisp
#     summary of the likely root cause.
#     """
#     client = _connections.get(connection_id)
#     if client is None:
#         return {"error": "Unknown connection_id", "type": "NotFound"}
#     crash_path = "/var/crash/dmesg_file.txt"
#     # Use sudo to read the file if a password is supplied;
#     # otherwise attempt direct read.
#     if sudo_password:
#         read_cmd = (
#             f"echo {shlex.quote(sudo_password)} | sudo -S "
#             f"bash -lc 'cat {shlex.quote(crash_path)}'"
#         )
#     else:
#         read_cmd = f"cat {shlex.quote(crash_path)}"
#     try:

#         start = time.time()
#         stdin, stdout, stderr = client.exec_command(
#             read_cmd, timeout=timeout_seconds
#         )
#         raw = stdout.read()[:max_bytes].decode("utf-8", errors="replace")
#         err = stderr.read().decode("utf-8", errors="replace")
#         code = stdout.channel.recv_exit_status()
#         if code != 0:
#             return {
#                 "error": f"Failed to read crash dmesg file (exit {code})",
#                 "stderr": err,
#                 "type": "ReadError",
#                 "path": crash_path,
#                 "exit_code": code,
#             }
#     except Exception as e:
#         return {"error": str(e), "type": e.__class__.__name__}

#     analysis = _analyze_dmesg_text(raw)
#     analysis.update({
#         "raw_text": raw,
#         "exit_code": code,
#         "stderr": err,
#         "retrieved_bytes": len(raw),
#         "truncated": len(raw) >= max_bytes,
#         "source_path": crash_path,
#         "command": read_cmd,
#     })
#     return analysis


# @mcp.tool()
# def analyze_dmesg_text(dmesg_text: str, max_bytes: int = 500_000) -> dict:
#     """Analyze provided dmesg text (already collected) and return
#     structured RCA.

#     Use this when the raw log is supplied instead of needing SSH
#     access.
#     """
#     if not dmesg_text:
#         return {"error": "Empty dmesg_text", "type": "ValueError"}
#     text = dmesg_text[:max_bytes]
#     analysis = _analyze_dmesg_text(text)
#     analysis.update({
#         "retrieved_bytes": len(text),
#         "truncated": len(dmesg_text) > len(text),
#     })
#     return analysis


# def _analyze_dmesg_text(raw: str) -> dict:
#     lines = raw.splitlines()
#     event_type = None
#     fault_addr = None
#     rip_line = None
#     fault_ip = None
#     call_trace_block = []
#     modules_line = None
#     registers_block = []
#     capture_trace = False
#     capture_registers = False

#     # Regex patterns
#     re_bug = re.compile(
#         r"BUG: (kernel )?NULL pointer dereference, "
#         r"address: (0x?[0-9a-fA-F]+)"
#     )
#     re_oops = re.compile(r"Oops: .*", re.IGNORECASE)
#     re_panic = re.compile(
#         r"kernel panic - not syncing|Kernel panic", re.IGNORECASE
#     )
#     re_rip = re.compile(
#         r"RIP: *[0-9a-fA-Fx]+:([^ +]+)\+0x[0-9a-fA-F]+/"
#         r"[0-9a-fA-F]+"
#     )
#     re_cr2 = re.compile(r"CR2: *(0x?[0-9a-fA-F]+)")
#     re_mods = re.compile(r"^Modules linked in: (.*)")
#     re_reg_line = re.compile(r"^(RIP|RAX|RDX|RSP|RBP|CR2|EFLAGS|R..:)")

#     # Walk through to find last significant event
#     for i, line in enumerate(lines):
#         bug_m = re_bug.search(line)
#         if bug_m:
#             event_type = "null_deref"
#             fault_addr = bug_m.group(2)
#         elif re_panic.search(line):
#             event_type = "panic"
#         elif re_oops.search(line):
#             # Only set if nothing more specific yet
#             if event_type not in ("panic", "null_deref"):
#                 event_type = "oops"

#         if (line.startswith("Call Trace:") or
#             line.strip() == "Call Trace:" or
#             line.strip() == "<TASK>"):
#             call_trace_block = []
#             capture_trace = True
#             continue
#         if capture_trace:
#             if not line.strip():
#                 capture_trace = False
#             elif line.strip().startswith("</TASK>"):
#                 capture_trace = False
#             else:
#                 call_trace_block.append(line.strip())

#         if line.startswith("RIP:"):
#             rip_line = line
#             m = re_rip.search(line + '"')  # ensure closing quote for pattern
#             if m:
#                 fault_ip = m.group(1)
#         if "CR2:" in line:
#             m = re_cr2.search(line)
#             if m:
#                 fault_addr = fault_addr or m.group(1)
#         if re_mods.match(line):
#             modules_line = line

#         if line.startswith("RAX:"):
#             # Start capturing registers until blank line
#             capture_registers = True
#             registers_block = [line.strip()]
#             continue
#         if capture_registers:
#             if not line.strip():
#                 capture_registers = False
#             else:
#                 registers_block.append(line.strip())

#     # Derive suspected function: first meaningful entry in call trace
#     # referencing a module or driver
#     suspected_function = None
#     for entry in call_trace_block:
#         # Typical entries look like:
#         # 'mana_get_rxfrag+0x284/0x370 [mana]' or
#         # 'dma_map_page_attrs+0x22/0x3c0'
#         fn = entry.split()[0] if entry else None
#         if fn and not fn.startswith("?"):
#             suspected_function = fn.split('+')[0]
#             break

#     # Determine summary
#     summary_parts = []
#     if event_type == "null_deref":
#         summary_parts.append("NULL pointer dereference")
#     elif event_type == "panic":
#         summary_parts.append("Kernel panic")
#     elif event_type == "oops":
#         summary_parts.append("Kernel oops")
#     else:
#         summary_parts.append("No critical (panic/oops) signature detected")
#     if suspected_function:
#         summary_parts.append(f"in {suspected_function}")
#     if fault_addr:
#         summary_parts.append(f"at address {fault_addr}")
#     short_summary = (
#         ': '.join([summary_parts[0], ' '.join(summary_parts[1:])])
#         if len(summary_parts) > 1
#         else summary_parts[0]
#     )

#     # Recommended actions heuristics
#     recs = []
#     if event_type == "null_deref":
#         recs.extend([
#             "Validate object pointer before use "
#             "(add WARN_ON_ONCE/guard).",
#             "Check allocation / initialization path for race or "
#             "failure handling.",
#             "Instrument with pr_debug to confirm pointer lifetime.",
#         ])
#     if event_type == "panic":
#         recs.append(
#             "Review preceding warnings or oops lines for first "
#             "failure cause."
#         )
#     if event_type in ("null_deref", "oops", "panic") and suspected_function:
#         recs.append(f"Audit recent changes around {suspected_function}.")
#     if not recs:
#         recs.append(
#             "No severe fault found; consider running with higher "
#             "log levels or repro steps."
#         )

#     modules = []
#     if modules_line:
#         modules = modules_line.split(':', 1)[1].strip().split()

#     # Raw excerpt: last ~40 lines for context
#     excerpt = '\n'.join(lines[-40:])

#     return {
#         "event_type": event_type,
#         "short_summary": short_summary,
#         "fault_address": fault_addr,
#         "faulting_ip": fault_ip,
#         "suspected_function": suspected_function,
#         "call_trace": call_trace_block[:40],
#         "registers": registers_block,
#         "modules": modules,
#         "recommended_actions": recs,
#         "raw_excerpt": excerpt,
#     }
