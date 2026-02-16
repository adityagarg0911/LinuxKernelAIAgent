"""MCP SSH Server - Refactored main entry point."""
from typing import Optional, Literal
from mcp.server.fastmcp import FastMCP  # type: ignore[import-not-found]

import connection_manager
import kernel_tools
import crash_analysis
import git_operations
import diagnostics

mcp = FastMCP("SSH")


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
    return connection_manager.ssh_connect_impl(
        host, username, port, password, private_key,
        passphrase, timeout_seconds, accept_unknown_host
    )


@mcp.tool()
def ssh_close(connection_id: str) -> dict:
    """Close a previously established SSH connection."""
    return connection_manager.ssh_close_impl(connection_id)


@mcp.tool()
def ssh_list() -> dict:
    """List active SSH connection IDs."""
    return connection_manager.ssh_list_impl()


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
    kernel source trees—use git_apply_patch_file instead and
    cloning Linux kernel source trees—use clone_linux_subsystem_tree
    instead, editing source files.
    """
    client = connection_manager.get_connection(connection_id)
    if client is None:
        return {"error": "Unknown connection_id", "type": "NotFound"}
    return diagnostics.ssh_exec_impl(
        client, command, timeout_seconds, output_encoding
    )


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
    client = connection_manager.get_connection(connection_id)
    if client is None:
        return {"error": "Unknown connection_id", "type": "NotFound"}
    return diagnostics.check_connection_impl(client, timeout_seconds)


@mcp.tool()
def kernel_version(
    connection_id: str,
    timeout_seconds: int = 5,
) -> dict:
    """Retrieve the remote kernel version using `uname -rs`.

    TRIGGER KEYWORDS: kernel version | uname -r | uname -rs | check kernel
    Returns both the raw output and parsed fields.
    """
    client = connection_manager.get_connection(connection_id)
    if client is None:
        return {"error": "Unknown connection_id", "type": "NotFound"}
    return diagnostics.kernel_version_impl(client, timeout_seconds)


@mcp.tool()
def install_developer_tools(
    connection_id: str,
    sudo_password: Optional[str] = None,
    timeout_seconds: int = 120,
) -> dict:
    """Install basic developer tools on the remote VM using
    sudo apt-get install. Optionally provide sudo_password."""
    client = connection_manager.get_connection(connection_id)
    if client is None:
        return {"error": "Unknown connection_id", "type": "NotFound"}
    return kernel_tools.install_developer_tools_impl(
        client, sudo_password, timeout_seconds
    )


@mcp.tool()
def sftp_patch_file(
    connection_id: str,
    local_path: str,
    remote_path: Optional[str] = None,
) -> dict:
    """
    Upload a local .patch file (from the machine running this MCP server)
    to the remote VM via SFTP.

    - If remote_path is omitted, it defaults to:
      ~/repos/net-next/debugAgent.patch
    - If remote_path ends with '/', the file will be uploaded with the
      same basename into that directory.
    """
    client = connection_manager.get_connection(connection_id)
    if client is None:
        return {"error": "Unknown connection_id", "type": "NotFound"}
    return git_operations.sftp_patch_file_impl(client, local_path, remote_path)


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
        - else => git apply patch && git commit -a -m
          "Apply patch: <filename>"

    Use this instead of generic ssh_exec when user asks to apply a patch.
    Parameters: connection_id, repo_path?, patch_path?
    Returns: exit_code, stdout, stderr, repo_path, patch_path.
    """
    client = connection_manager.get_connection(connection_id)
    if client is None:
        return {"error": "Unknown connection_id", "type": "NotFound"}
    return git_operations.git_apply_patch_file_impl(
        client, repo_path, patch_path, timeout_seconds
    )


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

    Use this tool when the user asks to clone a Linux kernel source tree
    (e.g., net-next or any other kernel repo).
    By default, this tool clones the net-next tree (mainline networking
    development) into ~/repos/net-next.
    If the user provides a specific git_url, that repository will be
    cloned instead, into ~/repos/{repo-name} unless a custom
    destination_path is given.

    When to invoke:
    - Use this tool for requests like "clone net-next", "clone kernel
      source", "clone linux tree", etc.
    - If no git_url is specified, the net-next tree will be cloned by
      default.
    - If you want a different tree, provide the git_url explicitly.
    """
    client = connection_manager.get_connection(connection_id)
    if client is None:
        return {"error": "Unknown connection_id", "type": "NotFound"}
    return git_operations.clone_linux_source_tree_impl(
        client, git_url, destination_path, branch, timeout_seconds
    )


@mcp.tool()
def build_kernel_from_source(
    connection_id: str,
    repo_path: str = "~/repos/net-next",
    sudo_password: Optional[str] = None,
    install_deps: bool = True,
    jobs: int = 0,
    timeout_seconds: int = 7200,
) -> dict:
    """Build and install the kernel from the repo root (no reboot).
    If the build fails or code fixes are needed, do NOT edit files
    on the VM; instead: use git_reset_last_commit, edit the LOCAL patch
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
    client = connection_manager.get_connection(connection_id)
    if client is None:
        return {"error": "Unknown connection_id", "type": "NotFound"}
    return kernel_tools.build_kernel_from_source_impl(
        client, repo_path, sudo_password, install_deps,
        jobs, timeout_seconds
    )


@mcp.tool()
def find_compile_regression(
    connection_id: str,
    repo_path: str = "~/repos/net-next",
    good_commit: str = "v6.8",
    bad_commit: str = "HEAD",
    sudo_password: str = "",
) -> dict:
    """
    Automated git bisect to find compilation regression in Linux kernel.
    Uses binary search with robust compilation testing to find the exact
    commit that broke the build.
    """
    client = connection_manager.get_connection(connection_id)
    if client is None:
        return {"error": "Unknown connection_id", "type": "NotFound"}
    return kernel_tools.find_compile_regression_impl(
        client, good_commit, bad_commit, repo_path, sudo_password
    )


@mcp.tool()
def analyze_dmesg_tail(
    connection_id: str,
    lines: int = 100,
    sudo_password: Optional[str] = None,
    timeout_seconds: int = 8,
) -> dict:
    """Fetch and heuristically analyze the tail of dmesg for recent
    problems.

    Parameters:
      lines (int): How many lines from the end of dmesg to inspect
        (default 100).
      sudo_password (optional): If provided, will attempt `sudo dmesg`
        if plain dmesg fails.

    Heuristics:
      Scans tail for common critical markers (case-insensitive where
      relevant):
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

    LLM finally gives a crisp and short analysis of the crash, steps to
    mitigate, update in patch if possible or needed.
    """
    client = connection_manager.get_connection(connection_id)
    if client is None:
        return {"error": "Unknown connection_id", "type": "NotFound"}
    return crash_analysis.analyze_dmesg_tail_impl(
        client, lines, sudo_password, timeout_seconds
    )


@mcp.tool()
def analyze_latest_crash_dmesg(
    connection_id: str,
    crash_root: str = "/var/crash",
    sudo_password: Optional[str] = None,
    max_bytes: int = 500_000,
    timeout_seconds: int = 20,
) -> dict:
    """Locate the newest crash directory (/var/crash/YYYYMMDDHHMM) and
    analyze its dmesg.<timestamp> file.

    Directory naming convention assumed: 12-digit UTC timestamp
    YYYYMMDDHHMM.
    We:
      1. List candidate directories matching ^[0-9]{12}$ under crash_root.
      2. Pick the latest lexicographically (correct for this timestamp
         format).
      3. Read dmesg.<timestamp> (fallback: first file starting with
         dmesg.).
      4. Run lightweight heuristic analysis (_analyze_dmesg_text_light).
      5. Convert UTC timestamp to IST (+05:30) for convenience.

    Returns fields:
      - crash_dir, timestamp_utc, timestamp_ist
      - dmesg_path, retrieved_bytes, truncated (bool)
      - analysis (nested dict: event_type, short_summary, ...)
      - raw_excerpt (tail ~40 lines)
      - stdout/stderr/exit_code from retrieval (for debugging) if error

    LLM finally gives a crisp and short analysis of the crash, steps to
    mitigate, update in patch if possible or needed.
    """
    client = connection_manager.get_connection(connection_id)
    if client is None:
        return {"error": "Unknown connection_id", "type": "NotFound"}
    return crash_analysis.analyze_latest_crash_dmesg_impl(
        client, crash_root, sudo_password, max_bytes, timeout_seconds
    )


@mcp.tool()
def get_ethtool_stats(
    connection_id: str,
    interface: str | None = None,
    command: str | None = None,
    timeout_seconds: int = 20,
) -> dict:
    """Get Ethtool stats for MANA NIC
    Run ethtool statistics (default: `ethtool -S <iface>`) or a custom
    command and apply a quick panic heuristic.

    Updated behavior:
        - Primary intent is to fetch NIC statistics via `ethtool -S`
          (was previously using other ethtool subcommands).
        - If 'command' is supplied, it is executed verbatim (via bash -lc)
          instead of the stats command.
        - If no 'command' and an 'interface' is provided: run
          `ethtool -S <interface>`.
        - If neither 'command' nor 'interface' is given: default interface
          'enP30832s1' is used.

    Panic heuristic (unchanged, coarse):
        - SSH exec exceptions (SSHException/EOFError/OSError/socket.error)
          => panic=True
        - Exceptions while reading stdout/stderr or retrieving exit status
          => panic=True
        - Transport becomes inactive after command with no exit_code
          => panic=True

    Returns dict:
        {
            panic, panic_reason, exit_code, stdout, stderr, duration_ms,
            executed_command, interface, transport_active_after
        }
    If panic occurs, LLM should run command for check ssh connection,
    close ssh, ssh_connect, analyze_latest_crash_dmesg. It should not
    rerun this same command without user asking.
    """
    client = connection_manager.get_connection(connection_id)
    if client is None:
        return {"error": "Unknown connection_id", "type": "NotFound"}
    return diagnostics.get_ethtool_stats_impl(
        client, interface, command, timeout_seconds
    )


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
    - Spawns a background `nohup` shell that sleeps briefly, then runs
      reboot.
    - Returns immediately before the SSH session is terminated by the
      reboot.
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
    client = connection_manager.get_connection(connection_id)
    if client is None:
        return {"error": "Unknown connection_id", "type": "NotFound"}
    return diagnostics.reboot_vm_impl(
        client, sudo_password, force, delay_seconds
    )


if __name__ == "__main__":
    mcp.run()
