"""MCP SSH Server — Linux kernel development automation over SSH.

Exposes a set of MCP tools for:
- Managing SSH connections (connect, close, list, check, exec)
- Kernel development (clone, patch, build, install, reboot)
- Crash analysis (dmesg tail, crash-directory inspection)
- Diagnostics (kernel version, ethtool stats)
- Automated bisection (compile regression)

Each tool returns a plain dict.  Connection-aware tools look up
an existing ``connection_id``; if it is unknown they return a
``NotFound`` error — callers should reconnect.
"""

from __future__ import annotations

from typing import Literal, Optional

from mcp.server.fastmcp import FastMCP  # type: ignore[import-not-found]

from . import connection_manager
from . import kernel_tools
from . import crash_analysis
from . import git_operations
from . import diagnostics
from ._helpers import not_found_result

mcp = FastMCP("SSH")

# ── Shared helper used by nearly every tool ──────────────────────

def _client_or_error(connection_id: str):
    """Return ``(client, None)`` or ``(None, error_dict)``."""
    client = connection_manager.get_connection(connection_id)
    if client is None:
        return None, not_found_result(connection_id)
    return client, None


# ── Connection management ────────────────────────────────────────


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
    """Establish and cache a persistent SSH connection to a remote VM.

    WHEN TO USE: User says "connect to", "SSH into", "log in to", or
    provides a host/IP and credentials.
    WHEN NOT TO USE: A connection_id already exists and is alive — reuse
    it instead.  Call check_connection first if unsure.

    IMPORTANT:
      - Provide exactly ONE of password or private_key (not both, not neither).
      - After this returns, do NOT call any other tool unless the user
        explicitly asks.  Just report the connection_id.
      - The returned connection_id must be passed to every subsequent
        tool that requires one.

    Args:
      host: IP address or hostname of the remote VM.
      username: SSH username (e.g. "root", "azureuser").
      port: SSH port (default 22).
      password: Plaintext password (mutually exclusive with private_key).
      private_key: PEM-encoded private key string (mutually exclusive with password).
      passphrase: Passphrase for an encrypted private_key (optional).
      timeout_seconds: Connection timeout in seconds.
      accept_unknown_host: If True, auto-accept unknown host keys.

    Returns:
      connection_id, host, port, username, connect_ms on success.
      error, type on failure.
    """
    return connection_manager.ssh_connect_impl(
        host, username, port, password, private_key,
        passphrase, timeout_seconds, accept_unknown_host,
    )


@mcp.tool()
def ssh_close(connection_id: str) -> dict:
    """Close a previously established SSH connection and free resources.

    WHEN TO USE: User says "disconnect", "close connection", or you need
    to reconnect after a failed check_connection.
    Always close before re-connecting to the same host.

    Args:
      connection_id: The UUID returned by ssh_connect.

    Returns:
      closed: True on success.
    """
    return connection_manager.ssh_close_impl(connection_id)


@mcp.tool()
def ssh_list() -> dict:
    """List all active SSH connections with metadata (host, port, user, time).

    WHEN TO USE: User asks "which connections are open", "list sessions",
    or you need to find an existing connection_id to reuse.
    No parameters required.

    Returns:
      connections: list of {connection_id, host, port, username, connected_at}.
    """
    return connection_manager.ssh_list_impl()


@mcp.tool()
def ssh_exec(
    connection_id: str,
    command: str,
    timeout_seconds: int = 30,
    output_encoding: Literal["utf-8", "latin-1"] = "utf-8",
) -> dict:
    """Execute an arbitrary shell command on the remote VM over SSH.

    WHEN TO USE: For generic commands that do NOT have a dedicated tool
    (e.g. ls, cat, grep, systemctl, ip addr, etc.).
    WHEN NOT TO USE — prefer these specialised tools instead:
      - Applying patches     → git_apply_patch_file
      - Cloning kernel repos → clone_linux_source_tree
      - Building the kernel  → build_kernel_from_source
      - Checking kernel logs → analyze_dmesg_tail
      - NIC statistics       → get_ethtool_stats
      - Kernel version       → kernel_version

    Args:
      connection_id: Active connection UUID from ssh_connect.
      command: The exact shell command string to execute.
      timeout_seconds: Max seconds to wait for the command to finish.
      output_encoding: Decode stdout/stderr as "utf-8" (default) or "latin-1".

    Returns:
      stdout, stderr, exit_code, duration_ms.
    """
    client, err = _client_or_error(connection_id)
    if err:
        return err
    return diagnostics.ssh_exec_impl(
        client, command, timeout_seconds, output_encoding,
    )


@mcp.tool()
def check_connection(
    connection_id: str,
    timeout_seconds: int = 5,
) -> dict:
    """Check whether an SSH connection is still alive and responsive.

    WHEN TO USE: After any tool returns an error or timeout, or when
    the user asks "is the connection alive?", "check connection",
    "is the VM up?".
    RECOVERY: If alive=False, call ssh_close then ssh_connect to
    re-establish the session.

    Runs a minimal ``echo OK`` round-trip and measures latency.

    Args:
      connection_id: Active connection UUID from ssh_connect.
      timeout_seconds: Max seconds for the probe command.

    Returns:
      alive (bool), transport_active (bool), latency_ms (int|null),
      stdout, stderr, exit_code,
      reason (str|null — "exec-failed" | "transport-inactive" | "exec-exception").
    """
    client, err = _client_or_error(connection_id)
    if err:
        return err
    return diagnostics.check_connection_impl(client, timeout_seconds)


@mcp.tool()
def kernel_version(
    connection_id: str,
    timeout_seconds: int = 5,
) -> dict:
    """Retrieve the running kernel version on the remote VM.

    WHEN TO USE: User says "kernel version", "uname", "what kernel",
    "check kernel", or you need to verify which kernel booted after
    a build/reboot cycle.

    Runs ``uname -rs`` and parses the output.

    Args:
      connection_id: Active connection UUID.
      timeout_seconds: Max seconds to wait.

    Returns:
      stdout (raw output), exit_code, kernel_name (e.g. "Linux"),
      release (e.g. "6.8.0-rc1+").
    """
    client, err = _client_or_error(connection_id)
    if err:
        return err
    return diagnostics.kernel_version_impl(client, timeout_seconds)


@mcp.tool()
def install_developer_tools(
    connection_id: str,
    sudo_password: Optional[str] = None,
    timeout_seconds: int = 120,
) -> dict:
    """Install Linux kernel development packages on the remote VM.

    WHEN TO USE: User says "install dev tools", "install build deps",
    "setup build environment", or before a first kernel build.
    Installs: build-essential, libncurses-dev, bison, flex, libssl-dev,
    libelf-dev, libdw-dev, ssh, git, vim, net-tools, zstd, universal-ctags.

    Args:
      connection_id: Active connection UUID.
      sudo_password: Required if the remote user needs sudo with a password.
        Pass the same password used for ssh_connect if applicable.
      timeout_seconds: Max seconds for apt operations.

    Returns:
      stdout, stderr, exit_code, duration_ms, command.
    """
    client, err = _client_or_error(connection_id)
    if err:
        return err
    return kernel_tools.install_developer_tools_impl(
        client, sudo_password, timeout_seconds,
    )


@mcp.tool()
def sftp_patch_file(
    connection_id: str,
    local_path: str,
    remote_path: Optional[str] = None,
) -> dict:
    """Upload a local .patch file from the MCP server host to the remote VM via SFTP.

    WHEN TO USE: User says "upload patch", "transfer patch", "send patch
    to VM", or before calling git_apply_patch_file.
    WORKFLOW: sftp_patch_file → git_apply_patch_file → build_kernel_from_source.

    Args:
      connection_id: Active connection UUID.
      local_path: Absolute path to the .patch file on the local machine
        (the machine running this MCP server).
      remote_path: Destination path on the VM. Defaults to
        ~/repos/net-next/debugAgent.patch. If it ends with "/", the
        local filename is appended automatically.

    Returns:
      ok (bool), local_path, remote_path, bytes, duration_ms.
    """
    client, err = _client_or_error(connection_id)
    if err:
        return err
    return git_operations.sftp_patch_file_impl(
        client, local_path, remote_path,
    )


@mcp.tool()
def git_apply_patch_file(
    connection_id: str,
    repo_path: str = "~/repos/net-next",
    patch_path: str = "~/repos/net-next/debugAgent.patch",
    timeout_seconds: int = 600,
) -> dict:
    """Apply a .patch file to a Linux kernel git repo on the remote VM.

    WHEN TO USE: User says "apply patch", "apply diff", "git am",
    "git apply", or after uploading a patch with sftp_patch_file.
    WHEN NOT TO USE: Do NOT use ssh_exec for this — always use this tool.

    Auto-detects mailbox-format patches (lines starting with
    ``From <40hex>``) and uses ``git am -3``; otherwise uses
    ``git apply`` followed by an explicit ``git commit``.

    TYPICAL WORKFLOW:
      1. sftp_patch_file (upload the .patch)
      2. git_apply_patch_file (this tool — apply it)
      3. build_kernel_from_source (compile & install)

    Args:
      connection_id: Active connection UUID.
      repo_path: Path to the kernel repo on the VM (default: ~/repos/net-next).
      patch_path: Path to the .patch file on the VM
        (default: ~/repos/net-next/debugAgent.patch).
      timeout_seconds: Max seconds for the apply operation.

    Returns:
      exit_code, stdout, stderr, duration_ms, repo_path, patch_path.
    """
    client, err = _client_or_error(connection_id)
    if err:
        return err
    return git_operations.git_apply_patch_file_impl(
        client, repo_path, patch_path, timeout_seconds,
    )


@mcp.tool()
def clone_linux_source_tree(
    connection_id: str,
    git_url: Optional[str] = None,
    destination_path: Optional[str] = None,
    branch: Optional[str] = None,
    timeout_seconds: int = 1200,
) -> dict:
    """Clone a Linux kernel source tree on the remote VM.

    WHEN TO USE: User says "clone net-next", "clone kernel source",
    "clone linux tree", "git clone kernel", or when the repo doesn't
    exist yet on the VM.
    WHEN NOT TO USE: Do NOT use ssh_exec for cloning — always use this tool.

    Defaults to cloning the net-next tree (mainline networking development)
    into ~/repos/net-next. Supply git_url for any other kernel repo.

    Args:
      connection_id: Active connection UUID.
      git_url: Full git URL. Defaults to the net-next tree at
        git.kernel.org if omitted.
      destination_path: Where to clone on the VM. Defaults to
        ~/repos/{repo-name} derived from the URL.
      branch: Specific branch to clone (optional).
      timeout_seconds: Max seconds (default 1200 = 20 min for large repos).

    Returns:
      exit_code, stdout, stderr, duration_ms, command, destination_path.
    """
    client, err = _client_or_error(connection_id)
    if err:
        return err
    return git_operations.clone_linux_source_tree_impl(
        client, git_url, destination_path, branch, timeout_seconds,
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
    """Build and install the Linux kernel from source on the remote VM (NO reboot).

    WHEN TO USE: User says "build kernel", "compile kernel", "make kernel",
    "install kernel", or after applying a patch.
    WHEN NOT TO USE: Do NOT use ssh_exec with raw make commands — use this tool.

    Build sequence:
      1. Copy /boot/config-$(uname -r) → .config
      2. make olddefconfig → localmodconfig
      3. Disable module signing (SYSTEM_TRUSTED_KEYS, MODULE_SIG, etc.)
      4. make -j$(nproc) (or -j<jobs>)
      5. Install: headers → modules → kernel → update-grub

    ON BUILD FAILURE — do NOT edit files on the VM. Instead:
      1. Fix the patch locally on the MCP server host.
      2. Re-upload with sftp_patch_file.
      3. Re-apply with git_apply_patch_file.
      4. Re-run this tool.

    After success, call reboot_vm to boot into the new kernel.

    Args:
      connection_id: Active connection UUID.
      repo_path: Kernel repo path on VM (default: ~/repos/net-next).
      sudo_password: Required for sudo operations during install.
      install_deps: Currently unused (reserved for future).
      jobs: Parallel make jobs (0 = auto-detect via nproc).
      timeout_seconds: Max seconds (default 7200 = 2 hours).

    Returns:
      exit_code, stdout, stderr, duration_ms, repo_path,
      log_path (on-VM build log), kernelrelease (e.g. "6.8.0-rc1+").
    """
    client, err = _client_or_error(connection_id)
    if err:
        return err
    return kernel_tools.build_kernel_from_source_impl(
        client, repo_path, sudo_password, install_deps,
        jobs, timeout_seconds,
    )


@mcp.tool()
def find_compile_regression(
    connection_id: str,
    repo_path: str = "~/repos/net-next",
    good_commit: str = "v6.8",
    bad_commit: str = "HEAD",
    sudo_password: str = "",
) -> dict:
    """Automated git-bisect to find which commit broke kernel compilation.

    WHEN TO USE: User says "find compile regression", "bisect build failure",
    "which commit broke the build", or when a kernel build fails and user
    wants to identify the culprit commit.

    Binary-searches between good_commit and bad_commit, testing compilation
    at each step (up to 20 iterations).

    Args:
      connection_id: Active connection UUID.
      repo_path: Kernel repo path (default: ~/repos/net-next).
      good_commit: A known-good commit or tag (default: "v6.8").
      bad_commit: A known-bad commit (default: "HEAD").
      sudo_password: For sudo during compilation.

    Returns:
      success (bool), culprit_commit (short hash), culprit_full (full hash),
      steps_taken, bisect_log (list of step dicts), summary, repo_path.
    """
    client, err = _client_or_error(connection_id)
    if err:
        return err
    return kernel_tools.find_compile_regression_impl(
        client, good_commit, bad_commit, repo_path, sudo_password,
    )


@mcp.tool()
def analyze_dmesg_tail(
    connection_id: str,
    lines: int = 100,
    sudo_password: Optional[str] = None,
    timeout_seconds: int = 8,
) -> dict:
    """Fetch and heuristically analyze the last N lines of dmesg for kernel problems.

    WHEN TO USE: User says "check dmesg", "kernel logs", "any crashes",
    "analyze dmesg", "check for panics", or after a suspected crash/hang.

    Scans for: kernel panic, oops, BUG:, WARNING:, Call Trace:,
    segfault, soft/hard lockup, general protection fault.

    After reviewing the results, provide a SHORT crash analysis to the
    user covering: what happened, likely root cause, and mitigation steps.

    Args:
      connection_id: Active connection UUID.
      lines: How many lines from the end of dmesg to inspect (default 100).
      sudo_password: If provided, runs dmesg via sudo (often required on
        non-root accounts).
      timeout_seconds: Max seconds for the dmesg fetch.

    Returns:
      issues_detected (bool), indicators (dict of counts per category),
      events (list of {kind, line_index, text}), last_event (str|null),
      raw_tail (full text), used_sudo (bool),
      stdout, stderr, exit_code.
    """
    client, err = _client_or_error(connection_id)
    if err:
        return err
    return crash_analysis.analyze_dmesg_tail_impl(
        client, lines, sudo_password, timeout_seconds,
    )


@mcp.tool()
def analyze_latest_crash_dmesg(
    connection_id: str,
    crash_root: str = "/var/crash",
    sudo_password: Optional[str] = None,
    max_bytes: int = 500_000,
    timeout_seconds: int = 20,
) -> dict:
    """Find the most recent crash directory and analyze its saved dmesg file.

    WHEN TO USE: User says "analyze crash", "check crash logs",
    "what caused the crash", or after a VM panic/reboot when
    /var/crash has crash dumps.

    Looks for directories named YYYYMMDDHHMM (12-digit UTC timestamp)
    under crash_root, picks the latest, reads its dmesg file, and runs
    heuristic analysis (panic, null_deref, oops detection).

    After reviewing results, provide a SHORT crash analysis with root
    cause and mitigation steps.

    Args:
      connection_id: Active connection UUID.
      crash_root: Directory containing crash subdirectories (default: /var/crash).
      sudo_password: For reading crash files that require elevated permissions.
      max_bytes: Max bytes to read from the dmesg file (default 500KB).
      timeout_seconds: Max seconds per remote command.

    Returns:
      crash_dir, timestamp_utc, timestamp_ist, dmesg_path,
      retrieved_bytes, truncated (bool),
      analysis (dict with event_type, short_summary, suspected_function,
        call_trace, recommended_actions),
      raw_excerpt (last 40 lines of dmesg).
    """
    client, err = _client_or_error(connection_id)
    if err:
        return err
    return crash_analysis.analyze_latest_crash_dmesg_impl(
        client, crash_root, sudo_password, max_bytes, timeout_seconds,
    )


@mcp.tool()
def get_ethtool_stats(
    connection_id: str,
    interface: Optional[str] = None,
    command: Optional[str] = None,
    timeout_seconds: int = 20,
) -> dict:
    """Get NIC statistics via ethtool or run a custom NIC diagnostic command.

    WHEN TO USE: User says "ethtool stats", "NIC statistics",
    "network stats", "check NIC", or needs to diagnose network issues.

    If neither command nor interface is provided, the default NIC is
    auto-detected via ``ip route``.

    PANIC HEURISTIC: If the SSH transport dies during execution,
    panic=True is returned. On panic, follow this recovery sequence:
      1. check_connection  (verify if VM is reachable)
      2. ssh_close         (clean up dead session)
      3. ssh_connect       (reconnect)
      4. analyze_latest_crash_dmesg  (check what happened)
    Do NOT re-run this tool on panic without the user asking.

    Args:
      connection_id: Active connection UUID.
      interface: NIC interface name (e.g. "eth0"). Auto-detected if omitted.
      command: Custom command to run instead of ethtool -S.
      timeout_seconds: Max seconds.

    Returns:
      panic (bool), panic_reason (str|null), exit_code,
      stdout, stderr, duration_ms, executed_command, interface,
      transport_active_after (bool).
    """
    client, err = _client_or_error(connection_id)
    if err:
        return err
    return diagnostics.get_ethtool_stats_impl(
        client, interface, command, timeout_seconds,
    )


@mcp.tool()
def reboot_vm(
    connection_id: str,
    sudo_password: Optional[str] = None,
    force: bool = False,
    delay_seconds: int = 1,
) -> dict:
    """Initiate an asynchronous reboot of the remote VM.

    WHEN TO USE: User says "reboot", "restart VM", or after a
    successful build_kernel_from_source to boot into the new kernel.

    The reboot is fire-and-forget: this tool returns BEFORE the VM
    goes down.  The current connection_id will become invalid.
    To reconnect after reboot, wait ~60 seconds then call ssh_connect.

    Args:
      connection_id: Active connection UUID.
      sudo_password: For sudo reboot (required on non-root accounts).
      force: If True, use ``reboot -f`` (immediate, no graceful shutdown).
      delay_seconds: Seconds to sleep before issuing reboot (default 1).

    Returns:
      started (bool), stdout, stderr, command, force, delay_seconds.
    """
    client, err = _client_or_error(connection_id)
    if err:
        return err
    result = diagnostics.reboot_vm_impl(
        client, sudo_password, force, delay_seconds,
    )
    # The connection is guaranteed dead after reboot — remove it now
    # so it doesn't linger as a stale entry in ssh_list.
    if result.get("started"):
        connection_manager.ssh_close_impl(connection_id)
        result["connection_closed"] = True
    return result
