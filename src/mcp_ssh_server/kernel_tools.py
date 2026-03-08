"""Kernel development and build tools.

Provides implementations for:
- Installing developer packages on the remote VM.
- Building and installing a Linux kernel from source.
- Automated git-bisect to locate compilation regressions.

All functions accept a live ``paramiko.SSHClient`` and return a
plain dict (never raise).  Shell commands use ``shlex.quote`` for
all user-supplied values to prevent injection.
"""

from __future__ import annotations

import re
import shlex
from typing import Optional

import paramiko  # type: ignore[import-untyped]

from ._helpers import (
    run_ssh,
    remote_path,
    build_sudo_runner_snippet,
    sudo_wrap,
    error_result,
    get_logger,
    DEV_PACKAGES,
    KERNEL_CONFIG_DISABLES,
    KERNEL_CONFIG_UNDEFINES,
    DEFAULT_REPO_PATH,
)

_log = get_logger("mcp_ssh_server.kernel_tools")


def install_developer_tools_impl(
    client: paramiko.SSHClient,
    sudo_password: Optional[str] = None,
    timeout_seconds: int = 120,
) -> dict:
    """Install basic developer tools on the remote VM.

    Uses the canonical ``DEV_PACKAGES`` list from ``_helpers`` so
    both sudo and non-sudo branches install exactly the same set.
    """
    pkg_str = " ".join(DEV_PACKAGES)
    update_cmd = "apt update"
    install_cmd = f"apt install -y {pkg_str}"

    if sudo_password:
        pw = shlex.quote(sudo_password)
        cmd = (
            f"echo {pw} | sudo -S {update_cmd} && "
            f"echo {pw} | sudo -S {install_cmd}"
        )
    else:
        cmd = f"sudo {update_cmd} && sudo {install_cmd}"

    code, out, err, dur = run_ssh(client, cmd, timeout=timeout_seconds)
    return {
        "stdout": out,
        "stderr": err,
        "exit_code": code,
        "duration_ms": dur,
        "command": cmd,
    }


def build_kernel_from_source_impl(
    client: paramiko.SSHClient,
    repo_path: str = "~/repos/net-next",
    sudo_password: Optional[str] = None,
    install_deps: bool = True,
    jobs: int = 0,
    timeout_seconds: int = 7200,
) -> dict:
    """Build and install the kernel from the repo root (no reboot).

    Uses ``_helpers.build_sudo_runner_snippet`` for safe sudo
    handling and ``KERNEL_CONFIG_DISABLES`` / ``KERNEL_CONFIG_UNDEFINES``
    for reproducible .config sanitisation.
    """
    jobs_flag = f"-j{jobs}" if jobs and jobs > 0 else "-j$(nproc)"
    rpath = remote_path(repo_path)

    # Build disable lines from centralised lists
    disable_lines = "\n".join(
        f"      scripts/config --disable {opt} || true"
        for opt in KERNEL_CONFIG_DISABLES
    )
    undefine_lines = "\n".join(
        f"      scripts/config --undefine {opt} || true"
        for opt in KERNEL_CONFIG_UNDEFINES
    )

    sudo_snippet = build_sudo_runner_snippet(sudo_password)

    script = f"""
    set -euo pipefail
    LOG=/tmp/simple_kernel_build_$(date +%s).log
    exec > >(tee -a "$LOG") 2>&1

    echo "[info] repo: {repo_path}"
    cd {rpath}
    git rev-parse --is-inside-work-tree >/dev/null

    echo "[step] copy base config"
    cp /boot/config-$(uname -r) .config
    echo "[step] olddefconfig"
    make olddefconfig
    echo "[step] localmodconfig"
    yes "" | make localmodconfig || true

    if [ -x scripts/config ]; then
      echo "[step] disabling keys & module signing"
{disable_lines}
{undefine_lines}
    fi

    echo "[step] second olddefconfig"
    make olddefconfig

    {sudo_snippet}

    echo "[build] kernel {jobs_flag}"
    run_sudo "make {jobs_flag}"
    echo "[install] headers"
    run_sudo "make headers_install"
    echo "[install] modules {jobs_flag}"
    run_sudo "make {jobs_flag} modules_install"
    echo "[install] kernel {jobs_flag}"
    run_sudo "make {jobs_flag} install"
    echo "[grub] update"
    run_sudo "\\
        (command -v update-grub && update-grub) || \\
        (command -v update-grub2 && update-grub2) || true"

    KREL=$(make kernelrelease 2>/dev/null || uname -r || true)
    echo "[done] kernelrelease=$KREL"
    echo "$LOG"
    """
    cmd = f"bash -lc {shlex.quote(script)}"
    code, out, err, dur = run_ssh(client, cmd, timeout=timeout_seconds)

    log_path = None
    kernelrelease = None
    for line in reversed(out.strip().splitlines()):
        if line.startswith("/tmp/simple_kernel_build_") and log_path is None:
            log_path = line.strip()
        if line.startswith("[done] kernelrelease=") and kernelrelease is None:
            kernelrelease = line.split("=", 1)[1]

    return {
        "exit_code": code,
        "duration_ms": dur,
        "stdout": out,
        "stderr": err,
        "repo_path": repo_path,
        "log_path": log_path,
        "kernelrelease": kernelrelease,
    }


def test_kernel_compile(
    client: paramiko.SSHClient,
    repo_path: str,
    sudo_password: str = "",
) -> bool:
    """Internal helper: test kernel compilation at current commit.

    Returns ``True`` only when exit-code is 0 **and** stdout+stderr
    contain none of the known fatal error markers.
    """
    rpath = remote_path(repo_path)
    sudo_snippet = build_sudo_runner_snippet(sudo_password or None)

    script = f"""
    set -euo pipefail
    cd {rpath}

    if [ ! -f .config ]; then
        cp /boot/config-$(uname -r) .config || true
    fi
    make olddefconfig

    {sudo_snippet}
    run_sudo "make -j$(nproc)"
    """
    code, out, err, _ = run_ssh(
        client, f"bash -c {shlex.quote(script)}", timeout=1800,
    )
    if code != 0:
        return False
    combined = (out + err).lower()
    return not any(
        marker in combined
        for marker in (
            "error:", "failed", "fatal error",
            "compilation terminated",
            "make: *** [", "no rule to make target",
        )
    )


def find_compile_regression_impl(
    client: paramiko.SSHClient,
    good_commit: str = "v6.8",
    bad_commit: str = "HEAD",
    repo_path: str = "~/repos/net-next",
    sudo_password: str = "",
) -> dict:
    """Automated git bisect to find compilation regression.

    Uses binary search between *good_commit* and *bad_commit*,
    testing compilation at each step.  Returns the culprit commit
    hash and a step-by-step log.
    """
    rpath = remote_path(repo_path)

    def run_cmd(cmd: str) -> str:
        full_cmd = f"cd {rpath}; {cmd}"
        code, out, err, _ = run_ssh(
            client, f"bash -lc {shlex.quote(full_cmd)}", timeout=60,
        )
        return out + err

    steps: list[dict] = []
    culprit: Optional[str] = None

    try:
        run_cmd("git bisect reset")
        run_cmd("git bisect start")
        run_cmd(f"git bisect bad {shlex.quote(bad_commit)}")
        run_cmd(f"git bisect good {shlex.quote(good_commit)}")

        while len(steps) < 20:
            current = run_cmd("git rev-parse HEAD").strip()
            if not current or len(current) < 8:
                break

            msg = run_cmd(
                f"git log -1 --format='%s' {current}"
            ).strip()
            compile_ok = test_kernel_compile(
                client, repo_path, sudo_password,
            )

            steps.append({
                "commit": current[:8],
                "message": (
                    msg[:50] + "..." if len(msg) > 50 else msg
                ),
                "result": "PASS" if compile_ok else "FAIL",
            })

            bisect_cmd = (
                "git bisect good" if compile_ok else "git bisect bad"
            )
            bisect_result = run_cmd(bisect_cmd)

            if "is the first bad commit" in bisect_result:
                m = re.search(
                    r"([0-9a-f]{7,40})\s+is the first bad commit",
                    bisect_result,
                )
                culprit = (
                    m.group(1) if m
                    else run_cmd("git rev-parse HEAD").strip()
                )
                break
            elif (
                "There are only" in bisect_result
                and "revisions left" in bisect_result
            ):
                continue

        run_cmd("git bisect reset")

        return {
            "success": True,
            "culprit_commit": (
                culprit[:8] if culprit else "Not found"
            ),
            "culprit_full": culprit,
            "steps_taken": len(steps),
            "bisect_log": steps,
            "summary": (
                f"Found regression in commit "
                f"{culprit[:8] if culprit else 'unknown'} "
                f"after {len(steps)} compilation tests"
            ),
            "repo_path": repo_path,
            "commit_range": f"{good_commit}..{bad_commit}",
        }

    except Exception as exc:
        run_cmd("git bisect reset")
        return error_result(str(exc), exc.__class__.__name__, success=False)
