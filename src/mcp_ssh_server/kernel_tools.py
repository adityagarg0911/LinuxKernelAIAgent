"""Kernel development and build tools."""
import time
import shlex
import re
from typing import Optional
import paramiko  # type: ignore[import-untyped]


def install_developer_tools_impl(
    client: paramiko.SSHClient,
    sudo_password: Optional[str] = None,
    timeout_seconds: int = 120,
) -> dict:
    """Install basic developer tools on the remote VM."""
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
                "net-tools zstd universal-ctags libdw-dev"
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


def build_kernel_from_source_impl(
    client: paramiko.SSHClient,
    repo_path: str = "~/repos/net-next",
    sudo_password: Optional[str] = None,
    install_deps: bool = True,
    jobs: int = 0,
    timeout_seconds: int = 7200,
) -> dict:
    """Build and install the kernel from the repo root (no reboot)."""
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
    run_sudo "\\
        (command -v update-grub && update-grub) || \\
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


def test_kernel_compile(
    client: paramiko.SSHClient,
    repo_path: str,
    sudo_password: str = ""
) -> bool:
    """Internal helper to test kernel compilation at current commit."""
    pw = sudo_password
    script = f"""
    set -euo pipefail
    cd {repo_path}

    # Ensure a consistent base config, then update defaults
    if [ ! -f .config ]; then
        cp /boot/config-$(uname -r) .config || true
    fi
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

        return exit_code == 0 and not any(x in (out + err).lower() for x in [
            "error:", "failed", "fatal error", "compilation terminated",
            "make: *** [", "no rule to make target"
        ])
    except Exception:
        return False


def find_compile_regression_impl(
    client: paramiko.SSHClient,
    good_commit: str = "v6.8",
    bad_commit: str = "HEAD",
    repo_path: str = "~/repos/net-next",
    sudo_password: str = ""
) -> dict:
    """Automated git bisect to find compilation regression."""
    def run_cmd(cmd):
        try:
            stdin, stdout, stderr = client.exec_command(
                f"cd {repo_path}; {cmd}", timeout=60
            )
            out = stdout.read().decode('utf-8', errors='replace')
            err = stderr.read().decode('utf-8', errors='replace')
            return out + err
        except Exception as e:
            return f"Error: {e}"

    steps: list[dict] = []
    culprit = None

    try:
        run_cmd("git bisect reset")
        run_cmd("git bisect start")
        run_cmd(f"git bisect bad {bad_commit}")
        run_cmd(f"git bisect good {good_commit}")

        while len(steps) < 20:
            current = run_cmd("git rev-parse HEAD").strip()
            if not current or len(current) < 8:
                break

            msg = run_cmd(f"git log -1 --format='%s' {current}").strip()
            compile_ok = test_kernel_compile(client, repo_path, sudo_password)

            steps.append({
                "commit": current[:8],
                "message": msg[:50] + "..." if len(msg) > 50 else msg,
                "result": "PASS" if compile_ok else "FAIL"
            })

            bisect_cmd = "git bisect good" if compile_ok else "git bisect bad"
            bisect_result = run_cmd(bisect_cmd)

            if "is the first bad commit" in bisect_result:
                m = re.search(
                    r"([0-9a-f]{7,40})\s+is the first bad commit",
                    bisect_result
                )
                if m:
                    culprit = m.group(1)
                else:
                    # Fallback: ask git for the current commit
                    culprit = run_cmd("git rev-parse HEAD").strip()
                break
            elif ("There are only" in bisect_result and
                  "revisions left" in bisect_result):
                continue
            # elif not any(
            #     word in bisect_result.lower()
            #     for word in ["bisecting:", "checkout"]
            # ):
            #     break

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
        run_cmd("git bisect reset")
        return {"error": str(e), "success": False}
