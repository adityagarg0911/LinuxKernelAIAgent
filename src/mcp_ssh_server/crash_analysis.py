"""Crash analysis and dmesg parsing tools."""
import re
import shlex
from datetime import datetime, timedelta
from typing import Optional
import paramiko  # type: ignore[import-untyped]


def analyze_dmesg_text_light(raw: str) -> dict:
    """Lightweight kernel crash / fault heuristic analyzer for dmesg text."""
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
        if re_modules.match(line):
            modules_line = line

    for entry in call_trace:
        if not entry:
            continue
        token = entry.split()[0]
        if token.startswith("?"):
            continue
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


def analyze_dmesg_tail_impl(
    client: paramiko.SSHClient,
    lines: int = 100,
    sudo_password: Optional[str] = None,
    timeout_seconds: int = 8,
) -> dict:
    """Fetch and heuristically analyze the tail of dmesg."""
    if lines <= 0:
        return {"error": "lines must be > 0", "type": "ValueError"}

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


def analyze_latest_crash_dmesg_impl(
    client: paramiko.SSHClient,
    crash_root: str = "/var/crash",
    sudo_password: Optional[str] = None,
    max_bytes: int = 500_000,
    timeout_seconds: int = 20,
) -> dict:
    """Locate the newest crash directory and analyze its dmesg file."""
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
    try:
        dt_utc = datetime.strptime(utc_ts, "%Y%m%d%H%M")
        dt_ist = dt_utc + timedelta(hours=5, minutes=30)
        ts_utc_iso = dt_utc.isoformat() + "Z"
        ts_ist_iso = dt_ist.isoformat()
    except Exception:
        ts_utc_iso = utc_ts
        ts_ist_iso = None

    dmesg_path = f"{crash_root}/{latest}/dmesg.{latest}"
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
    analysis = analyze_dmesg_text_light(raw)
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
