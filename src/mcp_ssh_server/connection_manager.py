"""SSH connection management utilities.

Manages a pool of persistent SSH connections keyed by UUID.
Each entry tracks the client handle plus metadata (host, port,
username, connection time) so callers can inspect active sessions
without needing to store that context themselves.
"""

from __future__ import annotations

import base64
import io
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, Optional

import paramiko  # type: ignore[import-untyped]

from ._helpers import error_result, not_found_result, get_logger

_log = get_logger("mcp_ssh_server.connection_manager")


# ── Connection metadata ──────────────────────────────────────────

@dataclass
class _ConnInfo:
    """Metadata kept alongside each SSH client."""

    client: paramiko.SSHClient
    host: str
    port: int
    username: str
    connected_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


_connections: Dict[str, _ConnInfo] = {}


# ── Private helpers ───────────────────────────────────────────────

def _build_pkey(private_key: str, passphrase: Optional[str]) -> paramiko.PKey:
    """Build a paramiko private-key object from a PEM string or
    base-64 blob.  Tries RSA -> ECDSA -> Ed25519 -> DSS."""
    key_data = private_key.strip()
    if "-----BEGIN" not in key_data:
        try:
            key_data = base64.b64decode(key_data).decode("utf-8")
        except Exception:
            pass

    last_error: Optional[Exception] = None
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
        except Exception as exc:
            last_error = exc
    raise ValueError(f"Could not parse private key: {last_error}")


def _make_client(accept_unknown_host: bool) -> paramiko.SSHClient:
    """Create a configured SSH client with the chosen host-key policy."""
    client = paramiko.SSHClient()
    policy = (
        paramiko.AutoAddPolicy()
        if accept_unknown_host
        else paramiko.RejectPolicy()
    )
    client.set_missing_host_key_policy(policy)
    return client


# ── Public API ────────────────────────────────────────────────────

def ssh_connect_impl(
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

    Provide **exactly one** of *password* or *private_key*.
    Returns a dict with ``connection_id`` on success, or an
    ``error`` / ``type`` pair on failure (never raises).
    """
    if (password is None) == (private_key is None):
        return error_result(
            "Provide exactly one of password or private_key",
            "ValueError",
        )

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
        _connections[conn_id] = _ConnInfo(
            client=client,
            host=host,
            port=port,
            username=username,
        )
        _log.info(
            "connected id=%s host=%s user=%s",
            conn_id[:8], host, username,
        )
        return {
            "connection_id": conn_id,
            "host": host,
            "port": port,
            "username": username,
            "connect_ms": int((time.time() - start) * 1000),
        }
    except Exception as exc:
        client.close()
        _log.warning("connect failed host=%s: %s", host, exc)
        return error_result(str(exc), exc.__class__.__name__)


def ssh_close_impl(connection_id: str) -> dict:
    """Close a previously established SSH connection."""
    info = _connections.pop(connection_id, None)
    if info is None:
        return not_found_result(connection_id)
    try:
        info.client.close()
        _log.info("closed id=%s", connection_id[:8])
        return {"closed": True}
    except Exception as exc:
        return error_result(str(exc), exc.__class__.__name__)


def ssh_list_impl() -> dict:
    """List active SSH connections with metadata."""
    items = []
    for cid, info in _connections.items():
        items.append({
            "connection_id": cid,
            "host": info.host,
            "port": info.port,
            "username": info.username,
            "connected_at": info.connected_at,
        })
    return {"connections": items}


def get_connection(connection_id: str) -> Optional[paramiko.SSHClient]:
    """Return the raw SSH client for *connection_id*, or ``None``."""
    info = _connections.get(connection_id)
    return info.client if info else None


def get_connection_info(connection_id: str) -> Optional[_ConnInfo]:
    """Return full metadata for *connection_id*, or ``None``."""
    return _connections.get(connection_id)
