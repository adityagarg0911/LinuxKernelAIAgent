"""SSH connection management utilities."""
import base64
import io
import time
import uuid
from typing import Optional, Dict
import paramiko  # type: ignore[import-untyped]

_connections: Dict[str, paramiko.SSHClient] = {}


def _build_pkey(private_key: str, passphrase: Optional[str]) -> paramiko.PKey:
    """Build a paramiko private key object from string."""
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
    """Create a configured SSH client."""
    client = paramiko.SSHClient()
    if accept_unknown_host:
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    else:
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
    return client


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
    """Establish and cache a persistent SSH connection."""
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


def ssh_close_impl(connection_id: str) -> dict:
    """Close a previously established SSH connection."""
    client = _connections.pop(connection_id, None)
    if client is None:
        return {"error": "Unknown connection_id", "type": "NotFound"}
    try:
        client.close()
        return {"closed": True}
    except Exception as e:
        return {"error": str(e), "type": e.__class__.__name__}


def ssh_list_impl() -> dict:
    """List active SSH connection IDs."""
    return {"connections": list(_connections.keys())}


def get_connection(connection_id: str) -> Optional[paramiko.SSHClient]:
    """Get an SSH client by connection ID."""
    return _connections.get(connection_id)
