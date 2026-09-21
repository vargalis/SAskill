"""Native OS stores only; explicit environment mode for headless installations."""
import os
import sys
import json
from ipaddress import IPv4Address

SERVICE = "Agent-for-SecureAccess/" + os.environ.get("SECUREACCESS_HOST", "").strip()
USER = os.environ.get("SECUREACCESS_USER", "").strip()
PSK_USER_PREFIX = "secureaccess-tunnel-psk"


def native_vault():
    if not os.environ.get("SECUREACCESS_HOST", "").strip():
        raise RuntimeError("Configure SECUREACCESS_HOST before using the credential store")
    if sys.platform == "win32":
        from keyring.backends.Windows import WinVaultKeyring
        vault = WinVaultKeyring()
    elif sys.platform == "darwin":
        from keyring.backends.macOS import Keyring
        vault = Keyring()
    elif sys.platform.startswith("linux"):
        from keyring.backends.SecretService import Keyring
        vault = Keyring()
    else:
        raise RuntimeError("Unsupported platform; use explicit environment provider")
    if vault.priority <= 0:
        raise RuntimeError("Native secret store unavailable or locked")
    return vault


def password():
    provider = os.environ.get("SECUREACCESS_SECRET_PROVIDER", "keyring")
    if provider == "environment":
        return os.environ.get("ISR_PASSWORD")
    if provider != "keyring":
        raise RuntimeError("Unknown secret provider")
    if not USER:
        raise RuntimeError("Configure SECUREACCESS_USER before loading stored credentials")
    return native_vault().get_password(SERVICE, USER)


def psk_account(tunnel_id, headend):
    tunnel_id = int(tunnel_id)
    if not 0 <= tunnel_id <= 2147483647:
        raise ValueError("Tunnel ID is outside the IOS XE range")
    return f"{PSK_USER_PREFIX}/Tunnel{tunnel_id}/{IPv4Address(headend)}"


def tunnel_psk(tunnel_id, headend):
    """Load a structured PSK from the native vault; never return it from an MCP tool."""
    value = native_vault().get_password(SERVICE, psk_account(tunnel_id, headend))
    if not value:
        return None
    record = json.loads(value)
    if record.get("mode") == "shared" and _valid_key(record.get("shared")):
        return record
    if record.get("mode") == "split" and _valid_key(record.get("local")) and _valid_key(record.get("remote")):
        return record
    raise RuntimeError("Stored tunnel PSK record is invalid; replace it with setup_local.py")


def save_tunnel_psk(tunnel_id, headend, record):
    if record.get("mode") == "shared":
        valid = _valid_key(record.get("shared"))
    else:
        valid = record.get("mode") == "split" and _valid_key(record.get("local")) and _valid_key(record.get("remote"))
    if not valid:
        raise ValueError("Invalid tunnel PSK record")
    native_vault().set_password(SERVICE, psk_account(tunnel_id, headend), json.dumps(record, separators=(",", ":")))


def delete_tunnel_psk(tunnel_id, headend):
    native_vault().delete_password(SERVICE, psk_account(tunnel_id, headend))


def _valid_key(item):
    if not isinstance(item, dict) or not isinstance(item.get("value"), str) or not item["value"]:
        return False
    kind = item.get("format")
    if kind == "hex":
        value = item["value"]
        return len(value) % 2 == 0 and all(c in "0123456789abcdefABCDEF" for c in value)
    return kind == "key" and item.get("encryption") in (0, 6)
