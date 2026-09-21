"""Interactive local credential setup; never invoke with a password argument."""
import os
import argparse
import base64
import getpass
import hashlib
from pathlib import Path

import paramiko
from local_secrets import native_vault, save_tunnel_psk, delete_tunnel_psk

HOST = os.environ.get("SECUREACCESS_HOST", "").strip()
USER = os.environ.get("SECUREACCESS_USER", "").strip()
SERVICE = "Agent-for-SecureAccess/" + os.environ.get("SECUREACCESS_HOST", "").strip()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=["password", "host-key", "delete-password", "tunnel-psk", "delete-tunnel-psk"])
    args = parser.parse_args()
    if not HOST:
        parser.error("Configure SECUREACCESS_HOST first")
    if args.action in ("password", "delete-password") and not USER:
        parser.error("Configure SECUREACCESS_USER first")
    if args.action == "password":
        vault = native_vault()
        password = getpass.getpass("NETCONF password (hidden): ")
        if not password:
            raise SystemExit("Empty password rejected")
        vault.set_password(SERVICE, USER, password)
        print("Password saved to the native OS secret store for this user.")
    elif args.action == "delete-password":
        vault = native_vault()
        vault.delete_password(SERVICE, USER)
        print("Password removed.")
    elif args.action in ("tunnel-psk", "delete-tunnel-psk"):
        tunnel_id = int(input("Tunnel number (for example 100): ").strip())
        headend = input("Secure Access headend IPv4 address: ").strip()
        if args.action == "delete-tunnel-psk":
            delete_tunnel_psk(tunnel_id, headend)
            print("Tunnel PSK removed from the native OS secret store.")
            return
        mode = input("Key mode [shared/split] (shared): ").strip().lower() or "shared"
        if mode not in ("shared", "split"):
            raise SystemExit("Key mode must be shared or split")

        def read_key(label):
            kind = input(f"{label} format [plain/type6/hex] (plain): ").strip().lower() or "plain"
            if kind not in ("plain", "type6", "hex"):
                raise SystemExit("Format must be plain, type6, or hex")
            first = getpass.getpass(f"{label} (hidden): ")
            second = getpass.getpass(f"Repeat {label} (hidden): ")
            if not first or first != second:
                raise SystemExit("Keys are empty or do not match; nothing saved")
            if "\r" in first or "\n" in first:
                raise SystemExit("Line breaks are not supported in IOS XE PSKs")
            if kind == "hex":
                if len(first) % 2 or any(c not in "0123456789abcdefABCDEF" for c in first):
                    raise SystemExit("Hex key must contain an even number of hexadecimal characters")
                return {"format": "hex", "value": first}
            return {"format": "key", "encryption": 6 if kind == "type6" else 0, "value": first}

        if mode == "shared":
            record = {"mode": "shared", "shared": read_key("Shared PSK")}
        else:
            record = {"mode": "split", "local": read_key("Local PSK"), "remote": read_key("Remote PSK")}
        save_tunnel_psk(tunnel_id, headend, record)
        print(f"PSK saved for Tunnel{tunnel_id} and {headend}. No secret was written to CSV or logs.")
    else:
        # Fetch a public SSH key without authenticating. Enrollment requires a trusted fingerprint.
        transport = paramiko.Transport((HOST, 830))
        transport.banner_timeout = 10
        transport.handshake_timeout = 10
        try:
            transport.start_client(timeout=10)
            key = transport.get_remote_server_key()
        finally:
            transport.close()
        fingerprint = "SHA256:" + base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip("=")
        print(f"Offered {key.get_name()} fingerprint: {fingerprint}")
        trusted = input("Paste the SHA256 fingerprint verified via a trusted independent channel: ").strip()
        if trusted != fingerprint:
            raise SystemExit("Fingerprint mismatch; nothing saved")
        path = Path.home() / ".ssh" / "known_hosts"
        path.parent.mkdir(parents=True, exist_ok=True)
        keys = paramiko.HostKeys()
        if path.exists():
            keys.load(str(path))
        existing = keys.lookup(f"[{HOST}]:830")
        if existing and (key.get_name() not in existing or existing[key.get_name()] != key):
            raise SystemExit("Existing host key differs; review key rotation manually")
        # Append only the new entry; do not rewrite unrelated known_hosts lines/comments.
        if not existing:
            with path.open("a", encoding="utf-8") as output:
                output.write(f"\n[{HOST}]:830 {key.get_name()} {key.get_base64()}\n")
        print("Verified host key enrolled.")


if __name__ == "__main__":
    main()
