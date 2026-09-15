"""Interactive local credential setup; never invoke with a password argument."""
import argparse
import base64
import getpass
import hashlib
from pathlib import Path

import paramiko
from local_secrets import native_vault

HOST = "10.2.3.1"
USER = "secureaccess-agent"
SERVICE = "Agent-for-SecureAccess/10.2.3.1"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=["password", "host-key", "delete-password"])
    args = parser.parse_args()
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
