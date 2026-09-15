"""Native OS stores only; explicit environment mode for headless installations."""
import os
import sys

SERVICE = "Agent-for-SecureAccess/10.2.3.1"
USER = "secureaccess-agent"


def native_vault():
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
    return native_vault().get_password(SERVICE, USER)
