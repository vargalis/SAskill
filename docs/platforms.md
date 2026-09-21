# Windows, macOS, and Linux

Requirements: Python 3.11+, a Codex CLI with plugin support, and the bundled
plugin-creator helpers. The plugin uses a local stdio MCP server.

Run `python3 scripts/install_local.py` on macOS/Linux or
`py -3 scripts/install_local.py` on Windows. If `codex` is not in PATH, pass
`--codex` with its full path.

The installed source is `~/plugins/agent-for-secureaccess`; its isolated runtime
is `~/plugins/.runtimes/agent-for-secureaccess`. The installer creates a portable
`python -m secureaccess_mcp` entry point and a machine-specific `.mcp.json`.

Secrets use Windows Credential Manager, macOS Keychain, or Linux Secret Service.
No file fallback is used. Run these commands interactively:

```text
python scripts/setup_local.py password
python scripts/setup_local.py tunnel-psk
```

The native-vault tunnel PSK action asks for Tunnel ID, headend, shared or split
keys, and the format of each key. Supported formats are plain IOS type 0, IOS
encrypted type 6, and hexadecimal. Prompts are hidden and require confirmation.
The test build can instead store the same values directly in CSV.

Headless Linux may explicitly set `SECUREACCESS_SECRET_PROVIDER=environment` and
provide `ISR_PASSWORD` from its process secret manager. The test build can instead
read the NETCONF username/password and tunnel PSKs from CSV. These values are
redacted from generated previews, diffs, diagnostics, and logs.

SSH host keys are verified through `~/.ssh/known_hosts`. Secrets do not migrate
between machines automatically.

### Local target configuration

Before starting the server or local setup, set `SECUREACCESS_HOST` to your router management address. Set `SECUREACCESS_USER` when using stored credentials; CSV login credentials are also supported. No router address or username is built in. Restart the server after changing these environment variables. Fill `<<< REQUIRED >>>` fields in a private copy of the CSV template. Never commit the filled deployment file.
