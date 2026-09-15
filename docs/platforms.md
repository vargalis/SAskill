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

The tunnel PSK action asks for Tunnel ID, headend, shared or split keys, and the
format of each key. Supported formats are plain IOS type 0, IOS encrypted type 6,
and hexadecimal. Prompts are hidden and require confirmation. The CSV stores no
PSK. A stored PSK is scoped to the enrolled router, Tunnel ID, and headend.

Headless Linux may explicitly set `SECUREACCESS_SECRET_PROVIDER=environment` and
provide `ISR_PASSWORD` from its process secret manager. Tunnel PSKs currently
require a native keyring. Never put credentials or PSKs in chat, CSV, `.mcp.json`,
YAML, command arguments, or logs.

SSH host keys are verified through `~/.ssh/known_hosts`. Secrets do not migrate
between machines automatically.
