# Workstation installation and access

Use the complete installation and operation guide in your preferred language:

- [English: prerequisites, macOS/Linux and Windows commands, credentials, SSH enrollment and usage](user-guide.en.md)
- [Русский: подготовка, команды macOS/Linux и Windows, credentials, SSH и использование](user-guide.ru.md)

The installer requires Python 3.11+, Codex CLI plugin support, bundled plugin-creator
helpers and package-download access. Run it as the same OS user as Codex:

```sh
# macOS/Linux, from the repository root
python3 scripts/install_local.py
```

```powershell
# Windows PowerShell, from the repository root
py -3 scripts/install_local.py
```

Use `--codex` with the executable's full path if it is not on PATH. The installer
copies source to `~/plugins/agent-for-secureaccess`, creates its runtime under
`~/plugins/.runtimes/agent-for-secureaccess`, writes `.mcp.json` and registers the
personal plugin. Re-run it from updated source to update; reload and open a new task.

Set SECUREACCESS_HOST in the actual MCP process environment; there is no default
router. Set SECUREACCESS_USER for discovery using stored/environment credentials.
A shell export does not configure an already running desktop app. The guides show
runtime-specific helper commands and how to verify the target and live connection.

Native login storage uses Windows Credential Manager, macOS Keychain or Linux
Secret Service. SSH host keys must be independently verified and enrolled in
`~/.ssh/known_hosts`. Secrets do not migrate between machines automatically.
The explicit `SECUREACCESS_SECRET_PROVIDER=environment` / `ISR_PASSWORD` alternative
supplies the login password only, not tunnel PSKs.

Current CSV validation requires login credentials and PSKs in the CSV despite the
adapter's internal vault/device-key support. Vault setup is useful for discovery
but does not eliminate those CSV fields. Read the guides' limitations and secret
handling section before beginning a deployment.
