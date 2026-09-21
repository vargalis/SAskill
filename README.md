# Agent for SecureAccess

Public CSV input → preview → device inline validation → reviewed one-use NETCONF
transaction. The native IOS XE adapter implements IKEv2/IPsec, selected VTI,
static routing and source-based PBR. FTD FMC/FDM template application is a later phase.

## Tools

- create_configuration_csv / preview_configuration_csv: offline Basic or Advanced template/import. The skill asks for the mode before creating a CSV; Basic is recommended and hides fields with built-in Cisco defaults.
- inventory_capabilities / routing_summary: enrolled router read-only discovery.
- validate_configuration_csv: reconciled patch, NETCONF edit-config test-only.
- validate_adapter_fixture: controlled GCM/CBC schema probes; no application path.
- prepare_configuration_apply: public exact diff and private expiring plan.
- tunnel_psk_status: confirms matching native-vault entries without exposing values; the test build can instead take PSKs from CSV.
- apply_configuration_plan: approved candidate transaction or guarded lab-running transaction.

See [docs/netconf-apply.md](docs/netconf-apply.md) for scope, conflict handling,
secret preservation, pre/postchecks, rollback and current validation evidence.
See [docs/csv-templates.md](docs/csv-templates.md) for CSV format.
See [docs/platforms.md](docs/platforms.md) for native secret store/verified SSH setup.
The wizard remains optional. Legacy YAML CLI is read-only; no CLI configuration RPC.

Exact model/submodule digests are checked against NETCONF get-schema. Current
device features/deviations are enforced by server inline validation. Missing or
unknown pre/postcheck evidence blocks or rolls back. Credentials/PSKs/private XML
are redacted from previews, results, diffs, diagnostics, and logs. The test build accepts
NETCONF credentials and shared or split PSKs directly in CSV; native stores remain optional.
Candidate and confirmed commit are preferred. On a lab ISR without them, the adapter
requires validate and rollback-on-error, locks running, uses test-then-set, verifies
the resulting nonsecret state, and retains an inverse patch for failed writes. Hardware schema/SA/
rollback evidence is distinct from passing unit tests.

## Development validation without installing

Run scripts/validate_adapter.py with the plugin Python runtime under the user whose
native secret store contains the enrolled credentials. It performs inline GCM/CBC
schema tests only. scripts/validate_csv.py validates a filled public CSV the same way.
Reload the updated plugin to use the latest MCP diagnostics.

### Local target configuration

Before starting the server or local setup, set `SECUREACCESS_HOST` to your router management address. Set `SECUREACCESS_USER` when using stored credentials; CSV login credentials are also supported. No router address or username is built in. Restart the server after changing these environment variables. Fill `<<< REQUIRED >>>` fields in a private copy of the CSV template. Never commit the filled deployment file.
