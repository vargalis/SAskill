# Agent for SecureAccess

Public CSV input → preview → device inline validation → reviewed one-use NETCONF
transaction. The native IOS XE adapter implements IKEv2/IPsec, selected VTI,
static routing and source-based PBR. FTD FMC/FDM template application is a later phase.

## Tools

- create_configuration_csv / preview_configuration_csv: offline template/import.
- inventory_capabilities / routing_summary: enrolled router read-only discovery.
- validate_configuration_csv: reconciled patch, NETCONF edit-config test-only.
- validate_adapter_fixture: controlled GCM/CBC schema probes; no application path.
- prepare_configuration_apply: public exact diff and private expiring plan.
- apply_configuration_plan: approved candidate/validate/confirmed-commit transaction.

See [docs/netconf-apply.md](docs/netconf-apply.md) for scope, conflict handling,
secret preservation, pre/postchecks, rollback and current validation evidence.
See [docs/csv-templates.md](docs/csv-templates.md) for CSV format.
See [docs/platforms.md](docs/platforms.md) for native secret store/verified SSH setup.
The wizard remains optional. Legacy YAML CLI is read-only; no CLI configuration RPC.

Exact model/submodule digests are checked against NETCONF get-schema. Current
device features/deviations are enforced by server inline validation. Missing or
unknown pre/postcheck evidence blocks or rolls back. Credentials/PSKs/private XML
never enter public CSV/tool arguments/results/logs; PSKs are pre-provisioned natively.
Candidate and confirmed commit are required for application; dg-wi-r1 currently
advertises neither. Inline validation does not require them. Hardware schema/SA/
rollback evidence is distinct from passing unit tests.

## Development validation without installing

Run scripts/validate_adapter.py with the plugin Python runtime under the user whose
native secret store contains the enrolled credentials. It performs inline GCM/CBC
schema tests only. scripts/validate_csv.py validates a filled public CSV the same way.
Reload the updated plugin to use the latest MCP diagnostics.
