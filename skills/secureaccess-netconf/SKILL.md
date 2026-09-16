---
name: secureaccess-netconf
description: Configure Cisco IOS XE Secure Access from public CSV through verified NETCONF validation and reviewed transactions, including VTI, static routes and PBR.
---

# Agent for SecureAccess

Use CSV as the default workflow; the conversational wizard is optional. Read
../../docs/csv-templates.md and ../../docs/netconf-apply.md. FTD templates are a
future FMC/FDM phase and must never generate IOS XE configuration or router I/O.

## Input and readiness

At the start of every CSV workflow, ask the user to choose **Basic** or **Advanced**.
Recommend Basic. Basic shows only deployment-specific decisions and applies the
built-in Cisco recommendations for omitted fields. Advanced exposes every supported
field and its recommendation. Do not create the CSV until the user selects a mode.

Create a template with create_configuration_csv and pass the selected mode. Read the locally filled
CSV and send its text to preview_configuration_csv. Return missing fields and
errors; do not invent headends, identities, crypto choices or interface selections.
Present row-specific validation errors with the accepted format, values, or range;
do not collapse them into a generic invalid-parameter response.
For multiple tunnel items, explain that blank source_interface, unnumbered_interface,
mtu, and tcp_mss values inherit from the first tunnel; report inherited_fields from
the preview. Never inherit interface_name, headend, local_identity, address, action,
or distance.
Template mode is offline. This test build accepts `connection.username` and
`connection.password` in CSV; the native login store remains optional. SSH
host-key verification is still mandatory. connection_status checks native readiness
only and does not inspect CSV credentials or prove live access.
This test build accepts tunnel PSKs in CSV. `psk_mode=shared` uses `shared_psk`;
`psk_mode=split` uses `local_psk` and `remote_psk`. `psk_format` accepts plain,
type6, or hex. Never echo PSKs in previews, diffs, diagnostics, or logs. The native
vault remains an optional alternative. Read ../../docs/platforms.md.

## Routing and Tunnel selection

For an enrolled router and authorized reading, use inventory_capabilities and
routing_summary. Show configured routes and operational RIB separately, default
route, interface masks and occupied Tunnel IDs. Errors/empty data mean unknown.
Preserve the actual management client return path and ISP/headend underlay. Never
infer ingress PBR interface from reverse static routes or assume EIGRP/NAT support.
The current enrolled target is dg-wi-r1 10.2.3.1; verify live capabilities.

PBR source_prefix rows identify SOURCE networks. destination_prefix rows identify
DESTINATION networks; 0.0.0.0/0 means any destination. bypass_prefix rows exempt
local/management destinations, plus headends. ACL deny means ordinary routing, not
dropping. normal-routing fallback and one VTI or an ordered primary/secondary VTI pair are
supported; tracking and fail-closed are not. The route-map tries tunnel interfaces
in CSV order. No ip local policy is generated.

Tunnel rows explicitly choose TunnelN and create/reuse. Tunnel1 has no hard-coded
preservation; preserve only user-selected other interfaces. Reuse requires current
versus proposed review, reuse_confirmed=true and exact change_scope. Matching
named objects are reused. Conflicts reject by default; existing_objects_action=
replace_named explicitly selects generated names for replacement, subject to the
exact public diff. Unrelated interfaces, keyring peers, management routes and the
ISP default remain untouched in PBR mode. Static protected routes overlapping
management are rejected. Reuse preserves unrelated interface/TCP/tunnel fields.

## Validation and application

The registered IOS XE native adapter is implemented for the shipped exact schemas.
validate_configuration_csv fetches current config into memory, checks model and
submodule compatibility, reconciles selected objects, and sends only the generated
patch through edit-config with test-option=test-only against running. RFC 6241
validate:1.1 requires test-only to test without applying the edit; re-read running
and require an unchanged digest. This works without candidate. Never validate by
round-tripping a complete get-config response. validate_adapter_fixture uses the
same nonproduction GCM/CBC test-only path and can never enter application. Offline
previews are review only. Acceptance is schema evidence, not live forwarding proof.
The digest excludes only the confirmed IOS XE retrieval artifact where test-only
causes an existing OpenConfig switched-vlan/config/native-vlan leaf to appear.
It also treats IOS XE's duplicated legacy aliases as equivalent only when their
values exactly match the canonical local-ip, tunnel-choice, profile-option/name,
or interface-list leaf. Native IOS XE and every Secure Access-managed value remains
strict.

prepare_configuration_apply uses candidate/confirmed-commit when available. On an
explicitly enrolled lab ISR without those capabilities, auto mode can prepare a
`lab-running` plan only when validate and rollback-on-error are advertised. Both
modes require the actual NETCONF client return address/RIB, source interface and a
matching CSV, device, or native-vault PSK. The tool returns the exact public diff, expiring
one-use plan ID and digest. Existing PSKs are preserved in memory and never
transferred implicitly to another headend.

Only invoke apply_configuration_plan after explicit user approval of that exact
diff/digest and an exclusive configuration window. It locks and rechecks running
and uses either the candidate transaction or the reviewed lab-running transaction.
Lab-running uses `test-then-set`, `rollback-on-error`, a generated inverse patch, and
post-write nonsecret state verification. A configuration may remain present with
`applied_operational_pending` so traffic can bring up the SA; it is never reported as
operationally verified until VTI/IKEv2/IPsec/counter/underlay/management checks pass.
Uncertain transactions are never automatically retried.
Running-to-startup persistence is separate.

Do not bypass these gates with arbitrary XML/RPC, generic SSH or CLI.
Do not expose raw running config, private XML, PSKs, exception messages or RPC logs.
Unit tests do not prove hardware application. If the loaded MCP tools predate an
update, state the limitation and follow the user's installation timing preference.
