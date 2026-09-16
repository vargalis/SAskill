# CSV configuration templates

Schema version 2 input is UTF-8 BOM CSV with semicolon delimiter and columns
section;item;field;value;required;description. Fill value only. For multiple
networks, copy a list row and assign a distinct positive item number. For
multiple tunnels, copy its field group with a distinct item. Never use formulas
or router password fields. The IOS XE test template includes redacted PSK input
fields. Required flags are explanatory, not validation authority.

Agent creates CSV, prefills ONLY user-confirmed values and sanitized authorized
live discovery. Label observed/suggested values in descriptions; do not assume
source interfaces, WAN IP, crypto defaults, bypass sets or fallback confirmation.
For dg-wi-r1 sources are the five 10.10.* /24 static-route networks, destination
is 0.0.0.0/0, ISP gateway is 192.168.2.1, management is 10.10.10.0/24.
TunnelN and create/reuse are explicit choices; Tunnel1 is not hard-coded.
`network.router_wan_ip` is the selected tunnel source interface IPv4 address and
is rendered as `crypto ikev2 policy ... match address local`. In PBR mode, one or
two tunnel row groups are accepted; their item order defines primary then secondary.

Read the completed file locally and submit its text to preview_configuration_csv.
The tool is stateless/offline and never reads paths or opens a network session.
Pass fresh occupied tunnel IDs from separate authorized routing_summary.
Blank required values produce missing_fields, unknown keys/duplicate rows and
invalid topology produce errors. Do not send secret-containing files to a tool.
Nonblank values are validated before rendering. Errors include the CSV row,
section, item, field, accepted format or values, and allowed numeric range. Checks
cover IPv4/CIDR syntax, interface names, enum choices, crypto compatibility,
lifetimes, MTU/MSS, tunnel identity, duplicate list values, and reuse controls.

Before creating a template, ask the user to choose Basic or Advanced. Basic is
recommended and omits fields with built-in Cisco defaults. Advanced includes every
supported field. The selected mode is recorded in meta.template_mode. A Basic CSV
expands to the same complete validated model by inserting the documented defaults;
it does not weaken validation or authorize device changes.

For multiple tunnel item groups, enter common values in the first tunnel. Blank
source_interface, unnumbered_interface, mtu, and tcp_mss fields in later tunnel
items inherit the first tunnel value. Unique or topology-sensitive fields such as
interface_name, headend, local_identity, numbered address, action, and distance do
not inherit. The preview reports every inherited field.
For reuse inspect current vs proposed parameters before reuse_confirmed=true.
CSV does not establish a reconciled baseline or qualified device diff.

Present the imported public spec and CLI/XML previews, then collect any required
plan confirmation. Do not apply automatically on file import. No device apply
tool exists: transaction and qualified schemas/rollback remain required.
FTD CSV is a separate future planning template (manager type, manager host,
device identifier/version/template name). It never produces IOS XE config and
does not imply FMC/FDM API support. Implement FTD templates and adapter only
after selecting manager/version and discovering actual capabilities.


Current application workflow: see [netconf-apply.md](netconf-apply.md). `validate_configuration_csv` checks inline config without edits, then `prepare_configuration_apply` / `apply_configuration_plan` use a reviewed one-use transaction. Conflicts default to rejection; `existing_objects_action=replace_named` explicitly selects generated named objects for replacement.
