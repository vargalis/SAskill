# CSV configuration reference

Full instructions: [English](user-guide.en.md) · [Русский](user-guide.ru.md).

## Format and modes

Use schema version `2`, UTF-8 (BOM accepted), semicolon delimiter, and exactly:

```text
section;item;field;value;required;description
```

Choose Basic or Advanced before requesting `create_configuration_csv`. Basic hides
built-in values; Advanced exposes them. Edit `value`, preserve field names and
enums, and replace `<<< REQUIRED >>>`. Keep `required` as yes/no and descriptions
nonempty. Required flags are explanatory; the importer enforces its own rules.
Formulas in nonsecret fields, unknown fields and duplicate field keys are rejected.

Lists use positive, unique item numbers. Copy a complete tunnel field group for
another tunnel. PBR supports one or two tunnels in numeric item order; static
supports up to eight. Examples are illustrative and must not be applied unchanged.

**Current Basic/static limitation:** Basic inserts `pbr.failure_behavior=normal-routing`
even with static mode, which the importer rejects. Use Advanced for static and
leave PBR failure behavior plus source/bypass/ingress values blank.

## Secrets in the current test build

`connection.username` and `connection.password` are required. Each tunnel requires
`psk_mode` and `psk_format`; shared mode requires `shared_psk`, while split requires
both `local_psk` and `remote_psk`. Format is plain, type6 or hex, common to both split
keys. CSV input is sensitive and is passed to MCP tools. Output redaction does not
redact the source file or make tool inputs secret-free. Keep filled files outside
source control and follow the handling requirements in the guides.

The adapter supports vault/device keys internally, but the current importer does
not provide a vault-only CSV path. Changing the required column does not bypass it.
Discovery tools separately need stored/environment login credentials.

## Routing, interfaces and inheritance

`source_prefix` identifies PBR sources; `destination_prefix` identifies destinations.
Destination `0.0.0.0/0` means any destination for matching PBR sources. Optional
`bypass_prefix` destinations create deny entries before permits: deny means normal
routing, not dropping. No management/headend bypass is inserted automatically.
The only fallback is `normal-routing`; tracking/fail-closed are unsupported.

`network.router_wan_ip` must match the selected tunnel source interface address.
Tunnel selection is explicit `TunnelN` plus create/reuse. Reuse additionally needs
`reuse_confirmed=true` and a reviewed `change_scope`; it does not authorize apply.
Choose exactly one numbered `address` or `unnumbered_interface`. New source loopback
addresses must use /32. CSV MTU is 576–1390, MSS 536–1350 with MSS ≤ MTU−40.

Later tunnel items inherit blank source_interface, unnumbered_interface, mtu and
tcp_mss from the first item. They do not inherit tunnel number, headend, identity,
numbered address, action or distance. Review `inherited_fields` in the result.

Static protected prefixes cannot overlap management prefixes. Competing configured
next hops for a protected prefix are rejected during device reconciliation and
require a separate approved change; replace_named does not override this gate.

## Preview, validate and apply

Read the completed local file and pass its text to `preview_configuration_csv`;
the tool accepts text, not a filesystem path. Supply fresh occupied tunnel IDs when
available. Resolve `missing_fields`, row-specific `errors` and reported inheritance.
Review the public spec and previews; offline `apply_ready=false` is expected.

Next use `validate_configuration_csv` (generated patch, NETCONF edit-config test-only),
then `prepare_configuration_apply` and explicit exact-diff/digest approval before
`apply_configuration_plan`. See [transaction details](netconf-apply.md).
Matching objects are reused; differences reject unless the operator deliberately
selects `existing_objects_action=replace_named` and reviews the resulting diff.

FTD templates contain manager type/host, device ID, version and template name only.
They do not generate IOS XE configuration, connect to an FTD manager or apply policy.
