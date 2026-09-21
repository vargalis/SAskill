# SecureAccess skill: complete operator guide

[Русская версия](user-guide.ru.md) · [README](../README.md) · [Transaction reference](netconf-apply.md)

This guide describes the code in this repository. The skill is `secureaccess-netconf`; the plugin is **Agent for SecureAccess**. The skill guides the conversation, while the local MCP server connects to the router. Both are required for the complete workflow. OpenAI describes this packaging in its [plugin architecture documentation](https://developers.openai.com/plugins/concepts/plugins).

The workflow is: prepare access → install → enroll the SSH key → discover → choose a CSV mode → fill and preview → validate on the device → prepare a plan → approve and apply → verify and separately save.

## 1. Before starting: scope and information to collect

The implementation supports IPv4 Cisco IOS XE IKEv2/IPsec, selected VTI interfaces, static routes and PBR. Compatibility requires the exact shipped YANG schemas, not merely an IOS XE version or router family. FTD/FMC/FDM is **template planning only**. The legacy YAML CLI and optional wizard do not apply configuration.

Prepare the following with the network owner:

| Information | Required decision or evidence |
| --- | --- |
| Target | Router inventory name and management IPv4 address; NETCONF TCP port is fixed at 830 in the MCP server. |
| Access | NETCONF username/password, permission to read schemas/configuration/operational state, and permission for the transaction RPCs when applying. |
| Trusted identity | Router SSH SHA256 host-key fingerprint from an independently trusted administrator or console. |
| Secure Access assignment | Assigned headend IPv4 address, local Tunnel ID/email, PSK and matching crypto settings for each tunnel. The skill does not provision these in the Secure Access portal. |
| Underlay | ISP gateway, actual source interface, source IPv4 address, existing routes, NAT/firewall behavior and headend reachability. |
| Management | Prefixes covering the actual NETCONF client's return address, plus observed global routing-table paths. |
| Traffic selection | Destination prefixes; for PBR, source prefixes, actual LAN ingress interfaces, explicit bypass destinations and acceptance of normal-routing fallback. |
| Interfaces | Unused `TunnelN` for create, or an explicitly reviewed existing interface for reuse; numbered VTI address or an unnumbered interface. |
| Change control | Configuration backup through your approved process, recovery/console access, exclusive change window, and a test host that can generate matching traffic. |

Do not use example addresses, example passwords or fixture PSKs as deployment values. Store the filled CSV outside this repository in a private location.

### Current limitations that affect preparation

- The CSV importer currently requires `connection.username`, `connection.password`, `psk_mode`, `psk_format`, and the corresponding nonempty PSK values. Vault-only or existing-device-only credentials are **not a complete CSV path in this build**, even though the adapter supports those sources internally.
- Secret values in CSV are passed as tool input. Redacted output does not make the CSV or the conversation/tool input secret-free. Use this test workflow only where that handling is permitted. If your policy forbids it, stop before submitting the file; the importer needs a code change for a vault-only workflow.
- Basic mode is suitable for PBR. For static routing, choose **Advanced** and leave PBR-only fields blank. Basic currently inserts `pbr.failure_behavior=normal-routing`, which causes a static CSV to fail validation.
- No automatic management or headend PBR exemptions are added. Enter required destinations explicitly as `bypass_prefix` rows.
- Apply prechecks require the client's local socket IPv4 address to belong to a management prefix, an exact operational route for each management prefix with a next-hop address, and non-tunnel return/ISP paths. A default route alone, a directly connected management route without a next-hop address, client-side NAT, or a different VRF may not satisfy these checks. Do not invent routes to make the checks pass; resolve the topology/support limitation first.
- PBR supports one tunnel or an ordered pair, with `normal-routing` fallback. There is no tracking or fail-closed mode. Static routing supports up to eight tunnels, but protected prefixes must not overlap management prefixes; therefore a protected static default route is rejected.
- Unrelated NAT, AAA, firewall policy, BGP, licensing, router bootstrap and running-to-startup persistence are outside the generated configuration.

## 2. Prepare the router and workstation

Have an authorized router administrator establish management addressing, working SSH, an appropriate NETCONF account/AAA policy, NETCONF on TCP 830, and read access to the required YANG and operational models. Use a device-specific bootstrap procedure; this skill does not install NETCONF or replace AAA. Keep an existing administrative session or console available while proving the new access.

Prepare network reachability from the machine running the local MCP server. Verify the tunnel underlay, site firewall/NAT policy and Secure Access assignment through your normal network procedures. Obtain a fresh backup before the change.

On the workstation, install Python **3.11+**, a Codex CLI with plugin support, and the bundled `plugin-creator` helper scripts. The repository installer expects these helpers at `$CODEX_HOME/skills/.system/plugin-creator/scripts`, or `~/.codex/skills/.system/plugin-creator/scripts` when `CODEX_HOME` is unset. It also needs package-download access. Run as the same normal OS user who will run Codex, not as root/Administrator.

The login vault uses macOS Keychain, Windows Credential Manager or Linux Secret Service. Linux needs an accessible, unlocked user secret service for vault operations; there is no file fallback.

## 3. Install the plugin

Open a terminal in the repository root. Check prerequisites and install:

**macOS/Linux**

```sh
python3 --version
codex --version
python3 scripts/install_local.py
```

**Windows PowerShell**

```powershell
py -3 --version
codex --version
py -3 scripts/install_local.py
```

If Codex is not on PATH, pass `--codex "/absolute/path/to/codex"` (or the Windows path to `codex.exe`). `scripts/windows-install.ps1` is an optional Windows wrapper for the same installer.

The installer copies the project to `~/plugins/agent-for-secureaccess`, creates a virtual environment at `~/plugins/.runtimes/agent-for-secureaccess`, installs dependencies and the editable Python package, updates the plugin version, writes the local MCP launch configuration, and registers the plugin in the personal marketplace. On Windows, `~` means the user profile directory.

Expected result: `Installed... Open a new Codex task.` If the installer reports missing helpers, a marketplace source mismatch or an incomplete target, resolve that specific condition before retrying. A plain wheel installation or copying only `SKILL.md` does not reproduce this setup: the MCP entry point needs the repository's `scripts` directory.

## 4. Set the target, credentials and trusted SSH key

Use the installed runtime for all helper commands. Replace the documentation address and username below with your own values.

**macOS/Linux**

```sh
export SECUREACCESS_HOST="192.0.2.10"
export SECUREACCESS_USER="secureaccess-agent"
SA_PLUGIN="$HOME/plugins/agent-for-secureaccess"
SA_PY="$HOME/plugins/.runtimes/agent-for-secureaccess/bin/python"
"$SA_PY" "$SA_PLUGIN/scripts/setup_local.py" host-key
"$SA_PY" "$SA_PLUGIN/scripts/setup_local.py" password
"$SA_PY" "$SA_PLUGIN/scripts/diagnose_connection.py"
```

**Windows PowerShell**

```powershell
$env:SECUREACCESS_HOST = "192.0.2.10"
$env:SECUREACCESS_USER = "secureaccess-agent"
$saPlugin = Join-Path $env:USERPROFILE "plugins/agent-for-secureaccess"
$saPython = Join-Path $env:USERPROFILE "plugins/.runtimes/agent-for-secureaccess/Scripts/python.exe"
& $saPython "$saPlugin/scripts/setup_local.py" host-key
& $saPython "$saPlugin/scripts/setup_local.py" password
& $saPython "$saPlugin/scripts/diagnose_connection.py"
```

The host-key action fetches the offered public key without authenticating, then asks you to paste the SHA256 fingerprint obtained independently. It writes `[host]:830` to your `~/.ssh/known_hosts` only on a match. Do not copy the displayed offered fingerprint back as if it were independently verified. Existing differing keys require a reviewed key-rotation procedure.

The password action prompts without echo and saves the login password in the OS vault. This is needed for discovery tools: `inventory_capabilities`, `routing_summary`, `configuration_summary`, the fixture probe and the connection diagnostic do not accept CSV credentials. `connection_status` checks local enrollment only; it does not prove a live connection. Look for `netconf_connected: true` in the diagnostic, then inspect the returned capabilities.

Optional native PSK enrollment:

```sh
# macOS/Linux
"$SA_PY" "$SA_PLUGIN/scripts/setup_local.py" tunnel-psk
```

```powershell
# Windows PowerShell
& $saPython "$saPlugin/scripts/setup_local.py" tunnel-psk
```

It asks for tunnel number, headend, shared/split keys and key format. Repeat for each tunnel. This does **not** remove the current CSV PSK requirement. CSV keys take precedence during the CSV apply workflow. `tunnel_psk_status` reports vault presence only, not whether the CSV or device PSK is correct.

For login on headless systems, the code also supports `SECUREACCESS_SECRET_PROVIDER=environment` with `ISR_PASSWORD` injected by your process secret manager and `SECUREACCESS_USER` set. This is a login-password provider, not an environment provider for tunnel PSKs. Do not put secret literals in shell history or source control.

### Make the environment available to Codex

The variables above affect only that shell and its child processes. Start `codex` from that configured shell for the CLI workflow. A desktop app that was already running will not acquire them automatically: supply the variables to its actual launch/MCP environment through your local configuration, restart it, and verify the target with `connection_status` before connecting. The installer does not persist the target or username for you.

Restart the MCP server after changing target/environment, updating code or rotating stored credentials. Open a new task and confirm the expected skill and tools are available. Prepared plans are lost on server restart. The server is configured for one target at a time; the CSV host must equal `SECUREACCESS_HOST`.

## 5. Start the skill and collect fresh inventory

Example request in Codex:

> Use the secureaccess-netconf skill. Prepare Cisco IOS XE Secure Access for my enrolled router. Start with read-only discovery and ask me to choose Basic or Advanced. Do not apply until I approve the exact prepared diff and digest.

Allow read-only access to the intended router. Ask for `connection_status`, `inventory_capabilities`, `routing_summary`, and, when needed, `configuration_summary`. Review:

1. Correct target and working NETCONF login.
2. Advertised models/capabilities and observed operational data.
3. Source interface and its IPv4 address, ISP gateway, default route and management return path.
4. Occupied tunnel IDs and the exact interfaces you intend to create or reuse.
5. Existing ingress policies and generated object names that could conflict.

Configured routes and the operational RIB are different evidence. Empty or failed reads mean unknown, not permission to guess. Sanitized summaries do not expose all settings needed for tunnel reuse; obtain an authorized sanitized current-versus-proposed review where necessary.

Offline template preparation may proceed without router access, but device validation and application cannot.

## 6. Choose, fill and preview the CSV

Choose **Basic** or **Advanced** before creation. Basic hides built-in values; Advanced exposes them. Request `create_configuration_csv` with `platform="iosxe"`, the chosen `mode`, and the confirmed device name/host. Save a private copy outside the repository. Files in `examples` illustrate the format and are not ready-to-apply configurations.

Preserve the header `section;item;field;value;required;description`, semicolon delimiter and UTF-8 encoding (BOM accepted). Normally edit only `value`. Replace every `<<< REQUIRED >>>`. Never translate field names or enum values. To add networks, duplicate a list row with a new positive `item`; to add tunnels, duplicate the complete tunnel group. Keep descriptions and `required` cells present. Changing `required` to `no` does not override validation. Do not use formulas.

| CSV group | What to enter/check |
| --- | --- |
| `meta`, `device` | Schema `2`, platform `iosxe`, selected mode, inventory name, exact enrolled host. |
| `connection` | Actual username and password; both currently mandatory. |
| `network` | `pbr` or `static`, ISP gateway, `router_wan_ip` matching the selected source interface, generated-name prefix. Leave object action blank/`reject` initially. |
| `management_prefix` | Management CIDRs covering the real client return path; not `0.0.0.0/0`. |
| `destination_prefix` | Protected destination CIDRs. In PBR, `0.0.0.0/0` means any destination for selected sources. |
| `source_prefix`, `ingress_interface` | PBR source LANs and interfaces where that traffic actually enters. Do not infer ingress from a reverse route. |
| `bypass_prefix` | Optional explicit PBR destination exemptions. Deny entries mean ordinary routing, not dropping. Blank rows add no exemption. |
| `pbr` | `failure_behavior=normal-routing` for PBR. For static, leave this and all source/bypass/ingress values blank. |
| `tunnel` identity/selection | `TunnelN`, `create` or `reuse`, assigned headend and local identity. Reuse also needs `reuse_confirmed=true` and a specific `change_scope`. |
| `tunnel` addressing | Existing source interface; exactly one of VTI `address` or `unnumbered_interface`. New source loopbacks, when deliberately requested, use `/32`. |
| `tunnel` secrets | `shared` with `shared_psk`, or `split` with both `local_psk` and `remote_psk`. Format `plain`, `type6` or `hex`; one selected format applies to both split keys. Type 6 means an already encrypted value suitable for the target, not plaintext to encrypt. |
| `crypto`, MTU/MSS/distance | Match the assigned tunnel policy. CSV allows MTU 576–1390, MSS 536–1350 and MSS ≤ MTU−40; distance 1–254. CBC requires integrity; GCM requires it blank. |

Basic's inserted values include prefix `sse`, GCM-256, PRF SHA256, DH 19/20, ESP GCM-256, no PFS, IKE lifetime 14400, IPsec lifetime 3600, DPD 10/3, MTU 1390, MSS 1350 and distance 1. Review these against your assignment; they are repository defaults, not proof of suitability for every deployment.

For later tunnel items, blank `source_interface`, `unnumbered_interface`, `mtu` and `tcp_mss` inherit from the first item. Tunnel number, headend, identity, numbered address, action and distance do not inherit. In PBR the numeric item order selects primary then secondary; `distance` does not control PBR order.

Ask Codex to read the private file and call `preview_configuration_csv`, optionally with fresh occupied tunnel IDs. Proceed only when `valid=true`; resolve `missing_fields` and row-specific `errors`, inspect `inherited_fields`, and review the public model and CLI/XML previews. `apply_ready=false` is normal for this offline step. Never execute the preview as a router CLI script.

## 7. Validate the proposed configuration on the device

Request `validate_configuration_csv` for the same filled CSV. It uses the CSV login, verifies the enrolled host, refreshes tunnel inventory, checks the seven exact model/submodule hashes in [profile.json](../backend/secureaccess/schemas/profile.json), reconciles selected objects, and sends a generated patch with NETCONF `edit-config` **`test-option=test-only`** against running. It does not commit or apply the patch.

Expected result: `validated=true`, `schema_validated=true`, `device_written=false`, and a sanitized diff. This is schema acceptance, not operational readiness. `transaction_ready` describes candidate/confirmed-commit availability; `false` does not by itself rule out lab-running. The standalone validation path does not do a post-test running digest check; preparation/build performs the before/after and stable-baseline checks.

Conflicts reject by default. If generated named objects must change, select `existing_objects_action=replace_named` in Advanced only after reviewing their use and desired change, then preview and validate again. This does not permit deleting unrelated next hops: a protected static prefix with competing forwarding entries is blocked even with `replace_named`; reconcile that conflict separately through an approved change. Management routes and unrelated keyring peers are preserved.

A schema mismatch requires a supported, tested adapter/profile update. Do not change hashes or disable checks to force compatibility. The prechecks also require operational revisions `Cisco-IOS-XE-interfaces-oper@2021-03-01`, `Cisco-IOS-XE-crypto-oper@2021-03-01` and `ietf-routing@2015-05-25`.

Optional local validation (same target environment, no application):

```sh
"$SA_PY" "$SA_PLUGIN/scripts/validate_csv.py" "/private/path/deployment.csv"
"$SA_PY" "$SA_PLUGIN/scripts/validate_adapter.py"
```

```powershell
& $saPython "$saPlugin/scripts/validate_csv.py" "C:\private\deployment.csv"
& $saPython "$saPlugin/scripts/validate_adapter.py"
```

The second command uses stored login credentials and nonproduction GCM/CBC fixtures. It is optional schema diagnosis, not a substitute for validating your CSV or testing real traffic. Sanitized fixture diagnostics are available through `validate_adapter_fixture(debug=true)`.

## 8. Prepare, review and approve the transaction

Request `prepare_configuration_apply` with the validated CSV and an intentional `transaction_mode`:

| Mode | Behavior |
| --- | --- |
| `candidate` | Requires candidate, validate and confirmed-commit. Fails if unavailable; use when fallback is not acceptable. |
| `lab-running` | Requires validate and rollback-on-error; directly edits running under lock during apply. Choose only for the reviewed lab procedure. |
| `auto` (default) | Chooses candidate when those capabilities exist; otherwise may choose lab-running. Always inspect the returned mode. |

The adapter requires validate **1.1** for its test-only checks in either mode. Preparation rechecks source addressing, management/ISP paths, available PSKs, schemas, conflicts and a stable running baseline. It does not apply configuration.

Proceed only with `apply_ready=true`. Review **this exact returned diff**, target, transaction mode, `plan_id`, `approval_digest` and expiry. Check tunnel reuse, shutdown removal on selected reused tunnels, crypto changes, PSK replacement/preservation intent, ACL bypass order, route-map attachment and every route. Secret values are omitted from the diff; independently confirm that the input keys belong to the intended tunnel/headend.

Plans live only in the current MCP process, expire after **900 seconds**, and are one-use. Editing the CSV, changing router configuration or restarting the server requires a fresh preparation and approval. `No reconciled changes to apply` means no new configuration transaction is needed; it does not prove that existing traffic works.

Arrange an exclusive window with other operators and automation stopped. Keep recovery access and matching test traffic ready. Explicitly approve the returned diff/digest and the window, for example:

> I approve the exact displayed diff for plan `<plan_id>` and digest `<approval_digest>` on the displayed target, using `<transaction_mode>`. The exclusive configuration window is active. Apply that plan once.

Replace the placeholders with the actual returned identifiers. Template creation, preview, validation and tunnel reuse confirmation do not authorize application.

## 9. During application

Codex calls `apply_configuration_plan(plan_id, approval_digest, exclusive_window=true)`. Defaults are `confirm_timeout=180` and `postcheck_budget=60` seconds. The MCP tool requires a postcheck budget of 30–300 seconds, a confirmation timeout of at most 600 seconds, and at least 60 seconds between budget and timeout; this input check also applies to lab-running.

Keep the MCP process and session alive and do not run competing configuration commands. Generate authorized traffic from the selected source through the intended ingress to a protected destination so the tunnel can establish and counters can become nonzero.

- **Candidate:** locks running and candidate, rejects a dirty candidate, rechecks the baseline, stages/validates the approved patch, performs a nonpersistent confirmed commit, and only confirms permanently after bounded postchecks pass. Failure before confirmation attempts rollback and reconnect verification. A final commit timeout is uncertain and is not retried.
- **Lab-running:** locks running, rechecks the baseline, uses `test-then-set` with `rollback-on-error`, and verifies the resulting nonsecret configuration. Failed/uncertain writes or configuration verification attempt the owned inverse patch. Once configuration is verified, failed or timed-out operational checks leave it present as `applied_operational_pending`. There is **no confirmed-commit timer** in this mode.

Postchecks examine selected tunnel state, nonzero input/output counters, headend IKEv2 and bidirectional ESP SAs, underlay/management routes and expected configuration. Static routing also requires the intended active tunnel forwarding without competing outgoing interfaces. These observations do not replace application testing or a measured failover test.

## 10. After application: decide from the result

| Result | Required next action |
| --- | --- |
| `status=applied`, `applied=true` | Configuration passed the mode's checks. Lab-running additionally reports `configuration_verified` and `operational_verified`. Perform independent service and management checks before separately saving startup configuration. |
| `applied_operational_pending` | Lab-running configuration remains installed. Investigate headend/PSK/traffic/SA/routing, test again through approved operational tools, or perform an approved recovery. Do not claim success or replay the plan. |
| `failed` | Inspect `error`, diagnostic stage and `rollback_status`; failure does not prove restoration. Use recovery access if needed. |
| `uncertain` or `final_commit_uncertain_manual_attention` | Stop retries. Determine the actual router state through authorized reads/console before any new plan. |
| Rollback `verified`, `staged_cleanup_verified`, `owned_inverse_verified` | These refer to different scopes: reconnected running, candidate cleanup, or nonsecret inverse verification. Confirm the affected service separately. Other rollback statuses do not establish verified restoration. |

After a successful change, check real application traffic, intended egress, management access, explicit PBR bypasses, normal-routing fallback and unaffected networks. Interface counters are observed totals, not a fresh before/after traffic measurement. A separate device/portal operational check is needed for a pending result; this MCP server has no dedicated “re-run postchecks for this plan” tool.

Every apply result concerns **running configuration only** (`startup_persisted=false`). Save running to startup only after acceptance, using your separate authorized router procedure; the plugin does not perform that operation. Keep a sanitized change record with target, diff, mode, result and verification evidence. Handle or remove the private CSV according to your credential policy.

## 11. Troubleshooting and repeat use

| Symptom | What to do |
| --- | --- |
| Skill/tools missing or old tools loaded | Finish installation, restart/reload the plugin and open a new task. Check the installed source/runtime, not just this checkout. |
| Host unset or CSV target differs | Set the target in the actual MCP process environment; use the same IPv4 address in the CSV and restart. |
| Vault unavailable/password missing | Run setup as the same user as Codex, unlock the OS vault, or configure the explicit login environment provider. CSV login does not supply discovery-tool credentials. |
| Host key unknown/changed | Verify independently and enroll/review rotation. Never turn off host-key verification. |
| Basic + static rejected | Generate Advanced; leave PBR failure behavior and source/bypass/ingress fields blank. |
| Management or WAN precheck fails | Inspect actual client address, exact global management routes, next-hop evidence, source IP and interface state. Resolve the real topology or adapter limitation. |
| Existing object/route conflict | Review affected objects. `replace_named` is a deliberate named-object choice; competing static next hops require a separate change. |
| Candidate dirty or lock denied | Coordinate with its owner; do not discard another operator's changes. |
| Plan expired, consumed or baseline changed | First establish current state, then prepare and approve a new plan. Never replay an uncertain attempt. |
| Schema/operational model mismatch | Stop application; collect sanitized inventory for a supported adapter update. |

For an update, run `scripts/install_local.py` again from the updated repository under the same user (or the Windows update wrapper), then restart the plugin and use a new task. The installer preserves OS credentials and known_hosts but rewrites its generated MCP launch file. Recheck environment configuration and revalidate before applying; do not reuse old plans.

Optional developer checks from the repository root, using a runtime with test dependencies installed:

```sh
python -m unittest discover -s tests -q
python -m pytest -q
```

Unit tests cover local behavior; they do not qualify real hardware, forwarding or rollback. Historical design documents are background only. The operational procedure is this guide and the [current transaction reference](netconf-apply.md).
