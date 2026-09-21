# CSV → IOS XE NETCONF: current transaction reference

Complete procedures: [English](user-guide.en.md) · [Русский](user-guide.ru.md).
This page describes the current implementation, not a hardware qualification report.

## Scope and entry points

The registered native adapter renders IKEv2 proposal/policy/keyring peer/profile,
IPsec transform/profile, selected Tunnel interfaces, optional source Loopback,
static routes, PBR ACL, route-map and ingress policy attachment. Exact schema
hashes are in [profile.json](../backend/secureaccess/schemas/profile.json).
FTD/FMC/FDM remains planning-only. The legacy YAML CLI does not apply changes.

| Tool | Effect and interpretation |
| --- | --- |
| `connection_status` | Local target, vault and known_hosts readiness; no live connection. |
| `inventory_capabilities`, `routing_summary`, `configuration_summary` | Read-only router discovery using stored/environment login credentials. |
| `create_configuration_csv`, `preview_configuration_csv` | Offline template and input validation; no device I/O. |
| `tunnel_psk_status` | Native-vault presence for CSV tunnel identities, not authentication proof. |
| `validate_configuration_csv` | Reconciles the CSV and sends a generated patch with `edit-config(test-option=test-only)`; no commit/application. |
| `validate_adapter_fixture` | Optional GCM/CBC nonproduction test-only probes. Fixtures cannot enter build/apply. |
| `prepare_configuration_apply` | Checks prerequisites, validates the patch, verifies stable running and stores a private one-use plan. |
| `apply_configuration_plan` | Mutates only after explicit exact-plan approval and an exclusive window. |

## Input, secrets and qualification

The current test CSV importer requires login credentials and shared or split PSKs.
Native-vault/device-secret support exists in the adapter but does not remove those
CSV requirements. Values in the input file and MCP arguments remain sensitive even
though generated outputs are redacted. See the guides before handling real secrets.

Schema qualification checks the seven shipped exact model/submodule digests through
`get-schema` and requires validate:1.1. Test-only checks the generated patch against
the device's schema constraints. Matching a platform name or version is insufficient.

`validate_configuration_csv` reads running for reconciliation and sends only the
patch with `default-operation=merge`, `test-option=test-only`, and
`error-option=stop-on-error`. It does not round-trip the complete get-config tree.
The standalone validation method does not re-read a running digest after this RPC.
`build`, used during prepare/apply, does compare before/after running digests;
prepare additionally checks that its initial baseline remains stable.

Fingerprints normalize the known OpenConfig native-vlan retrieval artifact and
exactly equivalent IOS XE legacy aliases. Nonsecret verification excludes secret
nodes; it is not proof that a newly supplied key authenticates successfully.

Apply prechecks require the actual client's local IPv4 socket address within a
reviewed management prefix, exact global operational routes with next-hop evidence
for management prefixes, non-tunnel return/ISP paths, source state/address and PSK
availability. Required operational models/revisions are interfaces-oper 2021-03-01,
crypto-oper 2021-03-01 and ietf-routing 2015-05-25. Unknown evidence blocks.

## Reconciliation and conflict handling

Tunnel create/reuse is checked against fresh inventory. Reuse needs a reviewed
change scope and retains unrelated interface/TCP/tunnel fields; shutdown is removed
on the selected reused tunnel. Generated named objects must match or have the
explicit `existing_objects_action=replace_named` choice and a reviewed exact diff.
Unrelated interfaces, keyring peers and management routes are preserved.

PBR bypasses are explicit CSV destinations, never automatically inferred. ACL
sequence reuse must preserve unique keys and desired evaluation order; otherwise
rules are resequenced. The patch and inverse reconcile keyed ACEs, including stale
rules, rather than replacing a referenced ACL root.

Static protected prefixes overlapping management are rejected, including default
routes. Existing forwarding entries for a protected prefix must belong to the
selected tunnel set. Competing next hops require a separate approved change, even
when `replace_named` is selected. PBR leaves existing static/default routes alone
apart from the generated headend underlay routes.

## Preparation and approval

Plans expire after 900 seconds, live only in the MCP process and are one-use after
consumption. They contain the private payload, baseline and specification. Public
results contain target, redacted diff, plan ID, approval digest and transaction mode.
A restart loses plans. Drift, input changes, expiry or uncertainty requires current
state inspection and a new plan/approval, not replay.

`auto` prefers candidate, then falls back to lab-running when its capabilities are
available. Select `candidate` explicitly when fallback is unacceptable. Inspect
`transaction_mode` before approval. A successful standalone test-only validation
is not authorization to apply. The exclusive window must cover other operators,
CLI writers and automation as well as this NETCONF session.

## Candidate mode

Requires candidate, validate and confirmed-commit, plus adapter qualification.
The engine locks running and candidate, checks baseline and clean candidate,
rechecks prerequisites, rebuilds/test-validates the patch, stages it, verifies the
candidate and validates it. A nonpersistent confirmed commit starts operational
checks; only success leads to final commit.

Before commit, only verified owned staged changes may be discarded. After the
initial commit but before final confirmation, failure attempts cancel/close and
reconnect comparison. A failed/uncertain final commit is never automatically
cancelled or replayed; it requires manual state inspection. Do not equate an
attempted rollback with `rollback_status=verified`.

## Lab-running mode

Requires validate and rollback-on-error, plus adapter qualification. Under running
lock, the engine rechecks baseline/preconditions, rebuilds the patch and sends
`edit-config(test-then-set, rollback-on-error)`. Failed or uncertain edits or failed
configuration verification attempt an owned inverse patch. Inspect its reported
verification status; rollback is not guaranteed by an RPC attempt.

After nonsecret running verification succeeds, operational failure/timeout leaves
the configuration installed as `applied_operational_pending`. There is no timed
confirmed-commit rollback. Investigate and verify the service separately, or use
an approved recovery procedure. This server has no dedicated postcheck-retry tool.

## Postchecks, timeouts and persistence

Postchecks examine expected nonsecret running, tunnel admin/oper state and nonzero
input/output counters, headend IKEv2 and inbound/outbound ESP SAs, headend underlay
through the ISP and management routes. Static active forwarding must use exactly
the expected active tunnel set, without extra outgoing interfaces. Counter totals
are not a measurement of fresh traffic, and these checks do not establish every
application, NAT or failover behavior.

MCP defaults: confirm timeout 180 seconds, postcheck budget 60 seconds. The MCP
wrapper accepts a budget of 30–300 seconds, timeout at most 600 seconds and at
least 60 seconds of margin. This wrapper validation also applies to lab-running.

`applied` means success for the implemented mode's checks; `applied_operational_pending`
means installed but not operationally verified. `failed` and `uncertain` require
inspection of error/rollback status and actual state. Do not replay a consumed plan.
All results concern running only: `startup_persisted=false`. Saving to startup is
an independent authorized operation after acceptance.

Local tests cover reconciliation and mocked transaction behavior. They do not prove
hardware schema acceptance, live forwarding, rollback or persistence on a deployment
router. Gather fresh evidence for that device; old task-specific observations are
not current readiness evidence.
