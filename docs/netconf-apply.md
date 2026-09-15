# CSV → IOS XE NETCONF

The IOS XE native VPN/PBR adapter is implemented and registered. It covers IKEv2
proposal/policy/keyring peer/profile, IPsec transform/profile, selected TunnelN,
source Loopback, static routes, extended PBR ACL, route-map and ingress attachment.
CSV is the default input; no wizard is required. FMC/FDM templates remain a later phase.

## Workflow

1. Fill the public CSV; `preview_configuration_csv` validates its structure.
2. `validate_configuration_csv` fetches current config only in memory, checks exact
   seven model/submodule digests from dg-wi-r1, reconciles each selected object and
   sends the complete proposed datastore as inline `validate` source (NETCONF 1.1).
   This does not call edit-config or commit and works without candidate.
3. `prepare_configuration_apply` additionally checks management client return
   address, global operational RIB, ISP gateway/source interface, pre-provisioned
   peer PSKs and transaction capabilities. It returns the exact public diff and
   one-use plan/digest. The secret-bearing payload is private for 15 minutes.
4. After explicit approval of that exact diff and an exclusive change window,
   `apply_configuration_plan` locks running/candidate, rechecks baseline/clean
   candidate, rebuilds and inline-validates, stages only selected atoms, checks the
   complete candidate, validates candidate and sends a nonpersistent confirmed commit.
5. Bounded postchecks verify selected VTI admin/oper state, observed input/output
   counters, exact headend IKEv2 SA and inbound/outbound ESP SAs, global headend
   routing through the ISP, preserved management path and complete expected config.
   Only success triggers final commit. Failure cancels/closes and reconnects to
   verify restoration. Unknown results fail. An uncertain final commit is never retried.

## Existing configuration

Tunnel create/reuse is checked against fresh inventory. Explicit reuse retains
unrelated interface settings and replaces reviewed address/MTU/MSS/VTI settings;
shutdown is removed on the selected tunnel. Other tunnels are untouched.
`network;1;existing_objects_action;replace_named` explicitly permits replacing the
generated named crypto/PBR objects. Default is reject on a conflict; a matching
object is reused. The diff shows the exact selected identities and before/after
public configuration. ACL/route-map replacement removes stale rules. Ingress policy
replacement is explicit. PSKs stay in memory and are never exported or moved to a
different headend. Unrelated keyring peers remain unchanged. New authentication
requires native/manual PSK provisioning first; no CSV PSK values are accepted.
Management static routes are retained. PBR does not replace the ISP default or the
five local routes. Static protected prefixes overlapping management are rejected.

## Validation evidence and current router

The shipped schema profile was read live from dg-wi-r1 via NETCONF get-schema.
Unit tests exercise reconciliation, preservation, conflict rejection, exact schema
selection, transaction failures, owned partial cleanup, rollback and commit uncertainty.
Unit tests do not prove hardware application or rollback behavior.
Live inventory confirms validate:1.1, but candidate=false and confirmed-commit=false.
Inline validation is available at protocol level; real application stays blocked
until the router advertises the required transaction capabilities.

The current task's loaded MCP process still exposes the older read-only tools.
Its native credential is available there, while the shell test process cannot access
that credential. Therefore no inline validate RPC, edit-config or commit was issued
by this development run. The direct validation helper was attempted and failed
before NETCONF connection because its native credential was unavailable. After loading the updated plugin, use the inline validation
tool first. Installation is intentionally deferred at the user's request.
Running→startup persistence is a separate operation.

Reference: https://www.rfc-editor.org/rfc/rfc6241.html#section-8.6.5.1

`validate_adapter_fixture` provides controlled GCM/CBC probes using an unused
Tunnel and documentation addresses. It runs inline validate only and cannot create
an apply plan. `scripts/validate_adapter.py` exposes the same probe under the local
user account without installation. These probes are schema tests, not production
parameters or live forwarding tests.

Schema fixtures allow replace_named only in the proposed inline validation input.
This accommodates existing ingress policies/objects without altering running config.
fixture_only still prevents build/apply. Production CSV conflicts still reject by
default and require an explicit operator-selected replace_named and reviewed diff.

## Validation architecture

The IOS XE adapter reads running for reconciliation and a public diff, then submits
only the generated patch to running using edit-config with test-option=test-only,
default-operation=merge and error-option=stop-on-error. RFC 6241 validate:1.1 defines
test-only as validation without attempting to set. A successful RPC is the validation
result. Full running digests are not compared after test-only because IOS XE retrieval
serialization is not a reliable equality oracle; prepare/apply perform their own
locked baseline and candidate checks.

The code no longer validates a reconstructed full get-config response. That approach
was rejected because server output is not guaranteed to be a portable configuration
input: defaults, implicit mandatory nodes, cross-model dependencies and QName prefix
scope can differ. It also made unrelated device configuration prevent validation.

The transaction engine remains capability-driven. IOS XE renderers/profiles handle
release-specific YANG differences; the test-only/diff/drift framework is shared by
supported ISR devices. Exact profile mismatch blocks safely until a compatible
profile is added. Candidate and confirmed-commit remain required for real apply.

validate_adapter_fixture exercises GCM/CBC using the same test-only patch path and
can never create an apply plan. Debug output remains sanitized and contains no raw
XML, values or secrets.

Validation evidence: 71 local unit tests passed. Hardware test-only validation with
this version has not yet run.
