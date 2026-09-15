"""Intent planning only: no fabricated IOS XE crypto XML or configuration RPCs."""
from dataclasses import asdict, dataclass
from difflib import unified_diff
import json

from .discovery import Inventory, parse_xml
from .models import AgentConfig


@dataclass
class Plan:
    intent: dict
    checks: dict[str, bool]
    blockers: list[str]
    warnings: list[str]
    diff: str
    apply_ready: bool = False
    adapter: str | None = None

    def as_dict(self):
        return asdict(self)


def build_plan(config: AgentConfig, inventory: Inventory, current_xml: str | None = None) -> Plan:
    sa, tunnel, routing = config.secure_access, config.tunnel, config.routing
    intent = {
        "ikev2": {"local_identity": sa.local_identity, "remote_identity": sa.remote_identity,
                   "encryption": sa.ike_encryption, "integrity": sa.ike_integrity,
                   "dh_group": sa.dh_group, "psk": "<secret-reference>"},
        "ipsec": {"transform": sa.ipsec_transform, "mode": "tunnel"},
        "vti": {"name": tunnel.name, "source": tunnel.source_interface,
                "destination": str(sa.headend), "address": str(tunnel.address), "mtu": tunnel.mtu},
        "static_routes": [
            {"prefix": f"{sa.headend}/32", "next_hop": str(routing.isp_gateway)},
            {"prefix": str(routing.management_network), "next_hop": str(routing.isp_gateway)},
            *[{"prefix": str(n), "interface": tunnel.name} for n in routing.protected_networks],
        ],
    }
    names = {m.name for m in inventory.models}
    checks = {f: inventory.supports(f) for f in ("candidate", "validate", "confirmed-commit")}
    checks["native_model_advertised"] = "Cisco-IOS-XE-native" in names
    checks["current_config_read"] = current_xml is not None
    blockers = [f"Missing prerequisite: {k}" for k, v in checks.items() if not v]
    warnings = list(inventory.warnings)
    if current_xml is not None:
        tree = parse_xml(current_xml)
        interfaces = tree.xpath("//*[local-name()='native']/*[local-name()='interface']/*")
        source_found = False
        tunnel_id = tunnel.name.removeprefix("Tunnel")
        for node in interfaces:
            kind = node.tag.rsplit("}", 1)[-1]
            number = node.xpath("./*[local-name()='name']/text()")
            if number and kind + number[0] == tunnel.source_interface:
                source_found = True
            if kind == "Tunnel" and number == [tunnel_id]:
                blockers.append("Tunnel interface already exists; ownership/reconciliation required")
        checks["source_interface_exists"] = source_found
        if not source_found:
            blockers.append("Configured source interface absent from native configuration")
        if not tree.xpath("//*[local-name()='native']"):
            blockers.append("Native configuration response empty or unavailable")
    crypto = sorted(n for n in names if "crypto" in n.lower())
    warnings.append("Advertised crypto modules: " + (", ".join(crypto) or "none"))
    warnings.append("Interface state, underlay reachability and IKE/IPsec operational checks remain unverified")
    blockers.append("No release/schema-qualified crypto adapter installed; apply is disabled")
    # Do not diff raw running data: it may contain passwords and key material.
    desired = json.dumps(intent, indent=2, sort_keys=True).splitlines(True)
    diff = "".join(unified_diff([], desired, fromfile="empty-intent", tofile="desired-intent"))
    warnings.append("Diff is desired intent against empty intent, not a device configuration diff")
    return Plan(intent, checks, blockers, warnings, diff)
