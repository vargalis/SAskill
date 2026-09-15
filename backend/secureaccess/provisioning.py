"""Complete secret-free Cisco IOS XE VTI configuration preview.

CLI is a human-readable review artifact only, never a configuration transport.
NETCONF rendering remains gated on retrieved, qualified device schemas.
"""
from ipaddress import IPv4Address, IPv4Interface, IPv4Network
from typing import Literal
from pydantic import Field, model_validator
from .models import StrictModel

TOKEN = r"^[A-Za-z0-9][A-Za-z0-9_.+-]{0,47}$"
INTERFACE = r"^(GigabitEthernet|Loopback|Vlan)[0-9]+(?:/[0-9]+)*(?:\.[0-9]+)?$"


class CryptoParameters(StrictModel):
    ike_encryption: Literal["aes-gcm-256", "aes-cbc-256"] = "aes-gcm-256"
    prf: Literal["sha256", "sha384", "sha512"] = "sha256"
    integrity: Literal["sha256", "sha384", "sha512"] | None = None
    dh_groups: list[Literal[19, 20]] = Field(default_factory=lambda: [19, 20], min_length=1)
    esp: Literal["esp-gcm-256", "esp-aes-256-sha256"] = "esp-gcm-256"
    pfs: Literal[19, 20] | None = None
    ike_lifetime: int = Field(default=86400, ge=120, le=86400)
    ipsec_lifetime: int = Field(default=3600, ge=120, le=86400)
    dpd_interval: int = Field(default=10, ge=10, le=3600)
    dpd_retries: int = Field(default=3, ge=2, le=60)

    @model_validator(mode="after")
    def check_integrity(self):
        if self.ike_encryption == "aes-gcm-256" and self.integrity is not None:
            raise ValueError("GCM must not configure separate IKE integrity")
        if self.ike_encryption == "aes-cbc-256" and self.integrity is None:
            raise ValueError("CBC requires explicit IKE integrity")
        if len(set(self.dh_groups)) != len(self.dh_groups):
            raise ValueError("Duplicate DH groups")
        return self


class TunnelSpec(StrictModel):
    tunnel_id: int = Field(ge=1, le=2147483647)
    headend: IPv4Address
    local_identity: str = Field(pattern=r"^[A-Za-z0-9_.+\-]+@[A-Za-z0-9.\-]+$", max_length=255)
    source_interface: str = Field(pattern=INTERFACE)
    address: IPv4Interface | None = None
    unnumbered_interface: str | None = Field(default=None, pattern=INTERFACE)
    source_loopback_address: IPv4Interface | None = None
    mtu: int = Field(default=1400, ge=576, le=1500)
    tcp_mss: int = Field(default=1350, ge=536, le=1460)
    distance: int = Field(default=1, ge=1, le=254)

    @model_validator(mode="after")
    def check_addressing(self):
        if (self.address is None) == (self.unnumbered_interface is None):
            raise ValueError("Choose exactly one VTI address or unnumbered interface")
        if self.tcp_mss > self.mtu - 40:
            raise ValueError("TCP MSS exceeds tunnel MTU minus IPv4/TCP headers")
        if self.source_loopback_address and not self.source_interface.startswith("Loopback"):
            raise ValueError("Source address creation supports Loopback only")
        if self.source_loopback_address and self.source_loopback_address.network.prefixlen != 32:
            raise ValueError("Source Loopback must use /32")
        if self.address and self.headend in self.address.network:
            raise ValueError("Headend cannot be on the VTI subnet")
        return self


class PBRParameters(StrictModel):
    source_prefixes: list[IPv4Network] = Field(min_length=1)
    ingress_interfaces: list[str] = Field(min_length=1)
    bypass_destination_prefixes: list[IPv4Network] = Field(min_length=1)
    failure_behavior: Literal["normal-routing"]

    @model_validator(mode="after")
    def check_policy(self):
        import re
        for values in (self.source_prefixes, self.ingress_interfaces, self.bypass_destination_prefixes):
            if len(set(values)) != len(values):
                raise ValueError("Duplicate PBR values")
        if any(p.prefixlen == 0 for p in self.source_prefixes + self.bypass_destination_prefixes):
            raise ValueError("Explicit source networks and non-default bypasses required")
        if any(not re.fullmatch(INTERFACE, name) or name.startswith("Loopback") for name in self.ingress_interfaces):
            raise ValueError("PBR requires physical or VLAN ingress interfaces")
        return self


class ProvisioningSpec(StrictModel):
    prefix: str = Field(default="SSE", pattern=TOKEN)
    isp_gateway: IPv4Address
    router_wan_ip: IPv4Address
    management_prefixes: list[IPv4Network] = Field(min_length=1)
    protected_prefixes: list[IPv4Network] = Field(min_length=1)
    routing_mode: Literal["static", "pbr"] = "static"
    pbr: PBRParameters | None = None
    tunnels: list[TunnelSpec] = Field(min_length=1, max_length=8)
    crypto: CryptoParameters = Field(default_factory=CryptoParameters)

    @model_validator(mode="after")
    def check_topology(self):
        if (self.routing_mode == "pbr") != (self.pbr is not None):
            raise ValueError("PBR parameters required only in PBR mode")
        if self.pbr:
            if not self.prefix[0].isalpha():
                raise ValueError("Named PBR ACL requires an alphabetic prefix")
            if len(self.tunnels) > 2:
                raise ValueError("PBR supports an ordered primary/secondary pair of VTIs")
            if any(not any(m.subnet_of(b) for b in self.pbr.bypass_destination_prefixes) for m in self.management_prefixes):
                raise ValueError("Management destinations must bypass PBR")
        ids = [t.tunnel_id for t in self.tunnels]
        if len(ids) != len(set(ids)):
            raise ValueError("Duplicate tunnel IDs")
        pairs = [(t.source_interface, t.headend) for t in self.tunnels]
        if len(pairs) != len(set(pairs)):
            raise ValueError("Multiple VTIs cannot share both source and destination")
        identities = [(t.local_identity, t.headend) for t in self.tunnels]
        if len(identities) != len(set(identities)):
            raise ValueError("Each tunnel requires a unique local/remote identity pair")
        for prefixes in (self.management_prefixes, self.protected_prefixes):
            if len(set(prefixes)) != len(prefixes):
                raise ValueError("Duplicate prefixes")
        for management in self.management_prefixes:
            if management.prefixlen == 0:
                raise ValueError("Management protection cannot be a default route")
            if self.routing_mode == "static" and any(management.overlaps(p) and management.prefixlen <= p.prefixlen
                   for p in self.protected_prefixes):
                raise ValueError("Protected route would override management preservation")
        for t in self.tunnels:
            if t.headend == self.isp_gateway:
                raise ValueError("Headend cannot equal ISP gateway")
            if any(p.prefixlen == 32 and t.headend in p for p in self.protected_prefixes):
                raise ValueError("Protected host route conflicts with headend underlay route")
            if t.address and self.isp_gateway in t.address.network:
                raise ValueError("ISP gateway cannot be on VTI subnet")
        networks = [t.address.network for t in self.tunnels if t.address]
        if any(a.overlaps(b) for i, a in enumerate(networks) for b in networks[i + 1:]):
            raise ValueError("Overlapping VTI networks")
        return self


def render_nonsecret(spec: ProvisioningSpec) -> dict:
    p, c = spec.prefix, spec.crypto
    lines = [f"crypto ikev2 proposal {p}-PROPOSAL", f" encryption {c.ike_encryption}",
             f" prf {c.prf}"]
    if c.integrity:
        lines.append(f" integrity {c.integrity}")
    lines.extend([" group " + " ".join(map(str, c.dh_groups)), " exit",
                  f"crypto ikev2 policy {p}-POLICY", f" match address local {spec.router_wan_ip}",
                  f" proposal {p}-PROPOSAL", " exit"])
    transform = "esp-gcm 256" if c.esp == "esp-gcm-256" else "esp-aes 256 esp-sha256-hmac"
    lines.extend([f"crypto ipsec transform-set {p}-TRANSFORM {transform}", " mode tunnel", " exit"])
    secret_steps = []
    warnings = []
    for t in spec.tunnels:
        keyring = f"{p}-KEYRING-{t.tunnel_id}"
        peer = f"{p}-PEER-{t.tunnel_id}"
        ike = f"{p}-IKEV2-{t.tunnel_id}"
        ipsec = f"{p}-IPSEC-{t.tunnel_id}"
        lines.extend([f"crypto ikev2 keyring {keyring}", f" peer {peer}",
                      f"  address {t.headend}", "  exit", " exit",
                      f"crypto ikev2 profile {ike}",
                      f" match identity remote address {t.headend} 255.255.255.255",
                      f" identity local email {t.local_identity}",
                      " authentication remote pre-share", " authentication local pre-share",
                      f" keyring local {keyring}", f" lifetime {c.ike_lifetime}",
                      f" dpd {c.dpd_interval} {c.dpd_retries} periodic", " exit",
                      f"crypto ipsec profile {ipsec}", f" set transform-set {p}-TRANSFORM",
                      f" set ikev2-profile {ike}", f" set security-association lifetime seconds {c.ipsec_lifetime}"])
        if c.pfs:
            lines.append(f" set pfs group{c.pfs}")
        lines.append(" exit")
        if t.source_loopback_address:
            a = t.source_loopback_address
            lines.extend([f"interface {t.source_interface}", f" ip address {a.ip} {a.netmask}", " exit"])
            warnings.append(f"{t.source_interface} underlay reachability/NAT must be qualified separately")
        lines.append(f"interface Tunnel{t.tunnel_id}")
        if t.address:
            lines.append(f" ip address {t.address.ip} {t.address.netmask}")
        else:
            lines.append(f" ip unnumbered {t.unnumbered_interface}")
        lines.extend([f" ip mtu {t.mtu}", f" ip tcp adjust-mss {t.tcp_mss}",
                      f" tunnel source {t.source_interface}", " tunnel mode ipsec ipv4",
                      f" tunnel destination {t.headend}", f" tunnel protection ipsec profile {ipsec}", " exit"])
        secret_steps.append({"keyring": keyring, "peer": peer,
                             "required_manual_values": ["local PSK", "remote PSK"],
                             "policy": "preserve existing values; manually supply if absent"})
    # Preserve headend and management underlay paths before protected routes.
    for headend in sorted({t.headend for t in spec.tunnels}):
        lines.append(f"ip route {headend} 255.255.255.255 {spec.isp_gateway}")
    for network in (spec.management_prefixes if spec.routing_mode == "static" else []):
        lines.append(f"ip route {network.network_address} {network.netmask} {spec.isp_gateway}")
    for t in (spec.tunnels if spec.routing_mode == "static" else []):
        for network in spec.protected_prefixes:
            lines.append(f"ip route {network.network_address} {network.netmask} Tunnel{t.tunnel_id} {t.distance}")
    if spec.pbr:
        policy = spec.pbr
        acl, route_map = f"{p}-PBR-ACL", f"{p}-PBR"
        lines.append(f"ip access-list extended {acl}")
        for action, source, destination in pbr_acl_entries(spec):
            source_match = "any" if source is None else f"{source.network_address} {source.hostmask}"
            lines.append(f" {action} ip {source_match} {destination.network_address} {destination.hostmask}")
        tunnel_order = " ".join(f"Tunnel{t.tunnel_id}" for t in spec.tunnels)
        lines.extend([" exit", f"route-map {route_map} permit 10", f" match ip address {acl}",
                      f" set interface {tunnel_order}", " exit"])
        for interface in policy.ingress_interfaces:
            lines.extend([f"interface {interface}", f" ip policy route-map {route_map}", " exit"])
        warnings.extend(["PBR preserves existing RIB/default and management return routes; bypass destinations use normal routing",
                         "PBR tries selected tunnel interfaces in CSV order, then uses normal routing if none is available",
                         "Tunnel interface state is only a local availability signal; it does not prove end-to-end Secure Access reachability",
                         "Existing ACL/route-map names, interface policies, NAT and point-to-point VTI support require reconciliation"])
    if len(spec.tunnels) > 1 and spec.routing_mode == "static":
        warnings.append("Equal distances request ECMP; unequal distances request floating routes, not monitored failover")
    return {"configuration_cli_preview": "\n".join(lines) + "\n",
            "manual_secret_steps": secret_steps, "secrets_included": False,
            "crypto_map_required": False, "bgp_included": False,
            "warnings": warnings + ["Optionally verify Security K9/HSEC licensing, UDP 500/4500 reachability, and absence of NAT commands on selected Tunnel interfaces",
                                     "New tunnel cannot authenticate until manual PSK provisioning",
                                     "CLI preview is not executed; device reconciliation and NETCONF schema qualification required",
                                     "Secret-free scope does not include unrelated router features such as NAT, AAA or firewall policy"],
            "apply_ready": False}


def pbr_acl_entries(spec: ProvisioningSpec):
    """Shared ordered classification for CLI/XML; excludes management and underlay."""
    if spec.pbr is None:
        return []
    bypasses = sorted(set(spec.pbr.bypass_destination_prefixes + spec.management_prefixes +
                          [IPv4Network(f"{t.headend}/32") for t in spec.tunnels]),
                      key=lambda n: (int(n.network_address), n.prefixlen))
    return [("deny", None, destination) for destination in bypasses] + [
        ("permit", source, destination) for source in spec.pbr.source_prefixes
        for destination in spec.protected_prefixes]
