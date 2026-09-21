"""Offline crypto/VTI adapter. Never opens a connection or sends an RPC."""
from lxml import etree
from .provisioning import ProvisioningSpec, render_nonsecret, pbr_acl_entries

NC = 'urn:ietf:params:xml:ns:netconf:base:1.0'
N = 'http://cisco.com/ns/yang/Cisco-IOS-XE-native'
C = 'http://cisco.com/ns/yang/Cisco-IOS-XE-crypto'
T = 'http://cisco.com/ns/yang/Cisco-IOS-XE-tunnel'
A = 'http://cisco.com/ns/yang/Cisco-IOS-XE-acl'
R = 'http://cisco.com/ns/yang/Cisco-IOS-XE-route-map'


def node(parent, name, value=None, namespace=C):
    child = etree.SubElement(parent, f'{{{namespace}}}{name}')
    if value is not None:
        child.text = str(value)
    return child


def _render_psk(peer, record):
    psk = node(peer, 'pre-shared-key')
    def value(parent, item):
        if item['format'] == 'hex':
            node(parent, 'hex', item['value'])
        else:
            node(parent, 'encryption', item['encryption'])
            node(parent, 'key', item['value'])
    if record['mode'] == 'shared':
        value(psk, record['shared'])
    else:
        value(node(psk, 'local-option'), record['local'])
        value(node(psk, 'remote-option'), record['remote'])


def render_netconf(spec: ProvisioningSpec, psk_resolver=None) -> dict:
    """Produce an offline merge preview for crypto 2022-07-20/tunnel 2022-03-01.

    Includes native interface IP and static routes; device qualification remains required.
    Omitting secret leaves is not permission to overwrite or remove existing keys.
    """
    root = etree.Element(f'{{{NC}}}config', nsmap={'nc': NC, 'ios': N, 'crypto': C, 'tun': T, 'acl': A, 'rmap': R})
    native = node(root, 'native', namespace=N)
    crypto = node(native, 'crypto', namespace=N)
    ikev2 = node(crypto, 'ikev2')
    p, c = spec.prefix, spec.crypto
    proposal = node(ikev2, 'proposal')
    node(proposal, 'name', f'{p}-PROPOSAL')
    node(node(proposal, 'encryption'), c.ike_encryption)
    node(node(proposal, 'prf'), c.prf)
    if c.integrity:
        node(node(proposal, 'integrity'), c.integrity)
    group = node(proposal, 'group')
    for g in c.dh_groups:
        node(group, {19: 'nineteen', 20: 'twenty'}[g])
    policy = node(ikev2, 'policy')
    node(policy, 'name', f'{p}-POLICY')
    address = node(node(policy, 'match'), 'address')
    node(address, 'local-ip', spec.router_wan_ip)
    node(node(policy, 'proposal'), 'proposals', f'{p}-PROPOSAL')
    ipsec = node(crypto, 'ipsec')
    transform = node(ipsec, 'transform-set')
    node(transform, 'tag', f'{p}-TRANSFORM')
    node(transform, 'esp', 'esp-gcm' if c.esp == 'esp-gcm-256' else 'esp-aes')
    node(transform, 'key-bit', '256')
    if c.esp != 'esp-gcm-256':
        node(transform, 'esp-hmac', 'esp-sha256-hmac')
    node(node(transform, 'mode'), 'tunnel-choice')
    interfaces = node(native, 'interface', namespace=N)
    loopbacks = {}
    for t in spec.tunnels:
        if t.source_loopback_address:
            if t.source_interface in loopbacks and loopbacks[t.source_interface] != t.source_loopback_address:
                raise ValueError('Conflicting Loopback addresses')
            loopbacks[t.source_interface] = t.source_loopback_address
    for name, address in sorted(loopbacks.items()):
        interface = node(interfaces, 'Loopback', namespace=N)
        node(interface, 'name', name.removeprefix('Loopback'), N)
        primary = node(node(node(interface, 'ip', namespace=N), 'address', namespace=N), 'primary', namespace=N)
        node(primary, 'address', address.ip, N)
        node(primary, 'mask', address.netmask, N)
    for t in spec.tunnels:
        keyring_name = f'{p}-KEYRING-{t.tunnel_id}'
        ike_name = f'{p}-IKEV2-{t.tunnel_id}'
        ipsec_name = f'{p}-IPSEC-{t.tunnel_id}'
        keyring = node(ikev2, 'keyring')
        node(keyring, 'name', keyring_name)
        peer = node(keyring, 'peer')
        node(peer, 'name', f'{p}-PEER-{t.tunnel_id}')
        addr = node(node(peer, 'address'), 'ipv4')
        node(addr, 'ipv4-address', t.headend)
        node(addr, 'ipv4-mask', '255.255.255.255')
        if psk_resolver is not None:
            secret = psk_resolver(t.tunnel_id, str(t.headend))
            if secret is not None:
                _render_psk(peer, secret)
        profile = node(ikev2, 'profile')
        node(profile, 'name', ike_name)
        remote = node(node(node(profile, 'match'), 'identity'), 'remote')
        addr = node(node(remote, 'address'), 'ipv4')
        node(addr, 'ipv4-address', t.headend)
        node(addr, 'ipv4-mask', '255.255.255.255')
        node(node(node(profile, 'identity'), 'local'), 'email', t.local_identity)
        authentication = node(profile, 'authentication')
        for side in ('local', 'remote'):
            node(node(authentication, side), 'pre-share')
        node(node(node(profile, 'keyring'), 'local'), 'name', keyring_name)
        node(node(profile, 'lifetime'), 'seconds', c.ike_lifetime)
        dpd = node(profile, 'dpd')
        for name, value in [('interval', c.dpd_interval), ('retry', c.dpd_retries), ('query', 'periodic')]:
            node(dpd, name, value)
        profile = node(ipsec, 'profile')
        node(profile, 'name', ipsec_name)
        settings = node(profile, 'set')
        node(settings, 'transform-set', f'{p}-TRANSFORM')
        node(settings, 'ikev2-profile', ike_name)
        node(node(node(settings, 'security-association'), 'lifetime'), 'seconds', c.ipsec_lifetime)
        if c.pfs:
            node(node(settings, 'pfs'), 'group', f'group{c.pfs}')
        interface = node(interfaces, 'Tunnel', namespace=N)
        node(interface, 'name', t.tunnel_id, N)
        ip = node(interface, 'ip', namespace=N)
        if t.address:
            primary = node(node(ip, 'address', namespace=N), 'primary', namespace=N)
            node(primary, 'address', t.address.ip, N)
            node(primary, 'mask', t.address.netmask, N)
        else:
            node(ip, 'unnumbered', t.unnumbered_interface, N)
        if not 500 <= t.tcp_mss <= 1460:
            raise ValueError('TCP MSS outside inspected YANG range 500..1460')
        node(ip, 'mtu', t.mtu, N)
        node(node(ip, 'tcp', namespace=N), 'adjust-mss', t.tcp_mss, N)
        tunnel = node(interface, 'tunnel', namespace=T)
        node(tunnel, 'source', t.source_interface, T)
        node(node(tunnel, 'destination-config', namespace=T), 'ipv4', t.headend, T)
        node(node(node(tunnel, 'mode', namespace=T), 'ipsec', namespace=T), 'ipv4', namespace=T)
        protection = node(tunnel, 'protection', namespace=T)
        node(node(node(protection, 'ipsec'), 'profile-option'), 'name', ipsec_name)
    from ipaddress import IPv4Network
    routes = {}
    def add_route(network, forward, distance):
        key = (str(network.network_address), str(network.netmask))
        previous = routes.setdefault(key, {}).get(str(forward))
        if previous is not None and previous != distance:
            raise ValueError('Conflicting route distances')
        routes[key][str(forward)] = distance
    for headend in sorted({t.headend for t in spec.tunnels}):
        add_route(IPv4Network(f'{headend}/32'), spec.isp_gateway, 1)
    for network in (spec.management_prefixes if spec.routing_mode == "static" else []):
        add_route(network, spec.isp_gateway, 1)
    for t in (spec.tunnels if spec.routing_mode == "static" else []):
        for network in spec.protected_prefixes:
            add_route(network, f'Tunnel{t.tunnel_id}', t.distance)
    route = node(node(native, 'ip', namespace=N), 'route', namespace=N)
    for (prefix, mask), forwards in routes.items():
        entry = node(route, 'ip-route-interface-forwarding-list', namespace=N)
        node(entry, 'prefix', prefix, N)
        node(entry, 'mask', mask, N)
        for forward, distance in forwards.items():
            hop = node(entry, 'fwd-list', namespace=N)
            node(hop, 'fwd', forward, N)
            node(hop, 'metric', distance, N)
    if spec.pbr:
        render_pbr(native, interfaces, spec)
    review = render_nonsecret(spec)
    return {'configuration_xml_preview': etree.tostring(root, pretty_print=True, encoding='unicode'),
            'payload_complete': True, 'schema_validated': False, 'device_qualified': False, 'apply_ready': False, 'secrets_included': False,
            'required_default_operation': 'merge',
            'schema_revisions': {'Cisco-IOS-XE-crypto': '2022-07-20', 'Cisco-IOS-XE-tunnel': '2022-03-01', 'Cisco-IOS-XE-native': '2022-08-01', 'Cisco-IOS-XE-ip': '2022-07-01'},
            'manual_secret_steps': review['manual_secret_steps'],
            'pbr_schema_provenance': ({
                'native_and_interfaces': 'Live get-schema from qualification device',
                'acl_reference': 'Cisco bundle xe/17121 Cisco-IOS-XE-acl@2023-07-01',
                'route_map_reference': 'Cisco bundle xe/17121 Cisco-IOS-XE-route-map@2023-07-01',
                'advertised_device_revisions': {'Cisco-IOS-XE-acl': '2021-07-01', 'Cisco-IOS-XE-route-map': '2022-07-01'},
                'exact_device_augments_verified': False} if spec.pbr else None),
            'blockers': (['Exact device ACL/route-map schemas and deviations must be checked against reference mapping; PBR is not lab-qualified'] if spec.pbr else []) + ['Device deviations and complete imported YANG schema set not validated',
                         'No running-config reconciliation, full YANG validation or live post-checks',
                         'Candidate and confirmed commit unavailable in supplied router inventory',
                         'Apply requires a PSK from the test CSV, native vault, or an existing matching peer'],
            'warning': 'Offline preview only; never send directly to a router. Merge alone does not reconcile conflicting choices or algorithms.'}


def render_pbr(native, interfaces, spec):
    """Reference-schema XML only: no session, RPC, or ownership reconciliation."""
    import re
    acl_name, map_name = f"{spec.prefix}-PBR-ACL", f"{spec.prefix}-PBR"
    ip = native.find(f"{{{N}}}ip")
    if ip is None:
        ip = node(native, 'ip', namespace=N)
    access_list = ip.find(f"{{{N}}}access-list")
    if access_list is None:
        access_list = node(ip, 'access-list', namespace=N)
    acl = node(access_list, 'extended', namespace=A)
    node(acl, 'name', acl_name, A)
    entries = pbr_acl_entries(spec)
    if len(entries) * 10 > 2147483647:
        raise ValueError('ACL sequence range exceeded')
    for sequence, (action, source, destination) in enumerate(entries, 1):
        entry = node(acl, 'access-list-seq-rule', namespace=A)
        node(entry, 'sequence', sequence * 10, A)
        ace = node(entry, 'ace-rule', namespace=A)
        node(ace, 'action', action, A)
        node(ace, 'protocol', 'ip', A)
        if source is None:
            node(ace, 'any', namespace=A)
        else:
            node(ace, 'ipv4-address', source.network_address, A)
            node(ace, 'mask', source.hostmask, A)
        node(ace, 'dest-ipv4-address', destination.network_address, A)
        node(ace, 'dest-mask', destination.hostmask, A)
    route_map = node(native, 'route-map', namespace=N)
    node(route_map, 'name', map_name, N)
    entry = node(route_map, 'route-map-without-order-seq', namespace=R)
    node(entry, 'seq_no', 10, R)
    node(entry, 'operation', 'permit', R)
    match = node(node(node(entry, 'match', namespace=R), 'ip', namespace=R), 'address', namespace=R)
    node(match, 'access-list', acl_name, R)
    set_clause = node(entry, 'set', namespace=R)
    for tunnel in spec.tunnels:
        node(set_clause, 'interface-list', f'Tunnel{tunnel.tunnel_id}', R)
    for name in spec.pbr.ingress_interfaces:
        parsed = re.fullmatch(r'(GigabitEthernet|Vlan)([0-9]+(?:/[0-9]+)*(?:\.[0-9]+)?)', name)
        if parsed is None:
            raise ValueError('Unsupported PBR ingress interface encoding')
        kind, key = parsed.groups()
        if kind == 'Vlan' and (not key.isdigit() or not 1 <= int(key) <= 4094):
            raise ValueError('Invalid VLAN interface ID')
        interface = next((item for item in interfaces.findall(f'{{{N}}}{kind}')
                          if item.findtext(f'{{{N}}}name') == key), None)
        if interface is None:
            interface = node(interfaces, kind, namespace=N)
            node(interface, 'name', key, N)
        ip = interface.find(f'{{{N}}}ip')
        if ip is None:
            ip = node(interface, 'ip', namespace=N)
        node(node(ip, 'policy', namespace=N), 'route-map', map_name, N)
