"""Sanitized read-only routing inventory; raw configuration never leaves memory."""
from ipaddress import IPv4Address, IPv4Network
from lxml import etree
from .discovery import NATIVE, parse_xml

ROUTING = 'urn:ietf:params:xml:ns:yang:ietf-routing'


def summarize(native_xml, operational_xml=None):
    tree = parse_xml(native_xml)
    interfaces, routes = [], []
    for entry in tree.xpath("//*[local-name()='native']/*[local-name()='interface']/*"):
        name = entry.findtext(f'{{{NATIVE}}}name')
        if name is None:
            continue
        primary = entry.find(f'{{{NATIVE}}}ip/{{{NATIVE}}}address/{{{NATIVE}}}primary')
        interfaces.append({'name': etree.QName(entry).localname + name,
            'address': primary.findtext(f'{{{NATIVE}}}address') if primary is not None else None,
            'mask': primary.findtext(f'{{{NATIVE}}}mask') if primary is not None else None,
            'shutdown': entry.find(f'{{{NATIVE}}}shutdown') is not None})
    for entry in tree.xpath("//*[local-name()='native']/*[local-name()='ip']/*[local-name()='route']/*[local-name()='ip-route-interface-forwarding-list']"):
        prefix, mask = entry.findtext(f'{{{NATIVE}}}prefix'), entry.findtext(f'{{{NATIVE}}}mask')
        network = str(IPv4Network(f'{prefix}/{mask}', strict=False))
        for hop in entry.findall(f'{{{NATIVE}}}fwd-list'):
            routes.append({'prefix': network, 'next_hop': hop.findtext(f'{{{NATIVE}}}fwd'),
                           'distance': hop.findtext(f'{{{NATIVE}}}metric') or '1', 'source': 'configured-static'})
    operational = []
    if operational_xml:
        op = parse_xml(operational_xml)
        for rib in op.xpath("//*[local-name()='rib']"):
            rib_name = rib.xpath("./*[local-name()='name']/text()")
            for route in rib.xpath("./*[local-name()='routes']/*[local-name()='route']"):
                def values(name):
                    return route.xpath(f".//*[local-name()='{name}']/text()")
                prefixes = values('destination-prefix')
                if not prefixes:
                    continue
                try:
                    prefix = str(IPv4Network(prefixes[0], strict=False))
                except ValueError:
                    continue
                operational.append({'prefix': prefix, 'rib': rib_name[0] if rib_name else None,
                    'next_hops': values('next-hop-address'), 'interfaces': values('outgoing-interface'),
                    'source_protocol': values('source-protocol'), 'source': 'operational-rib'})
    return {'interfaces': interfaces, 'static_routes': routes, 'routing_table': operational,
            'default_routes': [r for r in operational + routes if r['prefix'] == '0.0.0.0/0'],
            'occupied_tunnel_ids': sorted(int(i['name'][6:]) for i in interfaces if i['name'].startswith('Tunnel')),
            'warnings': ['Configured static routes are not proof of active forwarding',
                         'EIGRP redistribution and management-client return path require separate verification'],
            'operational_table_observed': bool(operational), 'apply_available': False}


def read_routing(device):
    # Read only the native subtrees needed for this step, excluding crypto/AAA.
    filt = f'<native xmlns="{NATIVE}"><interface/><ip><route/></ip></native>'
    native = device.get_config(source='running', filter=('subtree', filt)).data_xml
    caps = [str(c).strip() for c in device.server_capabilities]
    operational = None
    warning = None
    if any('module=ietf-routing&revision=2015-05-25' in c for c in caps):
        try:
            operational = device.get(filter=('subtree', f'<routing-state xmlns="{ROUTING}"/>')).data_xml
        except Exception:
            warning = 'Operational RIB read failed; active/default routing remains unverified'
    else:
        warning = 'No supported ietf-routing revision advertised; operational routing remains unverified'
    result = summarize(native, operational)
    if warning:
        result['warnings'].append(warning)
    if not result['operational_table_observed']:
        result['warnings'].append('No operational routes returned; do not substitute configured routes for the routing table')
    return result
