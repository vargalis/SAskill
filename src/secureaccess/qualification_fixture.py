"""Controlled nonproduction schema probe. Never stages/commits a configuration."""
from ipaddress import IPv4Network,IPv4Address
from .provisioning import ProvisioningSpec,CryptoParameters
from .workflow import ApplyBlocked

def schema_fixture(routing,host,*,cbc=False):
    defaults=[r for r in routing.get('static_routes',[]) if r['prefix']=='0.0.0.0/0']
    if len(defaults)!=1: raise ApplyBlocked('Schema fixture requires one reviewed ISP default')
    try: gateway=IPv4Address(defaults[0]['next_hop'])
    except ValueError: raise ApplyBlocked('Schema fixture requires IPv4 ISP next hop') from None
    interfaces=[i for i in routing.get('interfaces',[]) if i.get('address') and i.get('mask') and not i['shutdown']]
    wan=next((i for i in interfaces if i['name'].startswith('GigabitEthernet') and gateway in IPv4Network(i['address']+'/'+i['mask'],strict=False)),None)
    ingress=next((i for i in interfaces if i!=wan and i['name'].startswith('GigabitEthernet')),None)
    if wan is None or ingress is None: raise ApplyBlocked('No supported WAN and PBR ingress for schema fixture')
    occupied=set(routing.get('occupied_tunnel_ids',[]))
    number=next((n for n in range(64000,64100) if n not in occupied),None)
    if number is None: raise ApplyBlocked('No unused fixture tunnel ID')
    sources=list(dict.fromkeys(r['prefix'] for r in routing.get('static_routes',[]) if r['prefix']!='0.0.0.0/0'))
    if not sources: raise ApplyBlocked('No source prefixes available for schema fixture')
    if any(IPv4Address('192.0.2.1') in IPv4Network(i['address']+'/'+i['mask'],strict=False) for i in interfaces):
        raise ApplyBlocked('Documentation address collides with current interface network')
    crypto=CryptoParameters(ike_encryption='aes-cbc-256',integrity='sha256',esp='esp-aes-256-sha256',pfs=20,dh_groups=[20]) if cbc else CryptoParameters()
    spec=ProvisioningSpec(prefix='SAVALIDATE',isp_gateway=gateway,router_wan_ip=wan['address'],routing_mode='pbr',
        management_prefixes=[sources[0]],protected_prefixes=['0.0.0.0/0'],
        pbr=dict(source_prefixes=sources,ingress_interfaces=[ingress['name']],bypass_destination_prefixes=sources,failure_behavior='normal-routing'),
        tunnels=[dict(tunnel_id=number,headend='203.0.113.254',local_identity='validation@example.invalid',source_interface=wan['name'],address='192.0.2.1/30')],crypto=crypto)
    return {'platform':'iosxe','target':{'host':host,'name':'NONPRODUCTION-SCHEMA-FIXTURE'},
        'provisioning_spec':spec.model_dump(mode='json'),'existing_objects_action':'replace_named',
        'tunnel_interface_intent':[{'interface_name':f'Tunnel{number}','action':'create','change_scope':''}],
        'fixture_only':True,'inline_replacement_only':True,'note':'Documentation addresses/default crypto test schema only; never apply this fixture'}
