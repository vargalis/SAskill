"""CSV configuration templates and strict offline plan import. No device I/O."""
import csv
import io
import re
from ipaddress import IPv4Address, IPv4Interface, IPv4Network
from pydantic import ValidationError
from .provisioning import ProvisioningSpec, CryptoParameters, render_nonsecret
from .netconf_renderer import render_netconf

COLUMNS = ['section', 'item', 'field', 'value', 'required', 'description']
REQUIRED_PLACEHOLDER = '<<< REQUIRED >>>'
SCALARS = {
    'meta': {
        'schema_version': ('2', True, 'Keep 2. This identifies the CSV schema and must not be edited.'),
        'platform': ('iosxe', True, 'Enter iosxe or ftd. Use iosxe for Cisco ISR-G2, ISR4K, or CSR routers.'),
        'template_mode': ('advanced', False, 'Template presentation mode: basic or advanced. Basic omits parameters that have built-in recommended defaults.'),
    },
    'device': {
        'name': ('', True, 'Enter the inventory name of the router, for example branch-r1. Recommendation: use the existing hostname.'),
        'host': ('', True, 'Enter the NETCONF management IPv4 address, for example 10.2.3.1. Do not enter the WAN address.'),
    },
    'network': {
        'existing_objects_action': ('', False, 'Leave blank to reject name conflicts. Use replace_named only after reviewing an exact diff of the named objects.'),
        'routing_mode': ('', True, 'Enter static or pbr. Recommendation: use pbr when selected source LANs must reach 0.0.0.0/0 through Secure Access.'),
        'isp_gateway': ('', True, 'Enter the current ISP next-hop IPv4 address. Recommendation: copy it from the verified active default route.'),
        'router_wan_ip': ('', True, 'Enter the router WAN IPv4 address used by the IKEv2 policy local-address match. It can be private when the ISR is behind NAT.'),
        'prefix': ('sse', True, 'IOS XE object-name prefix. Recommended value: sse; use another short unique prefix only when required.'),
    },
    'crypto': {
        'ike_encryption': ('aes-gcm-256', True, 'IKEv2 encryption. Cisco recommends GCM for maximum throughput; recommended value: aes-gcm-256.'),
        'prf': ('sha256', True, 'IKEv2 pseudo-random function. SHA256 is required with the recommended AES-GCM proposal.'),
        'integrity': ('', False, 'IKEv2 integrity algorithm. Leave blank with AES-GCM because GCM provides authenticated encryption; use the portal-approved hash with CBC.'),
        'dh_groups': ('19|20', True, 'IKEv2 Diffie-Hellman groups separated by |. Recommended ISR proposal: 19|20; Secure Access also supports 14 and 15.'),
        'esp': ('esp-gcm-256', True, 'IPsec ESP transform. Cisco recommends GCM for throughput; recommended value: esp-gcm-256.'),
        'pfs': ('', False, 'Optional IPsec PFS group. Recommendation: leave blank unless required and tested; Cisco warns PFS preference can cause rekey failures.'),
        'ike_lifetime': ('14400', True, 'IKE rekey interval in seconds. Recommended Secure Access default: 14400 seconds (4 hours).'),
        'ipsec_lifetime': ('3600', True, 'Child SA/IPsec rekey interval in seconds. Recommended Secure Access default: 3600 seconds (1 hour).'),
        'dpd_interval': ('10', True, 'DPD interval in seconds. The Cisco ISR example uses 10 seconds; use 30 seconds when intentionally matching the Secure Access 156-second maximum timeout design.'),
        'dpd_retries': ('3', True, 'DPD retry value used by the ISR profile. Recommended ISR guide value: 3; verify the resulting failover timing in production testing.'),
    },
}
LISTS = {
    'management_prefix': 'Enter a management network in CIDR notation, for example 10.10.10.0/24. Recommendation: bypass it from PBR to preserve router access.',
    'destination_prefix': 'Enter a Secure Access destination in CIDR notation. Use 0.0.0.0/0 to steer all destinations selected by the PBR source ACL.',
    'source_prefix': 'Enter one PBR source LAN in CIDR notation; copy this row with a unique item number for each LAN. Include only networks intended for Secure Access.',
    'bypass_prefix': 'Enter one destination that must use normal routing, in CIDR notation. Include management/local destinations and the Secure Access headend as /32 to prevent recursion.',
    'ingress_interface': 'Enter the IOS XE LAN interface where matching traffic arrives, for example GigabitEthernet0/0/1. Cisco requires the route-map on the ingress interface.',
}
TUNNEL = {
    'interface_name': ('', True, 'Enter TunnelN, for example Tunnel2. Recommendation: choose an unused ID from the fresh router inventory.'),
    'action': ('', True, 'Enter create for an unused interface or reuse for an existing interface. Reuse requires a reviewed current-versus-proposed diff.'),
    'headend': ('', True, 'Enter the Secure Access data-center IPv4 address shown in the tunnel group. Recommendation: use the closest assigned data center.'),
    'local_identity': ('', True, 'Enter the Tunnel ID/email from the Secure Access portal.'),
    'psk_mode': ('shared', True, 'Test build only. Enter shared for one bidirectional PSK or split for separate local and remote PSKs.'),
    'psk_format': ('plain', True, 'Test build only. Enter plain, type6, or hex. Split mode applies the selected format to both keys.'),
    'shared_psk': ('', False, 'Test build only. Enter the tunnel passphrase when psk_mode=shared.'),
    'local_psk': ('', False, 'Test build only. Enter the local signing key when psk_mode=split.'),
    'remote_psk': ('', False, 'Test build only. Enter the remote verification key when psk_mode=split.'),
    'source_interface': ('', True, 'Enter the WAN interface that reaches the headend, for example GigabitEthernet0/0/0. Verify the underlay route first.'),
    'address': ('', False, 'Enter the VTI IPv4 address with prefix length only when numbered, for example 169.254.10.1/30. Otherwise use unnumbered_interface.'),
    'unnumbered_interface': ('', False, 'Enter an existing interface whose IPv4 address the VTI will borrow. Cisco ISR examples use ip unnumbered; use either this field or address.'),
    'source_loopback_address': ('', False, 'Enter a CIDR address only when the plan must create a new loopback used as the tunnel source; otherwise leave blank.'),
    'mtu': ('1390', True, 'Tunnel inner IP MTU in bytes. Cisco Secure Access requires no more than 1390; recommended value: 1390. Do not reduce physical-interface MTU.'),
    'tcp_mss': ('1350', True, 'TCP MSS clamp in bytes. Recommended value: 1350 to match Cisco Secure Access and avoid fragmentation.'),
    'distance': ('1', True, 'Static-route administrative distance from 1 to 254. Recommended primary value: 1; use a larger value only for an intentionally floating backup.'),
    'reuse_confirmed': ('', False, 'For action=reuse, enter true only after reviewing the current interface and the exact proposed changes.'),
    'change_scope': ('', False, 'For action=reuse, describe the exact approved fields that may change; leave blank for action=create.'),
}
PBR = {'failure_behavior': ('', True, 'Enter normal-routing. This returns traffic to the normal RIB/ISP when no PBR set action is usable; verify this behavior during failover testing.')}
FTD = {
    'manager_type': ('', True, 'Enter FMC or FDM according to the system that manages this FTD. The FTD adapter is planning-only.'),
    'manager_host': ('', True, 'Enter the management IPv4 address or resolvable hostname of FMC/FDM.'),
    'device_id': ('', True, 'Enter the exact device identifier used by the manager API; do not guess it from the hostname.'),
    'version': ('', True, 'Enter the installed FTD software version, for example 7.6.1, so a future template can be version-qualified.'),
    'template_name': ('', True, 'Enter the approved manager template name. Recommendation: include site, purpose, and version in the name.'),
}

BASIC_HIDDEN = {
    ('network', 'existing_objects_action'), ('network', 'prefix'),
    *(('crypto', field) for field in SCALARS['crypto']),
    ('pbr', 'failure_behavior'),
    ('tunnel', 'source_loopback_address'), ('tunnel', 'mtu'),
    ('tunnel', 'tcp_mss'), ('tunnel', 'distance'),
}
BASIC_DEFAULTS = {
    **{('crypto', field): value for field, (value, _, _) in SCALARS['crypto'].items()},
    ('network', 'prefix'): 'sse',
    ('pbr', 'failure_behavior'): 'normal-routing',
    ('tunnel', 'mtu'): '1390',
    ('tunnel', 'tcp_mss'): '1350',
    ('tunnel', 'distance'): '1',
}
TUNNEL_INHERITED_FIELDS = ('source_interface','unnumbered_interface','mtu','tcp_mss')
PSK_FIELDS = ('psk_mode','psk_format','shared_psk','local_psk','remote_psk')
PSK_VALUE_FIELDS = ('shared_psk','local_psk','remote_psk')

INTERFACE_PATTERN = re.compile(r'^(GigabitEthernet|Loopback|Vlan)[0-9]+(?:/[0-9]+)*(?:\.[0-9]+)?$')
IDENTITY_PATTERN = re.compile(r'^[A-Za-z0-9_.+\-]+@[A-Za-z0-9.\-]+$')
TOKEN_PATTERN = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.+\-]{0,47}$')


def _field_errors(cells, row_numbers, platform):
    """Return sanitized, row-specific validation errors for nonblank CSV values."""
    errors=[]
    def add(key, message):
        row=row_numbers.get(key, 'generated')
        errors.append(f"Row {row}: {key[0]}.{key[1]}.{key[2]}: {message}")
    def integer(key, low, high):
        value=cells.get(key,'')
        if not value: return
        if not value.isdigit() or not low <= int(value) <= high:
            add(key,f'enter an integer from {low} to {high}')
    def ipv4(key):
        value=cells.get(key,'')
        if not value: return
        try: IPv4Address(value)
        except ValueError: add(key,'enter an IPv4 address, for example 192.0.2.1')
    def cidr(key, interface=False):
        value=cells.get(key,'')
        if not value: return
        try:
            (IPv4Interface if interface else IPv4Network)(value, **({} if interface else {'strict':True}))
        except ValueError:
            add(key,'enter canonical IPv4 CIDR notation, for example 10.10.10.0/24')
    def choice(key, choices):
        value=cells.get(key,'')
        if value and value not in choices: add(key,'enter one of: '+', '.join(choices))

    name=('device','1','name')
    if cells.get(name) and not re.fullmatch(r'[A-Za-z0-9_.-]{1,48}',cells[name]):
        add(name,'use 1-48 letters, digits, dots, underscores, or hyphens')
    ipv4(('device','1','host'))
    if platform == 'ftd':
        choice(('ftd','1','manager_type'),('FMC','FDM'))
        host=('ftd','1','manager_host')
        if cells.get(host) and (len(cells[host])>253 or not re.fullmatch(r'[A-Za-z0-9.-]+',cells[host])):
            add(host,'enter an IPv4 address or resolvable DNS hostname')
        version=('ftd','1','version')
        if cells.get(version) and not re.fullmatch(r'[0-9]+(?:\.[0-9A-Za-z-]+){1,3}',cells[version]):
            add(version,'enter a release such as 7.6.1')
        for field in ('device_id','template_name'):
            key=('ftd','1',field)
            if cells.get(key) and len(cells[key])>128: add(key,'use no more than 128 characters')
        return errors

    choice(('network','1','existing_objects_action'),('reject','replace_named'))
    choice(('network','1','routing_mode'),('static','pbr'))
    ipv4(('network','1','isp_gateway'));ipv4(('network','1','router_wan_ip'))
    prefix=('network','1','prefix')
    if cells.get(prefix) and not TOKEN_PATTERN.fullmatch(cells[prefix]):
        add(prefix,'use 1-48 letters, digits, dots, underscores, plus signs, or hyphens')
    choice(('crypto','1','ike_encryption'),('aes-gcm-256','aes-cbc-256'))
    choice(('crypto','1','prf'),('sha256','sha384','sha512'))
    choice(('crypto','1','integrity'),('sha256','sha384','sha512'))
    choice(('crypto','1','esp'),('esp-gcm-256','esp-aes-256-sha256'))
    choice(('crypto','1','pfs'),('19','20'))
    dh=('crypto','1','dh_groups')
    if cells.get(dh):
        groups=cells[dh].split('|')
        if any(group not in ('19','20') for group in groups) or len(groups)!=len(set(groups)):
            add(dh,'enter unique supported groups separated by |, for example 19|20')
    integer(('crypto','1','ike_lifetime'),120,86400)
    integer(('crypto','1','ipsec_lifetime'),120,86400)
    integer(('crypto','1','dpd_interval'),10,3600)
    integer(('crypto','1','dpd_retries'),2,60)
    encryption=cells.get(('crypto','1','ike_encryption'),'')
    integrity=cells.get(('crypto','1','integrity'),'')
    if encryption=='aes-gcm-256' and integrity:
        add(('crypto','1','integrity'),'leave blank when using AES-GCM')
    if encryption=='aes-cbc-256' and not integrity:
        add(('crypto','1','integrity'),'CBC requires sha256, sha384, or sha512')
    for key in cells:
        section,item,field=key
        if section in ('management_prefix','destination_prefix','source_prefix','bypass_prefix') and field=='value': cidr(key)
        if section=='ingress_interface' and field=='value' and cells[key]:
            if not INTERFACE_PATTERN.fullmatch(cells[key]) or cells[key].startswith('Loopback'):
                add(key,'enter a physical or VLAN ingress interface, for example GigabitEthernet0/0/1')
    for section in ('management_prefix','destination_prefix','source_prefix','bypass_prefix','ingress_interface'):
        seen={}
        for key,entry in cells.items():
            if key[0]==section and key[2]=='value' and entry:
                if entry in seen: add(key,f'duplicate value; it is already present in item {seen[entry]}')
                else: seen[entry]=key[1]
    choice(('pbr','1','failure_behavior'),('normal-routing',))
    tunnel_items={item for section,item,field in cells if section=='tunnel'}
    for item in tunnel_items:
        base=lambda field: ('tunnel',item,field)
        interface_name=base('interface_name')
        if cells.get(interface_name) and not re.fullmatch(r'Tunnel[1-9][0-9]{0,9}',cells[interface_name]):
            add(interface_name,'enter TunnelN with N from 1 to 2147483647')
        elif cells.get(interface_name) and int(cells[interface_name][6:])>2147483647:
            add(interface_name,'tunnel ID must not exceed 2147483647')
        choice(base('action'),('create','reuse'));ipv4(base('headend'))
        choice(base('psk_mode'),('shared','split'));choice(base('psk_format'),('plain','type6','hex'))
        psk_mode=cells.get(base('psk_mode'),'');psk_format=cells.get(base('psk_format'),'')
        shared=cells.get(base('shared_psk'),'');local=cells.get(base('local_psk'),'');remote=cells.get(base('remote_psk'),'')
        if psk_mode=='shared' and (local or remote):
            add(base('shared_psk'),'shared mode requires blank local_psk/remote_psk')
        if psk_mode=='split' and shared:
            add(base('local_psk'),'split mode requires a blank shared_psk')
        for key_value,key_name in ((shared,'shared_psk'),(local,'local_psk'),(remote,'remote_psk')):
            if key_value and ('\r' in key_value or '\n' in key_value or len(key_value)>512):
                add(base(key_name),'use 1-512 characters without line breaks')
            if key_value and psk_format=='hex' and (len(key_value)%2 or not re.fullmatch(r'[0-9A-Fa-f]+',key_value)):
                add(base(key_name),'hex keys require an even number of hexadecimal characters')
        identity=base('local_identity')
        if cells.get(identity) and (len(cells[identity])>255 or not IDENTITY_PATTERN.fullmatch(cells[identity])):
            add(identity,'enter the portal Tunnel ID/email, for example tunnel-id@example.com')
        for field in ('source_interface','unnumbered_interface'):
            key=base(field)
            if cells.get(key) and not INTERFACE_PATTERN.fullmatch(cells[key]):
                add(key,'enter GigabitEthernet, Loopback, or Vlan followed by a valid interface number')
        cidr(base('address'),interface=True);cidr(base('source_loopback_address'),interface=True)
        loopback=base('source_loopback_address')
        if cells.get(loopback):
            try:
                if IPv4Interface(cells[loopback]).network.prefixlen!=32: add(loopback,'a source loopback address must use /32')
            except ValueError: pass
        integer(base('mtu'),576,1390);integer(base('tcp_mss'),536,1350);integer(base('distance'),1,254)
        choice(base('reuse_confirmed'),('true',))
        scope=base('change_scope')
        if len(cells.get(scope,''))>1000: add(scope,'use no more than 1000 characters')
        mtu=cells.get(base('mtu'),'');mss=cells.get(base('tcp_mss'),'')
        if mtu.isdigit() and mss.isdigit() and int(mss)>int(mtu)-40:
            add(base('tcp_mss'),'must not exceed tunnel MTU minus 40 bytes')
    return errors

def configuration_csv_template(platform='iosxe', name='', host='', mode='advanced'):
    if platform not in ('iosxe', 'ftd'):
        raise ValueError('Unsupported platform')
    if mode not in ('basic', 'advanced'):
        raise ValueError('Unsupported template mode')
    rows=[]
    def group(section, fields, item='1'):
        for field, (value, required, description) in fields.items():
            rows.append([section,item,field,value,'yes' if required else 'no',description])
    for section, fields in SCALARS.items():
        if platform == 'ftd' and section in ('network','crypto'):
            continue
        group(section, fields)
    for row in rows:
        if row[0]=='meta' and row[2]=='platform': row[3]=platform
        if row[0]=='meta' and row[2]=='template_mode': row[3]=mode
        if row[0]=='device': row[3]={'name':name,'host':host}[row[2]]
    if platform=='iosxe':
        for section, description in LISTS.items(): group(section,{'value':('',True,description)})
        group('pbr',PBR)
        group('tunnel',TUNNEL)
    else:
        group('ftd',FTD)
    if mode == 'basic' and platform == 'iosxe':
        rows = [row for row in rows if (row[0], row[2]) not in BASIC_HIDDEN]
    for row in rows:
        if row[4]=='yes' and not row[3]:
            row[3]=REQUIRED_PLACEHOLDER
    stream=io.StringIO(newline='')
    writer=csv.writer(stream,delimiter=';',lineterminator='\r\n')
    writer.writerow(COLUMNS);writer.writerows(rows)
    return {'csv_text':stream.getvalue(),'encoding':'utf-8-sig','delimiter':';','schema_version':'2',
            'platform':platform,'template_mode':mode,'apply_available':False,
            'note':'FTD template is planning-only; no FTD API/configuration adapter implemented' if platform=='ftd' else 'Test build: tunnel PSKs are accepted in CSV and are redacted from previews, diffs, and logs.'}

def import_configuration_csv(csv_text, occupied_tunnel_ids=None, include_test_secrets=False):
    base={'apply_available':False,'apply_ready':False}
    if not isinstance(csv_text,str) or len(csv_text)>200000:
        return {**base,'valid':False,'errors':['CSV size/type invalid']}
    try:
        reader=csv.DictReader(io.StringIO(csv_text.lstrip('\ufeff')),delimiter=';',strict=True)
        if reader.fieldnames!=COLUMNS:
            raise ValueError('Expected exact CSV header and semicolon delimiter')
        cells={};row_numbers={};errors=[]
        for index,row in enumerate(reader,2):
            if index>2001: raise ValueError('Too many CSV rows')
            if None in row or any(v is None for v in row.values()): raise ValueError('Malformed CSV row')
            section,item,field=[row[k].strip() for k in COLUMNS[:3]]
            value=row['value'] if field in PSK_VALUE_FIELDS else row['value'].strip()
            if value == REQUIRED_PLACEHOLDER:
                value = ''
            if not re.fullmatch(r'[1-9][0-9]{0,3}',item): errors.append(f'Row {index}: invalid item')
            key=(section,item,field)
            if key in cells: errors.append(f'Row {index}: duplicate field')
            if field not in PSK_VALUE_FIELDS and value.startswith(('=','+','-','@')): errors.append(f'Row {index}: formulas are not accepted')
            if row['required'].strip() not in ('yes','no'): errors.append(f'Row {index}: required must be yes or no')
            if not row['description'].strip(): errors.append(f'Row {index}: description must not be blank')
            cells[key]=value
            row_numbers[key]=index
        def value(s,f): return cells.get((s,'1',f),'')
        platform=value('meta','platform')
        if value('meta','schema_version')!='2':
            errors.append(f"Row {row_numbers.get(('meta','1','schema_version'),'unknown')}: meta.1.schema_version: enter 2")
        if platform not in ('iosxe','ftd'):
            errors.append(f"Row {row_numbers.get(('meta','1','platform'),'unknown')}: meta.1.platform: enter iosxe or ftd")
        template_mode=value('meta','template_mode') or 'advanced'
        if template_mode not in ('basic','advanced'):
            errors.append(f"Row {row_numbers.get(('meta','1','template_mode'),'unknown')}: meta.1.template_mode: enter basic or advanced")
        if errors: return {**base,'valid':False,'errors':errors}
        allowed={s:set(fields) for s,fields in SCALARS.items() if platform=='iosxe' or s in ('meta','device')}
        allowed.update({'ftd':set(FTD)} if platform=='ftd' else {**{s:{'value'} for s in LISTS},'pbr':set(PBR),'tunnel':set(TUNNEL)})
        for index,((s,i,f),v) in enumerate(cells.items(),2):
            if s not in allowed or f not in allowed[s] or (s not in LISTS and s!='tunnel' and i!='1'):
                errors.append(f'Row {index}: unknown field or section/item')
        if template_mode == 'basic' and platform == 'iosxe':
            for (section, field), default in BASIC_DEFAULTS.items():
                if section == 'tunnel':
                    for item in {i for s,i,f in cells if s=='tunnel'}:
                        cells.setdefault((section,item,field),default)
                else:
                    cells.setdefault((section,'1',field),default)
        inherited_fields=[]
        if platform == 'iosxe':
            tunnel_items=sorted({i for s,i,f in cells if s=='tunnel'},key=int)
            if tunnel_items:
                first=tunnel_items[0]
                for field in TUNNEL_INHERITED_FIELDS:
                    common=cells.get(('tunnel',first,field),'')
                    if common:
                        for item in tunnel_items[1:]:
                            key=('tunnel',item,field)
                            if not cells.get(key,''):
                                cells[key]=common
                                inherited_fields.append(f'tunnel.{item}.{field}')
        errors.extend(_field_errors(cells,row_numbers,platform))
        if errors: return {**base,'valid':False,'errors':errors,'inherited_fields':inherited_fields}
        missing=[]
        def required(s,fields,item='1'):
            for f,(_,needed,_) in fields.items():
                if needed and not cells.get((s,item,f),''): missing.append(f'{s}.{item}.{f}')
        for s in ('meta','device'): required(s,SCALARS[s])
        if platform=='ftd':
            required('ftd',FTD)
            return {**base,'valid':not missing,'missing_fields':missing,'platform':'ftd',
                    'public_parameters':{s:{f:value(s,f) for f in allowed[s]} for s in allowed},
                    'blockers':['FTD template format only; manager-specific template schema and API adapter not implemented'],
                    'configuration_preview':None}
        existing_action=value('network','existing_objects_action') or 'reject'
        if existing_action not in ('reject','replace_named'): raise ValueError('Invalid existing object action')
        mode=value('network','routing_mode')
        required('network',SCALARS['network']);required('crypto',SCALARS['crypto'])
        def values(section):
            return [v for (s,i,f),v in sorted(cells.items(),key=lambda x:(x[0][0],int(x[0][1]),x[0][2])) if s==section and v]
        for section in ['management_prefix','destination_prefix']+(['source_prefix','bypass_prefix','ingress_interface'] if mode=='pbr' else []):
            list_rows = sorted((int(i), v) for (s,i,f),v in cells.items() if s==section and f=='value')
            if not list_rows:
                missing.append(section)
            else:
                missing.extend(f'{section}.{item}.value' for item, entry in list_rows if not entry)
        if mode=='pbr': required('pbr',PBR)
        elif any(values(s) for s in ('source_prefix','bypass_prefix','ingress_interface')) or value('pbr','failure_behavior'):
            errors.append('PBR values require routing_mode=pbr')
        items=sorted({i for s,i,f in cells if s=='tunnel'},key=int)
        if not items: missing.append('tunnel')
        tunnels=[];intent=[];blockers=[];test_psks={}
        for item in items:
            required('tunnel',TUNNEL,item)
            t={f:v for (s,i,f),v in cells.items() if s=='tunnel' and i==item and v}
            name=t.pop('interface_name','');action=t.pop('action','')
            confirmed=t.pop('reuse_confirmed','');scope=t.pop('change_scope','')
            psk_mode=t.pop('psk_mode','');psk_format=t.pop('psk_format','')
            shared=t.pop('shared_psk','');local=t.pop('local_psk','');remote=t.pop('remote_psk','')
            if psk_mode=='shared' and not shared: missing.append(f'tunnel.{item}.shared_psk')
            if psk_mode=='split':
                if not local: missing.append(f'tunnel.{item}.local_psk')
                if not remote: missing.append(f'tunnel.{item}.remote_psk')
            if not name or not action:
                continue
            if not re.fullmatch(r'Tunnel[1-9][0-9]{0,9}',name) or action not in ('create','reuse'):
                errors.append(f'tunnel.{item}: choose TunnelN and create/reuse');continue
            number=int(name[6:]);t['tunnel_id']=number
            def encoded(secret):
                return {'format':'hex','value':secret} if psk_format=='hex' else {
                    'format':'key','encryption':6 if psk_format=='type6' else 0,'value':secret}
            if psk_mode=='shared' and shared:
                test_psks[f'{number}/{t.get("headend","")}']={'mode':'shared','shared':encoded(shared)}
            elif psk_mode=='split' and local and remote:
                test_psks[f'{number}/{t.get("headend","")}']={'mode':'split','local':encoded(local),'remote':encoded(remote)}
            if action=='reuse' and (confirmed!='true' or not scope): missing.append(f'tunnel.{item}.reuse_confirmed/change_scope')
            if action=='create' and (confirmed or scope): errors.append(f'tunnel.{item}: reuse fields require reuse action')
            if occupied_tunnel_ids is None: blockers.append('Fresh occupied tunnel inventory not supplied; interface action unverified')
            elif (action=='create' and number in occupied_tunnel_ids) or (action=='reuse' and number not in occupied_tunnel_ids):
                errors.append(f'tunnel.{item}: interface action conflicts with inventory')
            if action=='reuse': blockers.append('Reuse confirmation is caller-held; inspect current parameters and reconcile existing interface/secret choices')
            if not t.get('address') and not t.get('unnumbered_interface'): missing.append(f'tunnel.{item}.address OR unnumbered_interface')
            tunnels.append(t);intent.append({'interface_name':name,'action':action,'change_scope':scope})
        if missing or errors: return {**base,'valid':False,'missing_fields':missing,'errors':errors,'inherited_fields':inherited_fields}
        crypto={f:value('crypto',f) for f in SCALARS['crypto'] if value('crypto',f)}
        if 'dh_groups' in crypto: crypto['dh_groups']=[int(v.strip()) for v in crypto['dh_groups'].split('|')]
        if 'pfs' in crypto: crypto['pfs']=int(crypto['pfs'])
        spec=ProvisioningSpec.model_validate(dict(prefix=value('network','prefix'),isp_gateway=value('network','isp_gateway'),router_wan_ip=value('network','router_wan_ip'),routing_mode=mode,
             management_prefixes=values('management_prefix'),protected_prefixes=values('destination_prefix'),tunnels=tunnels,crypto=crypto,
             pbr=({'source_prefixes':values('source_prefix'),'ingress_interfaces':values('ingress_interface'),
                   'bypass_destination_prefixes':values('bypass_prefix'),'failure_behavior':value('pbr','failure_behavior')} if mode=='pbr' else None)))
        # Public device metadata is validated separately; no connection is opened.
        from .wizard import Target
        target=Target.model_validate({'name':value('device','name'),'host':value('device','host')})
        xml=render_netconf(spec)
        output={**base,'valid':True,'platform':'iosxe','template_mode':template_mode,'inherited_fields':inherited_fields,'target':target.model_dump(mode='json'),'provisioning_spec':spec.model_dump(mode='json'),
                'tunnel_interface_intent':intent,'existing_objects_action':existing_action,'result':render_nonsecret(spec),'netconf_preview':xml,
                'blockers':list(dict.fromkeys(blockers+['CSV approval is not device apply authorization']+xml['blockers']))}
        if include_test_secrets: output['_test_psks']=test_psks
        return output
    except ValidationError as error:
        return {**base,'valid':False,'errors':[
            'Invalid parameter '+'.'.join(map(str,e['loc']))+': '+e['msg'] for e in error.errors(include_input=False)]}
    except (ValueError,csv.Error):
        return {**base,'valid':False,'errors':['Invalid CSV structure, platform or field encoding']}
