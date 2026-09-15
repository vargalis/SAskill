"""Public CSV configuration templates and strict offline plan import. No device I/O."""
import csv
import io
import re
from pydantic import ValidationError
from .provisioning import ProvisioningSpec, CryptoParameters, render_nonsecret
from .netconf_renderer import render_netconf

COLUMNS = ['section', 'item', 'field', 'value', 'required', 'description']
REQUIRED_PLACEHOLDER = '<<< REQUIRED >>>'
SCALARS = {
    'meta': {
        'schema_version': ('2', True, 'Keep 2. This identifies the CSV schema and must not be edited.'),
        'platform': ('iosxe', True, 'Enter iosxe or ftd. Use iosxe for Cisco ISR-G2, ISR4K, or CSR routers.'),
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
        'prefix': ('', True, 'Enter a short IOS XE object-name prefix, for example sse. Recommendation: use letters, digits, hyphens, or underscores and keep it unique.'),
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
    'local_identity': ('', True, 'Enter the Tunnel ID/email from the Secure Access portal. Never place the tunnel passphrase or PSK in this CSV.'),
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

def configuration_csv_template(platform='iosxe', name='', host=''):
    if platform not in ('iosxe', 'ftd'):
        raise ValueError('Unsupported platform')
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
        if row[0]=='device': row[3]={'name':name,'host':host}[row[2]]
    if platform=='iosxe':
        for section, description in LISTS.items(): group(section,{'value':('',True,description)})
        group('pbr',PBR)
        group('tunnel',TUNNEL)
    else:
        group('ftd',FTD)
    for row in rows:
        if row[4]=='yes' and not row[3]:
            row[3]=REQUIRED_PLACEHOLDER
    stream=io.StringIO(newline='')
    writer=csv.writer(stream,delimiter=';',lineterminator='\r\n')
    writer.writerow(COLUMNS);writer.writerows(rows)
    return {'csv_text':stream.getvalue(),'encoding':'utf-8-sig','delimiter':';','schema_version':'2',
            'platform':platform,'apply_available':False,
            'note':'FTD template is planning-only; no FTD API/configuration adapter implemented' if platform=='ftd' else 'Fill values only; copy list/tunnel rows with distinct item numbers. No passwords or PSKs.'}

def import_configuration_csv(csv_text, occupied_tunnel_ids=None):
    base={'apply_available':False,'apply_ready':False}
    if not isinstance(csv_text,str) or len(csv_text)>200000:
        return {**base,'valid':False,'errors':['CSV size/type invalid']}
    try:
        reader=csv.DictReader(io.StringIO(csv_text.lstrip('\ufeff')),delimiter=';',strict=True)
        if reader.fieldnames!=COLUMNS:
            raise ValueError('Expected exact CSV header and semicolon delimiter')
        cells={};errors=[]
        for index,row in enumerate(reader,2):
            if index>2001: raise ValueError('Too many CSV rows')
            if None in row or any(v is None for v in row.values()): raise ValueError('Malformed CSV row')
            section,item,field,value=[row[k].strip() for k in COLUMNS[:4]]
            if value == REQUIRED_PLACEHOLDER:
                value = ''
            if not re.fullmatch(r'[1-9][0-9]{0,3}',item): errors.append(f'Row {index}: invalid item')
            key=(section,item,field)
            if key in cells: errors.append(f'Row {index}: duplicate field')
            if value.startswith(('=','+','-','@')): errors.append(f'Row {index}: formulas are not accepted')
            cells[key]=value
        def value(s,f): return cells.get((s,'1',f),'')
        platform=value('meta','platform')
        if platform not in ('iosxe','ftd') or value('meta','schema_version')!='2':
            raise ValueError('Unsupported platform/schema version')
        allowed={s:set(fields) for s,fields in SCALARS.items() if platform=='iosxe' or s in ('meta','device')}
        allowed.update({'ftd':set(FTD)} if platform=='ftd' else {**{s:{'value'} for s in LISTS},'pbr':set(PBR),'tunnel':set(TUNNEL)})
        for index,((s,i,f),v) in enumerate(cells.items(),2):
            if s not in allowed or f not in allowed[s] or (s not in LISTS and s!='tunnel' and i!='1'):
                errors.append(f'Row {index}: unknown field or section/item')
        if errors: return {**base,'valid':False,'errors':errors}
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
        tunnels=[];intent=[];blockers=[]
        for item in items:
            required('tunnel',TUNNEL,item)
            t={f:v for (s,i,f),v in cells.items() if s=='tunnel' and i==item and v}
            name=t.pop('interface_name','');action=t.pop('action','')
            confirmed=t.pop('reuse_confirmed','');scope=t.pop('change_scope','')
            if not re.fullmatch(r'Tunnel[1-9][0-9]{0,9}',name) or action not in ('create','reuse'):
                errors.append(f'tunnel.{item}: choose TunnelN and create/reuse');continue
            number=int(name[6:]);t['tunnel_id']=number
            if action=='reuse' and (confirmed!='true' or not scope): missing.append(f'tunnel.{item}.reuse_confirmed/change_scope')
            if action=='create' and (confirmed or scope): errors.append(f'tunnel.{item}: reuse fields require reuse action')
            if occupied_tunnel_ids is None: blockers.append('Fresh occupied tunnel inventory not supplied; interface action unverified')
            elif (action=='create' and number in occupied_tunnel_ids) or (action=='reuse' and number not in occupied_tunnel_ids):
                errors.append(f'tunnel.{item}: interface action conflicts with inventory')
            if action=='reuse': blockers.append('Reuse confirmation is caller-held; inspect current parameters and reconcile existing interface/secret choices')
            if not t.get('address') and not t.get('unnumbered_interface'): missing.append(f'tunnel.{item}.address OR unnumbered_interface')
            tunnels.append(t);intent.append({'interface_name':name,'action':action,'change_scope':scope})
        if missing or errors: return {**base,'valid':False,'missing_fields':missing,'errors':errors}
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
        return {**base,'valid':True,'platform':'iosxe','target':target.model_dump(mode='json'),'provisioning_spec':spec.model_dump(mode='json'),
                'tunnel_interface_intent':intent,'existing_objects_action':existing_action,'result':render_nonsecret(spec),'netconf_preview':xml,
                'blockers':list(dict.fromkeys(blockers+['CSV approval is not device apply authorization']+xml['blockers']))}
    except ValidationError as error:
        return {**base,'valid':False,'errors':['Invalid parameter: '+'.'.join(map(str,e['loc'])) for e in error.errors(include_input=False)]}
    except (ValueError,csv.Error):
        return {**base,'valid':False,'errors':['Invalid CSV structure, platform or field encoding']}
