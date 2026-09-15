"""Public CSV configuration templates and strict offline plan import. No device I/O."""
import csv
import io
import re
from pydantic import ValidationError
from .provisioning import ProvisioningSpec, CryptoParameters, render_nonsecret
from .netconf_renderer import render_netconf

COLUMNS = ['section', 'item', 'field', 'value', 'required', 'description']
SCALARS = {
    'meta': {'schema_version': ('2', True, 'Версия формата; не менять'), 'platform': ('iosxe', True, 'iosxe или ftd')},
    'device': {'name': ('', True, 'Имя устройства'), 'host': ('', True, 'IP управления')},
    'network': {'existing_objects_action': ('', False, 'reject по умолчанию; replace_named разрешает замену только перечисленных именованных объектов после diff'), 'routing_mode': ('', True, 'static или pbr'), 'isp_gateway': ('', True, 'Шлюз ISP'), 'router_wan_ip': ('', True, 'IPv4-адрес WAN-интерфейса для match address local в IKEv2 policy'), 'prefix': ('', True, 'Префикс имён объектов')},
    'crypto': {name: ('', name != 'integrity' and name != 'pfs', 'Параметр из согласованной настройки Secure Access; группы DH через |') for name in CryptoParameters.model_fields},
}
LISTS = {'management_prefix':'Сеть управления; CIDR', 'destination_prefix':'Сеть НАЗНАЧЕНИЯ Secure Access; CIDR',
         'source_prefix':'Сеть ИСТОЧНИКА PBR; CIDR', 'bypass_prefix':'Исключение PBR по НАЗНАЧЕНИЮ; CIDR',
         'ingress_interface':'Входной интерфейс PBR; не выводится из обратного маршрута'}
TUNNEL = {
    'interface_name': ('', True, 'Выберите TunnelN'), 'action': ('', True, 'create или reuse'),
    'headend': ('', True, 'IPv4 headend'), 'local_identity': ('', True, 'Local IKE identity; без PSK'),
    'source_interface': ('', True, 'WAN/source interface'), 'address': ('', False, 'IPv4 VTI с маской; либо unnumbered_interface'),
    'unnumbered_interface': ('', False, 'Вместо address'), 'source_loopback_address': ('', False, 'Только при создании source Loopback'),
    'mtu': ('', True, 'Подтвердите MTU'), 'tcp_mss': ('', True, 'Подтвердите MSS'), 'distance': ('', True, 'Administrative distance'),
    'reuse_confirmed': ('', False, 'Для reuse: true после просмотра текущих и желаемых параметров'),
    'change_scope': ('', False, 'Для reuse: точные границы изменения'),
}
PBR = {'failure_behavior': ('', True, 'normal-routing; подтвердите возврат к RIB/ISP при отказе VTI')}
FTD = {'manager_type': ('', True, 'FMC или FDM; будущий адаптер'), 'manager_host': ('', True, 'Адрес менеджера'),
       'device_id': ('', True, 'Идентификатор устройства'), 'version': ('', True, 'Версия FTD'),
       'template_name': ('', True, 'Имя будущего квалифицированного шаблона')}

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
            if not values(section): missing.append(section)
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
