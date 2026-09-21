"""IOS XE native VPN/PBR adapter with server-side validation and reconciliation.

Schema acceptance is established by exact get-schema digests AND inline validate
of the complete proposed datastore. This is distinct from testing live SA/rollback.
No CLI RPC, raw caller XML, or credential values are accepted.
"""
from copy import deepcopy
from hashlib import sha256
from ipaddress import IPv4Address, IPv4Network
from pathlib import Path
from time import monotonic, sleep
import json
import re
import threading
from lxml import etree
from .discovery import parse_xml
from .netconf_renderer import NC,N,C,T,A,R,render_netconf
from .provisioning import ProvisioningSpec
from .workflow import ApplyBlocked

IO='http://cisco.com/ns/yang/Cisco-IOS-XE-interfaces-oper'
CO='http://cisco.com/ns/yang/Cisco-IOS-XE-crypto-oper'
RO='urn:ietf:params:xml:ns:yang:ietf-routing'
KEYS={'proposal':('name',),'policy':('name',),'keyring':('name',),'peer':('name',),
      'profile':('name',),'transform-set':('tag',),'route-map':('name',),
      'extended':('name',),'Tunnel':('name',),'Loopback':('name',),
      'GigabitEthernet':('name',),'Vlan':('name',),
      'ip-route-interface-forwarding-list':('prefix','mask'),
      'fwd-list':('fwd',),'route-map-without-order-seq':('seq_no',),
      'access-list-seq-rule':('sequence',)}
SECRET=re.compile(r'password|secret|pre-shared|private-key|community|^key$|^hex$',re.I)
OPENCONFIG_VLAN='http://openconfig.net/yang/vlan'
OPENCONFIG_ACL='http://openconfig.net/yang/acl'

def identity(node):
    ns=etree.QName(node).namespace
    names=KEYS.get(etree.QName(node).localname,())
    fields=tuple(node.findtext(f'{{{ns}}}{n}') for n in names)
    return node.tag,fields

def find(parent,wanted):
    nodes=[n for n in parent if identity(n)==identity(wanted)]
    if len(nodes)>1: raise ApplyBlocked('Ambiguous native list encoding; unsupported configuration')
    return nodes[0] if nodes else None

def unstable_test_only_leaf(node):
    """Ignore the IOS XE get-config visibility artifact after test-only."""
    if node.tag != f'{{{OPENCONFIG_VLAN}}}native-vlan': return False
    ancestors=[];parent=node.getparent()
    while parent is not None and len(ancestors)<5:
        ancestors.append(etree.QName(parent).localname);parent=parent.getparent()
    return ancestors[:4]==['config','switched-vlan','ethernet','interface']

def materialized_alias(node):
    """Recognize IOS XE leaves materialized beside an equivalent canonical leaf."""
    parent=node.getparent()
    if parent is None: return False
    text=(node.text or '').strip()
    if node.tag==f'{{{C}}}local' and parent.tag==f'{{{C}}}address':
        return text==(parent.findtext(f'{{{C}}}local-ip') or '').strip()
    if node.tag==f'{{{C}}}tunnel' and parent.tag==f'{{{C}}}mode':
        return parent.find(f'{{{C}}}tunnel-choice') is not None and len(node)==0 and not text
    if node.tag==f'{{{C}}}profile' and parent.tag==f'{{{C}}}ipsec':
        canonical=parent.findtext(f'{{{C}}}profile-option/{{{C}}}name')
        return canonical is not None and text==canonical.strip()
    if node.tag==f'{{{R}}}interface' and parent.tag==f'{{{R}}}set':
        tunnel=node.findtext(f'{{{R}}}Tunnel')
        canonical=parent.findtext(f'{{{R}}}interface-list')
        return tunnel is not None and canonical==f'Tunnel{tunnel.strip()}'
    return False

def semantic(node):
    # Prefix-independent fingerprint; preserve repeated-node order for user lists.
    groups={}
    for child in node:
        if child.tag==f'{{{N}}}metric' and (child.text or '').strip()=='1': continue
        if unstable_test_only_leaf(child): continue
        if materialized_alias(child): continue
        if isinstance(child.tag,str): groups.setdefault(child.tag,[]).append(semantic(child))
    for tag,values in groups.items():
        if etree.QName(tag).localname in KEYS:
            values.sort(key=repr)
    return (node.tag,(node.text or '').strip(),tuple((tag,tuple(values)) for tag,values in sorted(groups.items())))

def digest(node): return sha256(repr(semantic(node)).encode()).hexdigest()

def digest_nonsecret(node):
    clean=deepcopy(node)
    for item in list(clean.iter()):
        if SECRET.search(etree.QName(item).localname):
            parent=item.getparent()
            if parent is not None: parent.remove(item)
    return digest(clean)

def digest_nonsecret_acl_order(node):
    """Compare ACL rule order and content while tolerating IOS XE resequencing."""
    clean=deepcopy(node)
    # IOS XE regenerates its OpenConfig ACL compatibility mirror after native
    # ACL edits. The native ACL below is the authoritative configured object.
    for item in list(clean.iter()):
        if etree.QName(item).namespace==OPENCONFIG_ACL:
            parent=item.getparent()
            if parent is not None and etree.QName(parent).namespace!=OPENCONFIG_ACL:
                parent.remove(item)
    for item in list(clean.iter()):
        if SECRET.search(etree.QName(item).localname):
            parent=item.getparent()
            if parent is not None: parent.remove(item)
    for acl in clean.findall(f'.//{{{A}}}extended'):
        entries=acl.findall(f'{{{A}}}access-list-seq-rule')
        try:
            ordered=sorted(entries,key=lambda entry:int(entry.findtext(f'{{{A}}}sequence')))
        except (TypeError,ValueError):
            ordered=entries
        for index,entry in enumerate(ordered,1):
            sequence=entry.find(f'{{{A}}}sequence')
            if sequence is not None: sequence.text=str(index*10)
    return digest(clean)

def drift_scopes(before,after,limit=32):
    """Return value-free schema scopes changed between snapshots."""
    left,right=flattened(before),flattened(after);changed=[]
    for path in sorted(left.keys()|right.keys(),key=repr):
        if left.get(path)!=right.get(path):
            names=[]
            for part in path:
                tag=part[0] if isinstance(part,tuple) else part
                if isinstance(tag,str) and tag.startswith('{'):names.append(etree.QName(tag).localname)
            scope='/'.join(names[:6]) or 'root'
            if scope not in changed:changed.append(scope)
            if len(changed)>=limit:break
    return changed

def pbr_acl_summary(tree):
    """Value-limited ACL diagnostics; no raw XML or secret-bearing nodes."""
    result=[]
    for acl in tree.findall(f'.//{{{A}}}extended'):
        rules=[]
        for entry in acl.findall(f'{{{A}}}access-list-seq-rule'):
            def one(name):
                values=entry.xpath(f".//*[local-name()='{name}']/text()")
                return values[0] if values else None
            rules.append({'sequence':one('sequence'),'action':one('action'),
                          'source':one('ipv4-address') or ('any' if entry.xpath(".//*[local-name()='any']") else None),
                          'source_mask':one('mask'),'destination':one('dest-ipv4-address'),
                          'destination_mask':one('dest-mask')})
        result.append({'name':acl.findtext(f'{{{A}}}name'),'rules':rules})
    return result


def flattened(node,path=()):
    """Qualified candidate cleanup permits only a subset of approved leaf changes."""
    out={path+((node.tag,'presence'),):(node.text or '').strip()}
    counts={}
    for child in node:
        if child.tag==f'{{{N}}}metric' and (child.text or '').strip()=='1': continue
        key=identity(child)
        if not key[1] or all(v is None for v in key[1]):
            index=counts.get(child.tag,0);counts[child.tag]=index+1;key=(child.tag,index)
        out.update(flattened(child,path+(key,)))
    return out

def data(device,datastore):
    options={'source':datastore}
    if any('netconf:capability:with-defaults:' in str(c) for c in device.server_capabilities): options['with_defaults']='explicit'
    tree=parse_xml(device.get_config(**options).data_xml)
    if etree.QName(tree).localname!='data': raise ApplyBlocked('Unexpected get-config data root')
    return tree

def config(tree):
    # Copy the complete tree: copying children separately drops inherited
    # namespace declarations used only in QName-valued text (identityref).
    root=deepcopy(tree)
    root.tag=f'{{{NC}}}config'
    root.attrib.clear()
    return root

def spec_for(intent):
    return intent if isinstance(intent,ProvisioningSpec) else ProvisioningSpec.model_validate(intent['provisioning_spec'])

def public(node):
    clean=deepcopy(node)
    for n in list(clean.iter()):
        if SECRET.search(etree.QName(n).localname):
            parent=n.getparent()
            if parent is not None: parent.remove(n)
    return etree.tostring(clean,encoding='unicode',pretty_print=True)

def schema_text(device,name):
    tree=parse_xml(device.get_schema(identifier=name,format='yang').xml)
    chunks=tree.xpath("//*[local-name()='data']/text()")
    if not chunks: raise ApplyBlocked('Required device YANG schema unavailable')
    return ''.join(chunks)

class IOSXENativeAdapter:
    adapter_id='iosxe-native-17.9-vpn-pbr-v1'
    def __init__(self,schemas=None,secret_resolver=None):
        path=Path(__file__).resolve().parent/'schemas'/'profile.json'
        self.schemas=schemas if schemas is not None else json.loads(path.read_text(encoding='utf-8'))
        self.secret_resolver=secret_resolver
        self.states={};self.mutex=threading.RLock();self.last_verification_report=None

    def qualified_for(self,device,intent):
        caps=[str(c).strip() for c in device.server_capabilities]
        if not any(c.startswith('urn:ietf:params:netconf:capability:validate:1.1') for c in caps): return False
        spec_for(intent)
        for name,record in self.schemas.items():
            advertised=[c for c in caps if re.search(r'[?&]module='+re.escape(name)+r'(&|$)',c)]
            if name not in ('Cisco-IOS-XE-ip','Cisco-IOS-XE-interfaces') and (not advertised or not any('revision='+record['revision'] in c for c in advertised)): return False
            schema=schema_text(device,name)
            # Native includes are submodules, advertised through monitoring, not hello.
            if not re.search(r'\brevision\s+'+re.escape(record['revision'])+r'\s*\{',schema): return False
            if sha256(schema.encode()).hexdigest()!=record['sha256']: return False
        return True

    def fingerprint(self,device,datastore): return digest(data(device,datastore))

    def _intent(self,intent):
        spec=spec_for(intent)
        if not isinstance(intent,dict) or 'tunnel_interface_intent' not in intent:
            raise ApplyBlocked('Apply requires CSV create/reuse intent, not a preview spec')
        selections={x['interface_name']:x for x in intent['tunnel_interface_intent']}
        if set(selections)!={f'Tunnel{x.tunnel_id}' for x in spec.tunnels}:
            raise ApplyBlocked('Tunnel selection does not match specification')
        return spec,selections,intent.get('existing_objects_action','reject')

    def _reconcile(self,baseline,intent):
        spec,selections,existing_action=self._intent(intent)
        inline_psks=intent.get('_test_psks',{}) if isinstance(intent,dict) else {}
        def resolve_psk(tunnel_id,headend):
            value=inline_psks.get(f'{tunnel_id}/{headend}')
            return value if value is not None else (self.secret_resolver(tunnel_id,headend) if self.secret_resolver else None)
        desired=parse_xml(render_netconf(spec,resolve_psk)['configuration_xml_preview'])
        expected=deepcopy(baseline);payload=etree.Element(f'{{{NC}}}config',nsmap=desired.nsmap)
        rollback=etree.Element(f'{{{NC}}}config',nsmap=desired.nsmap);diff=[]
        # Atom paths are generated locally; never selected by caller XML/XPath.
        def atom(wanted,path,kind,force_replace=False):
            parent=expected;p_parent=payload;r_parent=rollback
            for template in path:
                present=find(parent,template)
                if present is None:
                    present=etree.SubElement(parent,template.tag)
                    for key in KEYS.get(etree.QName(template).localname,()):
                        k=template.find(f'{{{etree.QName(template).namespace}}}{key}')
                        if k is not None: present.append(deepcopy(k))
                out=find(p_parent,template)
                if out is None:
                    out=etree.SubElement(p_parent,template.tag)
                    for key in KEYS.get(etree.QName(template).localname,()):
                        k=template.find(f'{{{etree.QName(template).namespace}}}{key}')
                        if k is not None: out.append(deepcopy(k))
                reverse=find(r_parent,template)
                if reverse is None:
                    reverse=etree.SubElement(r_parent,template.tag)
                    for key in KEYS.get(etree.QName(template).localname,()):
                        k=template.find(f'{{{etree.QName(template).namespace}}}{key}')
                        if k is not None: reverse.append(deepcopy(k))
                parent=present;p_parent=out;r_parent=reverse
            old=find(parent,wanted)
            replacement=deepcopy(wanted)
            if kind=='peer' and old is not None and replacement.find(f'{{{C}}}pre-shared-key') is None:
                # Secrets are copied in-memory only; unrelated peers remain outside this atom.
                for child in old:
                    if etree.QName(child).localname=='pre-shared-key': replacement.append(deepcopy(child))
            if kind=='loopback' and old is not None:
                old_address=old.find(f'{{{N}}}ip/{{{N}}}address/{{{N}}}primary')
                new_address=wanted.find(f'{{{N}}}ip/{{{N}}}address/{{{N}}}primary')
                if old_address is None or semantic(old_address)!=semantic(new_address):
                    raise ApplyBlocked('Source Loopback exists with different addressing; separate explicit interface change required')
                return # Existing Loopback and its unrelated configuration remain untouched.
            if kind=='tunnel' and old is not None:
                # Keep all unrelated interface configuration; replace only reviewed fields.
                replacement=deepcopy(old)
                for child in wanted:
                    actual=find(replacement,child)
                    if etree.QName(child).localname=='ip' and actual is not None:
                        for sub in child:
                            old_sub=find(actual,sub)
                            if etree.QName(sub).localname=='tcp' and old_sub is not None:
                                for setting in sub:
                                    prior=find(old_sub,setting)
                                    if prior is not None: old_sub.remove(prior)
                                    old_sub.append(deepcopy(setting))
                                continue
                            if old_sub is not None: actual.remove(old_sub)
                            if etree.QName(sub).localname=='address':
                                other=actual.find(f'{{{N}}}unnumbered')
                                if other is not None: actual.remove(other)
                            elif etree.QName(sub).localname=='unnumbered':
                                other=actual.find(f'{{{N}}}address')
                                if other is not None: actual.remove(other)
                            actual.append(deepcopy(sub))
                    elif etree.QName(child).localname=='tunnel' and actual is not None:
                        for setting in child:
                            prior=find(actual,setting)
                            if prior is not None: actual.remove(prior)
                            actual.append(deepcopy(setting))
                    else:
                        if actual is not None: replacement.remove(actual)
                        replacement.append(deepcopy(child))
                shutdown=replacement.find(f'{{{N}}}shutdown')
                if shutdown is not None: replacement.remove(shutdown)
            if kind=='pbr_acl' and old is not None:
                # Sequence numbers are list keys, not ACL semantics. Preserve the
                # keys of equivalent existing ACEs so removing bypass rules only
                # deletes those rules instead of rewriting every permit below them.
                def rule_without_sequence(rule):
                    body=deepcopy(rule)
                    sequence=body.find(f'{{{A}}}sequence')
                    if sequence is not None: body.remove(sequence)
                    return semantic(body)
                available={}
                for entry in old.findall(f'{{{A}}}access-list-seq-rule'):
                    available.setdefault(rule_without_sequence(entry),[]).append(entry)
                for entry in replacement.findall(f'{{{A}}}access-list-seq-rule'):
                    matches=available.get(rule_without_sequence(entry),[])
                    if not matches: continue
                    prior=matches.pop(0)
                    old_sequence=prior.find(f'{{{A}}}sequence')
                    new_sequence=entry.find(f'{{{A}}}sequence')
                    if old_sequence is not None and new_sequence is not None:
                        new_sequence.text=old_sequence.text
            if old is not None and semantic(old)==semantic(replacement): return
            if old is not None and not force_replace and existing_action!='replace_named':
                raise ApplyBlocked('Existing '+kind+' object '+str(identity(wanted)[1])+' differs; review and select existing_objects_action=replace_named')
            if old is not None: parent.remove(old)
            parent.append(deepcopy(replacement))
            if kind=='pbr_acl' and old is not None:
                # An ACL referenced by a route-map cannot be replaced as a list root
                # on this IOS XE build. Reconcile its keyed ACEs in place instead.
                edit=etree.Element(replacement.tag)
                reverse=etree.Element(old.tag)
                for container,source in ((edit,replacement),(reverse,old)):
                    key=source.find(f'{{{A}}}name')
                    if key is not None: container.append(deepcopy(key))
                old_entries={identity(x):x for x in old.findall(f'{{{A}}}access-list-seq-rule')}
                new_entries={identity(x):x for x in replacement.findall(f'{{{A}}}access-list-seq-rule')}
                for key in sorted(old_entries.keys()|new_entries.keys(),key=repr):
                    prior,current=old_entries.get(key),new_entries.get(key)
                    if prior is not None and current is not None and semantic(prior)==semantic(current): continue
                    if current is None:
                        change=etree.Element(prior.tag)
                        change.append(deepcopy(prior.find(f'{{{A}}}sequence')))
                        change.set(f'{{{NC}}}operation','delete')
                    else:
                        change=deepcopy(current);change.set(f'{{{NC}}}operation','replace')
                    edit.append(change)
                    if prior is None:
                        undo=etree.Element(current.tag)
                        undo.append(deepcopy(current.find(f'{{{A}}}sequence')))
                        undo.set(f'{{{NC}}}operation','delete')
                    else:
                        undo=deepcopy(prior);undo.set(f'{{{NC}}}operation','replace')
                    reverse.append(undo)
                p_parent.append(edit);r_parent.append(reverse)
            else:
                edit=deepcopy(replacement);edit.set(f'{{{NC}}}operation','replace');p_parent.append(edit)
            if old is None:
                reverse=etree.Element(wanted.tag)
                for key in KEYS.get(etree.QName(wanted).localname,()):
                    k=wanted.find(f'{{{etree.QName(wanted).namespace}}}{key}')
                    if k is not None: reverse.append(deepcopy(k))
                reverse.set(f'{{{NC}}}operation','delete')
            elif kind!='pbr_acl':
                reverse=deepcopy(old);reverse.set(f'{{{NC}}}operation','replace')
            if kind!='pbr_acl' or old is None: r_parent.append(reverse)
            # No raw baseline XML/PSK leaves in results. Interface diff exposes only reviewed fields.
            before=old
            after=replacement
            if kind=='tunnel':
                def owned_projection(entry):
                    if entry is None: return None
                    out=etree.Element(entry.tag)
                    for tag in ('name','shutdown','ip'):
                        child=entry.find(f'{{{N}}}{tag}')
                        if child is not None:
                            if tag=='ip':
                                ip=etree.SubElement(out,child.tag)
                                for k in ('address','unnumbered','mtu','tcp'):
                                    x=child.find(f'{{{N}}}{k}')
                                    if x is not None: ip.append(deepcopy(x))
                            else: out.append(deepcopy(child))
                    t=entry.find(f'{{{T}}}tunnel')
                    if t is not None: out.append(deepcopy(t))
                    return out
                before=owned_projection(old);after=owned_projection(replacement)
            diff.append({'object':kind,'identity':str(identity(wanted)[1]),
                         'action':'replace' if old is not None else 'create',
                         'before':public(before) if before is not None else None,'after':public(after),
                         'secrets_preserved':kind in ('peer','tunnel')})

        native=desired.find(f'{{{N}}}native');running=baseline.find(f'{{{N}}}native')
        if running is None: raise ApplyBlocked('Native running subtree missing')
        crypto=native.find(f'{{{N}}}crypto')
        for family in crypto:
            for obj in family:
                if etree.QName(obj).localname=='keyring':
                    for peer in obj.findall(f'{{{C}}}peer'): atom(peer,[native,crypto,family,obj],'peer')
                else: atom(obj,[native,crypto,family],etree.QName(obj).localname)
        interfaces=native.find(f'{{{N}}}interface');current_if=running.find(f'{{{N}}}interface')
        for interface in interfaces:
            kind=etree.QName(interface).localname;name=kind+interface.findtext(f'{{{N}}}name')
            old=find(current_if,interface) if current_if is not None else None
            if kind=='Tunnel':
                selection=selections[name]
                if (selection['action']=='create') != (old is None): raise ApplyBlocked('Tunnel create/reuse conflicts with current device')
                if selection['action']=='reuse' and not selection.get('change_scope'): raise ApplyBlocked('Reuse change scope missing')
                atom(interface,[native,interfaces],'tunnel',force_replace=selection['action']=='reuse')
            elif kind=='Loopback': atom(interface,[native,interfaces],'loopback')
            else:
                if old is None: raise ApplyBlocked('PBR ingress does not exist')
                policy=interface.find(f'{{{N}}}ip/{{{N}}}policy')
                atom(policy,[native,interfaces,interface,interface.find(f'{{{N}}}ip')],'ingress_policy')
        ip=native.find(f'{{{N}}}ip')
        if ip is not None:
            route=ip.find(f'{{{N}}}route')
            if route is not None:
                for entry in route:
                    network=IPv4Network(entry.findtext(f'{{{N}}}prefix')+'/'+entry.findtext(f'{{{N}}}mask'))
                    if network in spec.management_prefixes: continue # Preserve current management route.
                    for forward in entry.findall(f'{{{N}}}fwd-list'):
                        atom(forward,[native,ip,route,entry],'static_route')
            access=ip.find(f'{{{N}}}access-list')
            if access is not None:
                for acl in access: atom(acl,[native,ip,access],'pbr_acl')
        for route_map in native.findall(f'{{{N}}}route-map'): atom(route_map,[native],'pbr_route_map')
        return expected,payload,rollback,diff

    def validate_intent(self,device,intent,events=None,probe_baseline=False):
        def stage(name):
            if events is not None: events.append({"step":name})
        stage("schema_check")
        if not self.qualified_for(device,intent): raise ApplyBlocked('Exact device schemas differ from supported profile')
        stage('read_running')
        before=data(device,'running')
        stage('reconcile')
        expected,payload,rollback,diff=self._reconcile(before,intent)
        # RFC 6241 validate:1.1: test-only performs validation without attempting
        # to set. A successful RPC is the validation result. Full running
        # snapshots are not a stable equality oracle on IOS XE.
        stage('test_only_edit_config_rpc')
        device.edit_config(target='running',config=payload,default_operation='merge',
                           test_option='test-only',error_option='stop-on-error')
        stage('test_only_accepted')
        return {'schema_validated':True,'validation_method':'edit-config test-only',
                'diff':diff,'device_written':False,
                'transaction_ready':all(any(str(c).strip().startswith('urn:ietf:params:netconf:capability:'+k+':') for c in device.server_capabilities) for k in ('candidate','confirmed-commit')),
                'operational_qualification':'Not proven by test-only validation; postchecks remain mandatory'}

    def build(self,device,intent):
        if isinstance(intent,dict) and intent.get('fixture_only'): raise ApplyBlocked('Schema fixtures can never be applied')
        baseline=data(device,'running');expected,payload,rollback,diff=self._reconcile(baseline,intent)
        device.edit_config(target='running',config=payload,default_operation='merge',
                           test_option='test-only',error_option='stop-on-error')
        if digest(data(device,'running'))!=digest(baseline):
            raise ApplyBlocked('Running changed during test-only build validation')
        with self.mutex:
            if len(self.states)>=64 and id(device) not in self.states: raise ApplyBlocked('Too many adapter snapshots')
            self.states[id(device)]=(baseline,expected,payload,rollback)
        return etree.tostring(payload,encoding='unicode'),diff

    def candidate_matches(self,device,intent,payload):
        state=self.states.get(id(device))
        return state is not None and digest_nonsecret(data(device,'candidate'))==digest_nonsecret(state[1])

    def running_matches(self,device,intent,payload):
        state=self.states.get(id(device))
        if state is None: return False
        current=data(device,'running')
        matched=digest_nonsecret_acl_order(current)==digest_nonsecret_acl_order(state[1])
        self.last_verification_report=None if matched else {
            'changed_scopes':drift_scopes(state[1],current),
            'expected_pbr_acls':pbr_acl_summary(state[1]),
            'actual_pbr_acls':pbr_acl_summary(current),
        }
        return matched

    def rollback_running(self,device):
        state=self.states.get(id(device))
        if state is None: return False
        device.edit_config(target='running',config=state[3],default_operation='merge',
                           test_option='test-then-set',error_option='rollback-on-error')
        return digest_nonsecret(data(device,'running'))==digest_nonsecret(state[0])

    def candidate_changes_owned(self,device,baseline,payload):
        state=self.states.get(id(device))
        if state is None or digest(state[0])!=baseline: return False
        current=data(device,'candidate')
        base,wanted,actual=map(flattened,(state[0],state[1],current))
        absent=object()
        approved={k for k in base.keys()|wanted.keys() if base.get(k,absent)!=wanted.get(k,absent)}
        changed={k for k in base.keys()|actual.keys() if base.get(k,absent)!=actual.get(k,absent)}
        return changed<=approved and all(actual.get(k,absent) in (base.get(k,absent),wanted.get(k,absent)) for k in changed)

    def release(self,device):
        with self.mutex: self.states.pop(id(device),None)

    def _oper(self,device,ns,root):
        return parse_xml(device.get(filter=('subtree',f'<{root} xmlns="{ns}"/>')).data_xml)

    def prechecks(self,device,intent):
        spec,_,_=self._intent(intent)
        if any(IPv4Address(t.headend) in m for t in spec.tunnels for m in spec.management_prefixes):
            raise ApplyBlocked('Headend route would overlap management network')
        if spec.routing_mode!='pbr':
            if any(a.overlaps(b) for a in spec.protected_prefixes for b in spec.management_prefixes):
                raise ApplyBlocked('Protected static routes overlap management; use PBR or narrower routes')
        rib=self._oper(device,RO,'routing-state')
        routes=parse_routes(rib)
        if not routes: return False
        try: agent_ip=IPv4Address(device._session._transport.sock.getsockname()[0])
        except (AttributeError,ValueError,IndexError):
            raise ApplyBlocked('Cannot verify actual NETCONF client return address')
        if not any(agent_ip in m for m in spec.management_prefixes) or not route_to(routes,agent_ip,allow_tunnel=False):
            raise ApplyBlocked('Actual NETCONF client return path is outside reviewed management networks or unverified')
        for prefix in spec.management_prefixes:
            if not any(r['network']==prefix and r['hops'] and not any(i.startswith('Tunnel') for i in r['interfaces']) for r in routes): return False
        if not route_to(routes,spec.isp_gateway,allow_tunnel=False): return False
        # Operational models must be advertised at the inspected revisions.
        for model,revision in [('Cisco-IOS-XE-interfaces-oper','2021-03-01'),('Cisco-IOS-XE-crypto-oper','2021-03-01'),('ietf-routing','2015-05-25')]:
            if not any('module='+model+'&revision='+revision in str(c) for c in device.server_capabilities): return False
        interfaces=self._oper(device,IO,'interfaces')
        running=data(device,'running')
        for t in spec.tunnels:
            if not t.source_loopback_address and not interface_up(interfaces,t.source_interface): return False
            configured_sources = ({t.source_loopback_address.ip} if t.source_loopback_address else
                                  configured_interface_addresses(running, t.source_interface))
            if spec.router_wan_ip not in configured_sources:
                raise ApplyBlocked('router_wan_ip does not match the selected tunnel source interface address')
            keyring=f'{spec.prefix}-KEYRING-{t.tunnel_id}';peer=f'{spec.prefix}-PEER-{t.tunnel_id}'
            rings=running.findall(f'{{{N}}}native/{{{N}}}crypto/{{{C}}}ikev2/{{{C}}}keyring')
            match=next((r for r in rings if r.findtext(f'{{{C}}}name')==keyring),None)
            peers=match.findall(f'{{{C}}}peer') if match is not None else []
            entry=next((p for p in peers if p.findtext(f'{{{C}}}name')==peer),None)
            stored=(intent.get('_test_psks',{}).get(f'{t.tunnel_id}/{t.headend}') if isinstance(intent,dict) else None)
            if stored is None and self.secret_resolver is not None: stored=self.secret_resolver(t.tunnel_id,str(t.headend))
            if stored is None and (entry is None or not psk_present(entry)):
                raise ApplyBlocked('No PSK is available for this tunnel in the native secret store or selected device peer')
            if entry is not None:
                address=entry.findtext(f'{{{C}}}address/{{{C}}}ipv4/{{{C}}}ipv4-address')
                if address!=str(t.headend): raise ApplyBlocked('PSK peer headend differs; never transfer an existing PSK to a new peer implicitly')
        return True

    def postchecks(self,device,intent,deadline):
        spec=spec_for(intent)
        while monotonic()<deadline:
            interfaces=self._oper(device,IO,'interfaces');rib=parse_routes(self._oper(device,RO,'routing-state'))
            crypto=self._oper(device,CO,'crypto-oper-data')
            state=self.states.get(id(device))
            good=state is not None and digest_nonsecret_acl_order(data(device,'running'))==digest_nonsecret_acl_order(state[1])
            good=good and all(interface_up(interfaces,f'Tunnel{t.tunnel_id}') and interface_counters(interfaces,f'Tunnel{t.tunnel_id}') and
                route_to(rib,t.headend,allow_tunnel=False,required_hop=str(spec.isp_gateway)) and
                crypto_up(crypto,f'Tunnel{t.tunnel_id}',str(t.headend)) for t in spec.tunnels)
            good=good and all(any(r['network']==p and r['hops'] and not any(i.startswith('Tunnel') for i in r['interfaces']) for r in rib) for p in spec.management_prefixes)
            if spec.routing_mode=='static':
                good=good and all(any(r['network']==p and f'Tunnel{t.tunnel_id}' in r['interfaces'] for r in rib) for p in spec.protected_prefixes for t in spec.tunnels if t.distance==min(x.distance for x in spec.tunnels))
            if good: return True
            sleep(min(2,max(0,deadline-monotonic())))
        return False

def psk_present(peer):
    p=peer.find(f'{{{C}}}pre-shared-key')
    if p is None: return False
    def configured(n): return n is not None and any(n.findtext(f'{{{C}}}{k}') for k in ('key','hex'))
    return configured(p) or (configured(p.find(f'{{{C}}}local-option')) and configured(p.find(f'{{{C}}}remote-option')))

def interface_up(tree,name):
    return any(n.findtext(f'{{{IO}}}name')==name and n.findtext(f'{{{IO}}}admin-status')=='if-state-up' and
               n.findtext(f'{{{IO}}}oper-status')=='if-oper-state-ready' for n in tree.findall(f'.//{{{IO}}}interface'))

def configured_interface_addresses(tree, name):
    for group in tree.findall(f'{{{N}}}native/{{{N}}}interface'):
        for entry in group:
            if etree.QName(entry).localname + (entry.findtext(f'{{{N}}}name') or '') == name:
                values = entry.xpath("./*[local-name()='ip']/*[local-name()='address']//*[local-name()='address']/text()")
                result = set()
                for value in values:
                    try:
                        result.add(IPv4Address(value))
                    except ValueError:
                        continue
                return result
    return set()

def interface_counters(tree,name):
    entry=next((n for n in tree.findall(f'.//{{{IO}}}interface') if n.findtext(f'{{{IO}}}name')==name),None)
    if entry is None: return False
    stats=entry.find(f'{{{IO}}}statistics')
    if stats is None: return False
    try:
        # Active SAs plus observed VTI input/output counters; missing data is unknown.
        return all(int(stats.findtext(f'{{{IO}}}{k}',default='-1'))>0 for k in ('in-octets','out-octets'))
    except ValueError: return False

def parse_routes(tree):
    routes=[]
    for rib in tree.findall(f'.//{{{RO}}}rib'):
        # Only the global IPv4 table; a matching route in another VRF is not evidence.
        if rib.findtext(f'{{{RO}}}name')!='ipv4-default': continue
        for route in rib.findall(f'{{{RO}}}routes/{{{RO}}}route'):
            prefix=route.findtext(f'{{{RO}}}destination-prefix')
            if prefix:
                routes.append({'network':IPv4Network(prefix,strict=False),
                    'hops':route.xpath(".//*[local-name()='next-hop-address']/text()"),
                    'interfaces':route.xpath(".//*[local-name()='outgoing-interface']/text()")})
    return routes

def route_to(routes,address,allow_tunnel=False,required_hop=None):
    matches=[r for r in routes if IPv4Address(address) in r['network']]
    if not matches: return False
    best=max(r['network'].prefixlen for r in matches)
    selected=[r for r in matches if r['network'].prefixlen==best]
    if not allow_tunnel and any(any(i.startswith('Tunnel') for i in r['interfaces']) for r in selected): return False
    return all((r['hops'] or r['interfaces']) and (required_hop is None or set(r['hops'])=={required_hop}) for r in selected)

def crypto_up(tree,interface,headend):
    # Exact per-interface IPsec identity; never accept an unrelated headend's SA.
    ike=tree.findall(f'.//{{{CO}}}crypto-ikev2-sa/{{{CO}}}sa-data')
    if not any(n.findtext(f'{{{CO}}}remote-ip-addr')==headend and n.findtext(f'{{{CO}}}sa-status')=='crypto-sa-status-active' for n in ike): return False
    identities=[n for n in tree.findall(f'.//{{{CO}}}crypto-ipsec-ident') if n.findtext(f'{{{CO}}}interface')==interface]
    for ident in identities:
        data=ident.find(f'{{{CO}}}ident-data')
        if data is None or data.findtext(f'{{{CO}}}remote-endpt-addr')!=headend: continue
        if all((sa:=data.find(f'{{{CO}}}{side}-esp-sa')) is not None and
               sa.findtext(f'{{{CO}}}sa-status')=='crypto-sa-status-active' and
               sa.findtext(f'{{{CO}}}dir')==f'crypto-dir-{side}' for side in ('inbound','outbound')): return True
    return False
