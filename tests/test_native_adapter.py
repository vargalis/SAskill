import unittest,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'backend'))
from copy import deepcopy
from types import SimpleNamespace
from hashlib import sha256
from secureaccess.native_adapter import IOSXENativeAdapter,digest,config,psk_present,parse_routes,route_to,crypto_up,interface_up,IO,CO,RO,N,C,T,NC
from secureaccess.discovery import parse_xml
from secureaccess.workflow import ApplyBlocked
from test_csv_config import filled,encode
from secureaccess.csv_config import import_configuration_csv

BASE=f'''<data xmlns="{NC}"><native xmlns="{N}">
<hostname>test</hostname><interface><GigabitEthernet><name>0/0/0</name><ip><address><primary><address>192.168.2.110</address><mask>255.255.255.0</mask></primary></address></ip></GigabitEthernet>
<GigabitEthernet><name>0/0/1</name></GigabitEthernet><Tunnel><name>1</name><shutdown/><description>untouched</description></Tunnel></interface>
<ip><route><ip-route-interface-forwarding-list><prefix>0.0.0.0</prefix><mask>0.0.0.0</mask><fwd-list><fwd>192.168.2.1</fwd></fwd-list></ip-route-interface-forwarding-list>
<ip-route-interface-forwarding-list><prefix>10.10.10.0</prefix><mask>255.255.255.0</mask><fwd-list><fwd>10.2.3.2</fwd></fwd-list></ip-route-interface-forwarding-list></route></ip>
<crypto><ikev2 xmlns="{C}"><keyring><name>SSE-KEYRING-100</name><peer><name>SSE-PEER-100</name><address><ipv4><ipv4-address>203.0.113.20</ipv4-address><ipv4-mask>255.255.255.255</ipv4-mask></ipv4></address><pre-shared-key><key>FIXTURE-SECRET-NEVER-OUTPUT</key></pre-shared-key></peer>
<peer><name>unrelated</name><pre-shared-key><key>OTHER-SECRET</key></pre-shared-key></peer></keyring></ikev2></crypto></native></data>'''
def intent():
    p=import_configuration_csv(encode(filled()),[1]);assert p['valid'];return p
class Device:
    server_capabilities=['urn:ietf:params:netconf:capability:validate:1.1']
    def __init__(self):self.running=parse_xml(BASE);self.calls=[]
    def get_config(self,source,**kw):self.calls.append(('get',source));return SimpleNamespace(data_xml=__import__('lxml').etree.tostring(self.running,encoding='unicode'))
    def validate(self,source):self.calls.append(('validate',source if isinstance(source,str) else 'inline'))
    def edit_config(self,**kwargs):
        assert kwargs['target']=='running';assert kwargs['test_option']=='test-only'
        assert kwargs['config'].tag==f'{{{NC}}}config';self.calls.append(('edit-test-only','running'))
    def get_schema(self,identifier,format):
        s=Path(__file__).resolve().parents[1]/'backend/secureaccess/schemas'/f'{identifier}.yang'
        import html
        return SimpleNamespace(xml='<rpc-reply><data>'+html.escape(s.read_text(encoding='utf-8'))+'</data></rpc-reply>')

class NativeTests(unittest.TestCase):
    def setUp(self): self.a=IOSXENativeAdapter(schemas={});self.d=Device();self.p=intent()
    def test_pbr_preserves_default_management_other_tunnel_and_secrets(self):
        expected,payload,rollback,diff=self.a._reconcile(self.d.running,self.p)
        for path in [f'{{{N}}}native/{{{N}}}ip/{{{N}}}route',f'{{{N}}}native/{{{N}}}interface/{{{N}}}Tunnel']:
            old=self.d.running.find(path);new=expected.find(path)
            if path.endswith('Tunnel'):self.assertEqual(digest(old),digest(new))
            else:
                for r in old:self.assertTrue(any(digest(r)==digest(x) for x in new))
        self.assertNotIn('FIXTURE-SECRET',str(diff));self.assertNotIn('OTHER-SECRET',str(diff))
        self.assertNotIn('FIXTURE-SECRET',__import__('lxml').etree.tostring(payload,encoding='unicode'))
        self.assertEqual(len(expected.findall(f'.//{{{C}}}peer')),2)
        self.assertTrue(any(x['object']=='pbr_acl' for x in diff))
    def test_validation_only_never_edits(self):
        r=self.a.validate_intent(self.d,self.p)
        self.assertTrue(r['schema_validated']);self.assertFalse(r['device_written']);self.assertFalse(r['transaction_ready'])
        self.assertEqual([c for c in self.d.calls if c[0]!='get'],[('edit-test-only','running')])
    def test_existing_proposal_requires_explicit_choice(self):
        ike=self.d.running.find(f'{{{N}}}native/{{{N}}}crypto/{{{C}}}ikev2')
        from lxml import etree
        ike.append(parse_xml(f'<proposal xmlns="{C}"><name>SSE-PROPOSAL</name><encryption><aes-cbc-128/></encryption></proposal>'))
        with self.assertRaises(ApplyBlocked):self.a._reconcile(self.d.running,self.p)
        self.p['existing_objects_action']='replace_named';expected,_,_,diff=self.a._reconcile(self.d.running,self.p)
        self.assertFalse(expected.findall(f'.//{{{C}}}aes-cbc-128'))
        self.assertTrue(any(x['object']=='proposal' and x['action']=='replace' for x in diff))
    def test_reuse_chosen_tunnel_preserves_description_and_peer_psk(self):
        rows=filled()
        for r in rows:
            if r['section']=='tunnel':
                values={'interface_name':'Tunnel1','action':'reuse','reuse_confirmed':'true','change_scope':'replace VPN parameters'}
                if r['field'] in values:r['value']=values[r['field']]
        p=import_configuration_csv(encode(rows),[1]);expected,_,_,diff=self.a._reconcile(self.d.running,p)
        selected=expected.find(f'{{{N}}}native/{{{N}}}interface/{{{N}}}Tunnel')
        self.assertEqual(selected.findtext(f'{{{N}}}description'),'untouched');self.assertIsNone(selected.find(f'{{{N}}}shutdown'))
        self.assertFalse(any(x['object']=='tunnel' and x['identity']!="('1',)" for x in diff))
    def test_tunnel_create_collision_rejected(self):
        self.p['tunnel_interface_intent'][0]['action']='reuse'
        with self.assertRaises(ApplyBlocked):self.a._reconcile(self.d.running,self.p)
    def test_candidate_full_match_and_foreign_changes(self):
        self.a.build(self.d,self.p);state=self.a.states[id(self.d)];self.d.running=deepcopy(state[1])
        self.assertTrue(self.a.candidate_matches(self.d,self.p,''))
        self.d.running.find(f'{{{N}}}native/{{{N}}}hostname').text='foreign'
        self.assertFalse(self.a.candidate_matches(self.d,self.p,''));self.assertFalse(self.a.candidate_changes_owned(self.d,digest(state[0]),''))
        self.a.release(self.d);self.assertFalse(self.a.states)
    def test_schema_digest_mismatch_rejected(self):
        record={'Cisco-IOS-XE-crypto':{'revision':'2022-07-20','sha256':'wrong'}}
        self.d.server_capabilities=Device.server_capabilities+['http://cisco.com/ns/yang/Cisco-IOS-XE-crypto?module=Cisco-IOS-XE-crypto&revision=2022-07-20']
        self.assertFalse(IOSXENativeAdapter(record).qualified_for(self.d,self.p))
    def test_transport_added_newline_is_not_an_exact_schema_match(self):
        a=IOSXENativeAdapter()
        self.d.server_capabilities=Device.server_capabilities+['http://test?module='+n+'&revision='+r['revision'] for n,r in a.schemas.items() if n not in ('Cisco-IOS-XE-ip','Cisco-IOS-XE-interfaces')]
        original=self.d.get_schema
        def extra_newline(identifier,format):
            reply=original(identifier,format)
            return SimpleNamespace(xml=reply.xml.replace('</data>','\n</data>'))
        self.d.get_schema=extra_newline
        self.assertFalse(a.qualified_for(self.d,self.p))

    def test_exact_profile_and_native_submodules(self):
        a=IOSXENativeAdapter();self.d.server_capabilities=Device.server_capabilities+['http://test?module='+n+'&revision='+r['revision'] for n,r in a.schemas.items() if n not in ('Cisco-IOS-XE-ip','Cisco-IOS-XE-interfaces')]
        self.assertTrue(a.qualified_for(self.d,self.p))
    def test_psk_local_remote_both_required(self):
        peer=parse_xml(f'<peer xmlns="{C}"><pre-shared-key><local-option><key>x</key></local-option></pre-shared-key></peer>')
        self.assertFalse(psk_present(peer))
    def test_vault_psk_variants_are_injected_only_into_private_payload(self):
        variants=[
            {'mode':'shared','shared':{'format':'key','encryption':0,'value':'plain-secret'}},
            {'mode':'shared','shared':{'format':'key','encryption':6,'value':'type6-secret'}},
            {'mode':'shared','shared':{'format':'hex','value':'A1B2'}},
            {'mode':'split','local':{'format':'key','encryption':0,'value':'local-secret'},
             'remote':{'format':'hex','value':'C3D4'}},
        ]
        for record in variants:
            adapter=IOSXENativeAdapter(schemas={},secret_resolver=lambda *_args,record=record:record)
            selected=deepcopy(self.p);selected['existing_objects_action']='replace_named'
            _,payload,rollback,diff=adapter._reconcile(self.d.running,selected)
            wire=__import__('lxml').etree.tostring(payload,encoding='unicode')
            self.assertTrue(psk_present(payload.find(f'.//{{{C}}}peer')))
            for secret in ('plain-secret','type6-secret','local-secret','A1B2','C3D4'):
                self.assertNotIn(secret,str(diff))
            self.assertIn('pre-shared-key',wire)
            self.assertIn('operation="replace"',__import__('lxml').etree.tostring(rollback,encoding='unicode'))
    def test_longest_prefix_tunnel_recursion_not_hidden_by_default(self):
        routes=[{'network':__import__('ipaddress').IPv4Network('0.0.0.0/0'),'hops':['192.168.2.1'],'interfaces':['GigabitEthernet0/0/0']},
                {'network':__import__('ipaddress').IPv4Network('203.0.113.20/32'),'hops':[],'interfaces':['Tunnel1']}]
        self.assertFalse(route_to(routes,'203.0.113.20'))
    def test_unrelated_ike_sa_or_interface_not_accepted(self):
        tree=parse_xml(f'<data xmlns="{NC}"><crypto-oper-data xmlns="{CO}"><crypto-ikev2-sa><sa-data><remote-ip-addr>203.0.113.21</remote-ip-addr><sa-status>crypto-sa-status-active</sa-status></sa-data></crypto-ikev2-sa></crypto-oper-data></data>')
        self.assertFalse(crypto_up(tree,'Tunnel100','203.0.113.20'))
    def test_active_exact_ike_and_ipsec_bidirectional(self):
        tree=parse_xml(f'<data xmlns="{NC}"><crypto-oper-data xmlns="{CO}"><crypto-ikev2-sa><sa-data><remote-ip-addr>203.0.113.20</remote-ip-addr><sa-status>crypto-sa-status-active</sa-status></sa-data></crypto-ikev2-sa><crypto-ipsec-ident><interface>Tunnel100</interface><ident-data><remote-endpt-addr>203.0.113.20</remote-endpt-addr><inbound-esp-sa><dir>crypto-dir-inbound</dir><sa-status>crypto-sa-status-active</sa-status></inbound-esp-sa><outbound-esp-sa><dir>crypto-dir-outbound</dir><sa-status>crypto-sa-status-active</sa-status></outbound-esp-sa></ident-data></crypto-ipsec-ident></crypto-oper-data></data>')
        self.assertTrue(crypto_up(tree,'Tunnel100','203.0.113.20'))
    def test_partial_owned_candidate_can_be_cleaned(self):
        self.a.build(self.d,self.p);base,expected,_,_=self.a.states[id(self.d)]
        self.d.running=deepcopy(base)
        # Simulate edit-config staging one fully approved object then failing.
        wanted=expected.find(f'{{{N}}}native/{{{N}}}crypto/{{{C}}}ikev2/{{{C}}}proposal')
        self.d.running.find(f'{{{N}}}native/{{{N}}}crypto/{{{C}}}ikev2').append(deepcopy(wanted))
        self.assertTrue(self.a.candidate_changes_owned(self.d,digest(base),''))
        self.d.running.find(f'{{{N}}}native/{{{N}}}hostname').text='someone-else'
        self.assertFalse(self.a.candidate_changes_owned(self.d,digest(base),''))
    def test_unknown_peer_psk_change_is_never_owned(self):
        self.a.build(self.d,self.p);base,expected,_,_=self.a.states[id(self.d)]
        self.d.running=deepcopy(expected)
        self.d.running.find(f'.//{{{C}}}pre-shared-key/{{{C}}}key').text='foreign-key'
        self.assertFalse(self.a.candidate_changes_owned(self.d,digest(base),''))
    def test_matching_objects_not_rewritten_on_second_pass(self):
        expected,_,_,_=self.a._reconcile(self.d.running,self.p)
        p=deepcopy(self.p);p['tunnel_interface_intent'][0].update(action='reuse',change_scope='review exact settings')
        _,_,_,diff=self.a._reconcile(expected,p)
        self.assertEqual(diff,[])
    def test_metric_default_normalization(self):
        a=parse_xml(f'<fwd-list xmlns="{N}"><fwd>192.168.2.1</fwd><metric>1</metric></fwd-list>')
        b=parse_xml(f'<fwd-list xmlns="{N}"><fwd>192.168.2.1</fwd></fwd-list>')
        self.assertEqual(digest(a),digest(b))
    def test_prechecks_actual_client_and_missing_psk(self):
        from types import SimpleNamespace
        self.d._session=SimpleNamespace(_transport=SimpleNamespace(sock=SimpleNamespace(getsockname=lambda:('10.10.10.9',4444))))
        self.d.server_capabilities=Device.server_capabilities+['http://test?module='+n+'&revision='+rev for n,rev in [('Cisco-IOS-XE-interfaces-oper','2021-03-01'),('Cisco-IOS-XE-crypto-oper','2021-03-01'),('ietf-routing','2015-05-25')]]
        routing=parse_xml(f'<data xmlns="{NC}"><routing-state xmlns="{RO}"><ribs><rib><name>ipv4-default</name><routes><route><destination-prefix>10.10.10.0/24</destination-prefix><next-hop><next-hop-address>10.2.3.2</next-hop-address><outgoing-interface>GigabitEthernet0/0/1</outgoing-interface></next-hop></route><route><destination-prefix>192.168.2.0/24</destination-prefix><next-hop><outgoing-interface>GigabitEthernet0/0/0</outgoing-interface></next-hop></route></routes></rib></ribs></routing-state></data>')
        interfaces=parse_xml(f'<data xmlns="{NC}"><interfaces xmlns="{IO}"><interface><name>GigabitEthernet0/0/0</name><admin-status>if-state-up</admin-status><oper-status>if-oper-state-ready</oper-status></interface></interfaces></data>')
        self.a._oper=lambda device,ns,root:routing if ns==RO else interfaces
        self.assertTrue(self.a.prechecks(self.d,self.p))
        self.d.running.find(f'.//{{{C}}}peer/{{{C}}}pre-shared-key').getparent().remove(self.d.running.find(f'.//{{{C}}}peer/{{{C}}}pre-shared-key'))
        with self.assertRaises(ApplyBlocked):self.a.prechecks(self.d,self.p)
    def test_prechecks_reject_wan_ip_mismatch(self):
        self.p['provisioning_spec']['router_wan_ip']='192.168.2.111'
        self.d._session=SimpleNamespace(_transport=SimpleNamespace(sock=SimpleNamespace(getsockname=lambda:('10.10.10.9',4444))))
        self.d.server_capabilities=Device.server_capabilities+['http://test?module='+n+'&revision='+rev for n,rev in [('Cisco-IOS-XE-interfaces-oper','2021-03-01'),('Cisco-IOS-XE-crypto-oper','2021-03-01'),('ietf-routing','2015-05-25')]]
        routing=parse_xml(f'<data xmlns="{NC}"><routing-state xmlns="{RO}"><ribs><rib><name>ipv4-default</name><routes><route><destination-prefix>10.10.10.0/24</destination-prefix><next-hop><next-hop-address>10.2.3.2</next-hop-address><outgoing-interface>GigabitEthernet0/0/1</outgoing-interface></next-hop></route><route><destination-prefix>192.168.2.0/24</destination-prefix><next-hop><outgoing-interface>GigabitEthernet0/0/0</outgoing-interface></next-hop></route></routes></rib></ribs></routing-state></data>')
        interfaces=parse_xml(f'<data xmlns="{NC}"><interfaces xmlns="{IO}"><interface><name>GigabitEthernet0/0/0</name><admin-status>if-state-up</admin-status><oper-status>if-oper-state-ready</oper-status></interface></interfaces></data>')
        self.a._oper=lambda device,ns,root:routing if ns==RO else interfaces
        with self.assertRaisesRegex(ApplyBlocked,'router_wan_ip'):
            self.a.prechecks(self.d,self.p)
    def test_client_outside_management_rejected(self):
        self.d._session=SimpleNamespace(_transport=SimpleNamespace(sock=SimpleNamespace(getsockname=lambda:('10.99.99.9',4444))))
        routing=parse_xml(f'<data xmlns="{NC}"><routing-state xmlns="{RO}"><rib><name>ipv4-default</name><routes><route><destination-prefix>0.0.0.0/0</destination-prefix><next-hop><next-hop-address>192.168.2.1</next-hop-address></next-hop></route></routes></rib></routing-state></data>')
        self.a._oper=lambda *args:routing
        with self.assertRaises(ApplyBlocked):self.a.prechecks(self.d,self.p)
    def test_validation_fixture_cannot_enter_build(self):
        self.p['fixture_only']=True
        with self.assertRaises(ApplyBlocked):self.a.build(self.d,self.p)

    def test_inline_fixture_can_check_conflicting_ingress_without_writing(self):
        from lxml import etree
        interface=self.d.running.find(f'{{{N}}}native/{{{N}}}interface/{{{N}}}GigabitEthernet[{{{N}}}name="0/0/1"]')
        interface.append(parse_xml(f'<ip xmlns="{N}"><policy><route-map>UNRELATED-POLICY</route-map></policy></ip>'))
        before=digest(self.d.running)
        self.p.update(fixture_only=True,existing_objects_action='replace_named')
        result=self.a.validate_intent(self.d,self.p)
        self.assertTrue(result['schema_validated']);self.assertFalse(result['device_written'])
        self.assertEqual(digest(self.d.running),before)
        self.assertEqual([x for x in self.d.calls if x[0]!='get'],[('edit-test-only','running')])
        with self.assertRaises(ApplyBlocked):self.a.build(self.d,self.p)
    def test_production_csv_still_rejects_conflicting_ingress(self):
        interface=self.d.running.find(f'{{{N}}}native/{{{N}}}interface/{{{N}}}GigabitEthernet[{{{N}}}name="0/0/1"]')
        interface.append(parse_xml(f'<ip xmlns="{N}"><policy><route-map>UNRELATED-POLICY</route-map></policy></ip>'))
        self.assertEqual(self.p['existing_objects_action'],'reject')
        with self.assertRaises(ApplyBlocked):self.a._reconcile(self.d.running,self.p)

    def test_debug_records_test_only_method(self):
        events=[];result=self.a.validate_intent(self.d,self.p,events=events,probe_baseline=True)
        self.assertEqual(result['validation_method'],'edit-config test-only')
        self.assertIn('test_only_edit_config_rpc',[e['step'] for e in events])
        self.assertIn('test_only_accepted',[e['step'] for e in events])
        self.assertNotIn('baseline_validate_rpc',[e['step'] for e in events])
        self.assertEqual([c for c in self.d.calls if c[0]!='get'],[('edit-test-only','running')])
    def test_test_only_error_stops_without_mutation(self):
        events=[];before=digest(self.d.running)
        def reject(**kwargs):raise ValueError('fixture rejection')
        self.d.edit_config=reject
        with self.assertRaises(ValueError):self.a.validate_intent(self.d,self.p,events=events,probe_baseline=True)
        self.assertIn('test_only_edit_config_rpc',[e['step'] for e in events])
        self.assertEqual(digest(self.d.running),before);self.assertNotIn('recheck_running',[e['step'] for e in events])

class NamespaceTests(unittest.TestCase):
    def test_qname_namespaces_survive_config_and_rpc_wrapper(self):
        from lxml import etree
        original=parse_xml(f'<data xmlns="{NC}" xmlns:i="urn:identity"><native xmlns="{N}"><nested xmlns:j="urn:nested"><type>i:value</type><other>j:value</other></nested></native></data>')
        rebuilt=config(original)
        source=etree.Element(f'{{{NC}}}source');source.append(rebuilt)
        wire=parse_xml(etree.tostring(source))
        leaf=wire.find(f'.//{{{N}}}type');other=wire.find(f'.//{{{N}}}other')
        self.assertEqual(leaf.nsmap['i'],'urn:identity');self.assertEqual(other.nsmap['j'],'urn:nested')
        self.assertEqual(leaf.text,'i:value');self.assertEqual(original.tag,f'{{{NC}}}data')

if __name__=='__main__':unittest.main()





