import sys
from pathlib import Path
import unittest
from ipaddress import IPv4Address, IPv4Network
from lxml import etree
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"backend"))
from secureaccess.provisioning import ProvisioningSpec, render_nonsecret
from secureaccess.netconf_renderer import render_netconf, N,A,R

sources=['10.10.10.0/24','10.10.11.0/24','10.10.15.0/24','10.10.20.0/24','10.10.100.0/24']
def spec(interfaces=None,tunnels=None):
    return ProvisioningSpec.model_validate(dict(routing_mode='pbr',isp_gateway='192.168.2.1',router_wan_ip='192.168.2.110',management_prefixes=[sources[0]],protected_prefixes=['0.0.0.0/0'],pbr=dict(source_prefixes=sources,ingress_interfaces=interfaces or ['GigabitEthernet0/0/1'],bypass_destination_prefixes=sources,failure_behavior='normal-routing'),tunnels=tunnels or [dict(tunnel_id=100,headend='203.0.113.20',local_identity='test@example.com',source_interface='GigabitEthernet0/0/0',address='172.16.0.1/30')]))

class Checks(unittest.TestCase):
    def xml(self,**kwargs):
        return etree.fromstring(render_netconf(spec(**kwargs))['configuration_xml_preview'].encode())
    def test_namespace_keys_and_policy(self):
        xml=self.xml(); ns={'n':N,'a':A,'r':R,'c':'http://cisco.com/ns/yang/Cisco-IOS-XE-crypto'}
        self.assertEqual(xml.xpath('//n:ip/n:access-list/a:extended/a:name/text()',namespaces=ns),['SSE-PBR-ACL'])
        self.assertEqual(xml.xpath('//n:route-map/r:route-map-without-order-seq/r:seq_no/text()',namespaces=ns),['10'])
        self.assertEqual(xml.xpath('//r:match/r:ip/r:address/r:access-list/text()',namespaces=ns),['SSE-PBR-ACL'])
        self.assertEqual(xml.xpath('//r:set/r:interface-list/text()',namespaces=ns),['Tunnel100'])
        self.assertEqual(xml.xpath('//c:policy[c:name="SSE-POLICY"]/c:match/c:address/c:local-ip/text()',namespaces=ns),['192.168.2.110'])
        self.assertEqual(xml.xpath('//n:GigabitEthernet[n:name="0/0/1"]/n:ip/n:policy/n:route-map/text()',namespaces=ns),['SSE-PBR'])
        self.assertEqual(xml.xpath('//n:Tunnel/n:name/text()',namespaces=ns),['100'])
        self.assertFalse(xml.xpath('//n:local|//*[@operation="delete"]',namespaces=ns))

    def test_packet_classification_and_order(self):
        entries=self.xml().findall('.//{%s}access-list-seq-rule'%A)
        self.assertEqual(len(entries),11)
        self.assertEqual([int(e.findtext('{%s}sequence'%A)) for e in entries],list(range(10,120,10)))
        def classify(src,dst):
            for entry in entries:
                ace=entry.find('{%s}ace-rule'%A)
                def network(address,mask):
                    wildcard=int(IPv4Address(ace.findtext('{%s}%s'%(A,mask))))
                    return IPv4Network((ace.findtext('{%s}%s'%(A,address)),(0xffffffff^wildcard).bit_count()))
                if ace.find('{%s}any'%A) is None and IPv4Address(src) not in network('ipv4-address','mask'):
                    continue
                if IPv4Address(dst) in network('dest-ipv4-address','dest-mask'):
                    return ace.findtext('{%s}action'%A)=='permit'
            return False
        for subnet in sources:
            self.assertTrue(classify(str(IPv4Network(subnet).network_address+9),'8.8.8.8'))
        for destination in ['10.10.10.9','10.10.11.9','10.10.100.9','203.0.113.20']:
            self.assertFalse(classify('10.10.15.9',destination))
        self.assertFalse(classify('10.2.3.9','8.8.8.8'))

    def test_preserve_rib(self):
        xml=self.xml(); ns={'n':N}
        self.assertEqual(xml.xpath('//n:ip-route-interface-forwarding-list/n:prefix/text()',namespaces=ns),['203.0.113.20'])
        self.assertEqual(xml.xpath('//n:fwd-list/n:fwd/text()',namespaces=ns),['192.168.2.1'])
        result=render_netconf(spec())
        self.assertTrue(result['payload_complete'])
        for key in ['schema_validated','device_qualified','apply_ready','secrets_included']:
            self.assertFalse(result[key])
        self.assertFalse(result['pbr_schema_provenance']['exact_device_augments_verified'])
        self.assertTrue(any('Exact device ACL' in b for b in result['blockers']))

    def test_multiple_ingress_and_subinterface(self):
        xml=self.xml(interfaces=['GigabitEthernet0/0/1','GigabitEthernet0/0/1.111','Vlan111'])
        self.assertEqual(len(xml.findall('.//{%s}policy'%N)),3)
        self.assertEqual(xml.findtext('.//{%s}Vlan/{%s}name'%(N,N)),'111')
        self.assertEqual(len(xml.findall('.//{%s}extended'%A)),1)

    def test_primary_secondary_leaf_list_order(self):
        tunnels=[dict(tunnel_id=100,headend='203.0.113.20',local_identity='one@example.com',source_interface='GigabitEthernet0/0/0',address='172.16.0.1/30'),
                 dict(tunnel_id=101,headend='203.0.113.21',local_identity='two@example.com',source_interface='GigabitEthernet0/0/0',address='172.16.1.1/30')]
        xml=self.xml(tunnels=tunnels);ns={'r':R}
        self.assertEqual(xml.xpath('//r:set/r:interface-list/text()',namespaces=ns),['Tunnel100','Tunnel101'])

if __name__=='__main__':
    unittest.main(argv=[sys.argv[0]],verbosity=2)
