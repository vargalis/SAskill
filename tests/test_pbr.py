import sys
import unittest
from pathlib import Path
from pydantic import ValidationError

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))
from secureaccess.provisioning import ProvisioningSpec, render_nonsecret
from secureaccess.netconf_renderer import render_netconf
from secureaccess.wizard import WizardState, wizard_step

sources = ['10.10.10.0/24', '10.10.11.0/24', '10.10.15.0/24', '10.10.20.0/24', '10.10.100.0/24']
network = dict(routing_mode='pbr', isp_gateway='192.168.2.1', router_wan_ip='192.168.2.110', management_prefixes=[sources[0]], protected_prefixes=['0.0.0.0/0'])
policy = dict(source_prefixes=sources, ingress_interfaces=['GigabitEthernet0/0/1'], bypass_destination_prefixes=sources, failure_behavior='normal-routing')
tunnel = dict(tunnel_id=100, headend='203.0.113.20', local_identity='test@example.com', source_interface='GigabitEthernet0/0/0', address='172.16.0.1/30')

class Checks(unittest.TestCase):
    def spec(self, **changes):
        values = dict(**network, pbr=policy, tunnels=[tunnel])
        values.update(changes)
        return ProvisioningSpec.model_validate(values)

    def test_complete_wizard(self):
        state = None
        answers = [('mode','new'), ('target',dict(name='dg-wi-r1',host='10.2.3.1')),
                   ('bootstrap',dict(management_ready=True,netconf_ready=True)),
                   ('routing',dict(reviewed=True,occupied_tunnel_ids=[1],preserve_tunnel_ids=[1],operational_table_verified=True)),
                   ('network',network), ('pbr',policy), ('tunnel_numbers',[100]), ('tunnels',[tunnel]), ('crypto',{}), ('review','confirmed')]
        for step, value in answers:
            result = wizard_step(state, {step:value})
            self.assertNotIn('error',result, result)
            state = WizardState.model_validate(result['state'])
        self.assertEqual(result['step'],'complete')
        self.assertFalse(result['apply_available'])
        self.assertEqual(result['provisioning_spec']['pbr']['source_prefixes'],sources)
        self.assertTrue(any('PBR' in b for b in result['blockers']))

    def test_forwarding_scope_and_preservation(self):
        cli = render_nonsecret(self.spec())['configuration_cli_preview']
        self.assertEqual(cli.count(' permit ip '),5)
        self.assertIn(' permit ip 10.10.100.0 0.0.0.255 0.0.0.0 255.255.255.255',cli)
        self.assertIn(' deny ip any 10.10.10.0 0.0.0.255',cli)
        self.assertIn(' deny ip any 203.0.113.20 0.0.0.0',cli)
        self.assertIn(' set interface Tunnel100',cli)
        self.assertIn(' match address local 192.168.2.110',cli)
        self.assertIn(' ip tcp adjust-mss 1350',cli)
        self.assertIn(' dpd 10 3 periodic',cli)
        self.assertNotIn(' set pfs ',cli)
        self.assertIn(' ip policy route-map SSE-PBR',cli)
        self.assertNotIn('ip local policy',cli)
        self.assertNotIn('ip route 0.0.0.0',cli)
        self.assertNotIn('ip route 10.10.',cli)
        self.assertNotIn('interface Tunnel1\n',cli)

    def test_xml_coverage_without_device_qualification(self):
        result = render_netconf(self.spec())
        self.assertTrue(result['payload_complete'])
        self.assertFalse(result['apply_ready'])
        self.assertIsInstance(result['configuration_xml_preview'], str)
        self.assertFalse(result['device_qualified'])

    def test_invalid_or_unsupported_policy(self):
        for change in [dict(pbr=None), dict(pbr={**policy,'ingress_interfaces':['GigabitEthernet0/0/1\nip local policy X']}),
                       dict(pbr={**policy,'bypass_destination_prefixes':['192.168.2.0/24']}),
                       dict(pbr={**policy,'failure_behavior':'fail-closed'}),
                       dict(pbr={**policy,'source_prefixes':['0.0.0.0/0']}),
                       dict(tunnels=[tunnel,{**tunnel,'tunnel_id':101,'headend':'203.0.113.21','address':'172.16.1.1/30'},
                                     {**tunnel,'tunnel_id':102,'headend':'203.0.113.22','address':'172.16.2.1/30'}])]:
            with self.subTest(change=change), self.assertRaises(ValidationError):
                self.spec(**change)

    def test_static_compatibility(self):
        spec = ProvisioningSpec(isp_gateway='192.168.2.1',router_wan_ip='192.168.2.110',management_prefixes=['10.10.10.0/24'],protected_prefixes=['10.20.0.0/24'],tunnels=[tunnel])
        cli = render_nonsecret(spec)['configuration_cli_preview']
        self.assertIn('ip route 10.10.10.0 255.255.255.0 192.168.2.1',cli)
        self.assertIn('ip route 10.20.0.0 255.255.255.0 Tunnel100 1',cli)
        self.assertTrue(render_netconf(spec)['payload_complete'])
        state = WizardState(mode='template',target={'name':'test'},network=dict(isp_gateway='192.168.2.1',router_wan_ip='192.168.2.110',management_prefixes=['10.10.10.0/24'],protected_prefixes=['10.20.0.0/24']))
        self.assertEqual(wizard_step(state)['step'],'tunnel_numbers')

    def test_primary_secondary_pbr_order(self):
        secondary={**tunnel,'tunnel_id':101,'headend':'203.0.113.21','address':'172.16.1.1/30'}
        cli=render_nonsecret(self.spec(tunnels=[tunnel,secondary]))['configuration_cli_preview']
        self.assertIn(' set interface Tunnel100 Tunnel101',cli)

    def test_preserved_tunnel_rejected(self):
        state = WizardState(mode='new',target={'name':'dg-wi-r1','host':'10.2.3.1'},bootstrap={'management_ready':True,'netconf_ready':True},routing={'reviewed':True,'occupied_tunnel_ids':[1],'preserve_tunnel_ids':[1]},network=network,pbr=policy)
        result = wizard_step(state,{'tunnel_numbers':[1]})
        self.assertIn('error',result)
        self.assertEqual(result['step'],'tunnel_numbers')

if __name__ == '__main__':
    unittest.main(argv=[sys.argv[0]], verbosity=2)

