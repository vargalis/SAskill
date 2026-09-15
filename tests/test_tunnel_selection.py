import sys
from pathlib import Path
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'backend'))
from secureaccess.wizard import WizardState,wizard_step

class Checks(unittest.TestCase):
    def state(self):
        return WizardState(mode='new',target={'name':'dg-wi-r1','host':'10.2.3.1'},bootstrap={'management_ready':True,'netconf_ready':True},routing={'reviewed':True,'occupied_tunnel_ids':[1,2],'preserve_tunnel_ids':[1,2]},network={'isp_gateway':'192.168.2.1','router_wan_ip':'192.168.2.110','management_prefixes':['10.10.10.0/24'],'protected_prefixes':['0.0.0.0/0']})
    def test_create_occupied_rejected(self):
        self.assertIn('error',wizard_step(self.state(),{'tunnel_numbers':[{'interface_name':'Tunnel1','action':'create'}]}))
    def test_existing_selection_and_review(self):
        r=wizard_step(self.state(),{'tunnel_numbers':[{'interface_name':'Tunnel1','action':'reuse'}]})
        self.assertNotIn('error',r)
        self.assertEqual(r['state']['tunnel_numbers'],[1])
        state=WizardState.model_validate(r['state'])
        r=wizard_step(state,{'tunnels':[{'tunnel_id':1,'headend':'203.0.113.20','local_identity':'test@example.com','source_interface':'GigabitEthernet0/0/0','address':'172.16.0.1/30'}]})
        self.assertEqual(r['step'],'tunnel_reuse_review')
        self.assertEqual(r['selected_existing_interfaces'],['Tunnel1'])
        state=WizardState.model_validate(r['state'])
        review={'confirmed':False,'change_scope':'Reuse selected interface for Secure Access','current_interfaces':[{'interface_name':'Tunnel1','shutdown':True}]}
        r=wizard_step(state,{'tunnel_reuse_review':review})
        self.assertEqual(r['step'],'tunnel_reuse_review')
        self.assertEqual(r['state']['routing']['preserve_tunnel_ids'],[1,2])
        r=wizard_step(WizardState.model_validate(r['state']),{'tunnel_reuse_review':{**review,'confirmed':True}})
        self.assertEqual(r['step'],'crypto')
        self.assertEqual(r['state']['routing']['preserve_tunnel_ids'],[2])
    def test_legacy_and_unobserved(self):
        self.assertEqual(wizard_step(self.state(),{'tunnel_numbers':[100]})['step'],'tunnels')
        self.assertIn('error',wizard_step(self.state(),{'tunnel_numbers':[{'interface_name':'Tunnel100','action':'reuse'}]}))
    def test_names_and_range(self):
        for name in ['VPN1','Tunnel0','Tunnel01','Tunnel2147483648','Tunnel1\nno shutdown']:
            self.assertIn('error',wizard_step(self.state(),{'tunnel_numbers':[{'interface_name':name,'action':'create'}]}))

if __name__=='__main__': unittest.main(verbosity=2)
