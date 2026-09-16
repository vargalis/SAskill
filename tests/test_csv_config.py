import csv
import io
import sys
from pathlib import Path
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'backend'))
from secureaccess.csv_config import configuration_csv_template, import_configuration_csv,COLUMNS
from secureaccess.provisioning import CryptoParameters

def encode(rows):
    stream=io.StringIO(newline='');w=csv.DictWriter(stream,COLUMNS,delimiter=';');w.writeheader();w.writerows(rows);return stream.getvalue()
def filled(mode='advanced'):
    rows=list(csv.DictReader(io.StringIO(configuration_csv_template(name='test',host='10.2.3.1',mode=mode)['csv_text']),delimiter=';'))
    supplied={'network':{'routing_mode':'pbr','isp_gateway':'192.168.2.1','router_wan_ip':'192.168.2.110','prefix':'SSE'},
              'connection':{'username':'secureaccess-agent','password':'FIXTURE-PASSWORD'},
              'management_prefix':{'value':'10.10.10.0/24'},'destination_prefix':{'value':'0.0.0.0/0'},
              'source_prefix':{'value':'10.10.10.0/24'},'bypass_prefix':{'value':'10.10.10.0/24'},
              'ingress_interface':{'value':'GigabitEthernet0/0/1'},'pbr':{'failure_behavior':'normal-routing'},
              'tunnel':{'interface_name':'Tunnel100','action':'create','headend':'203.0.113.20','local_identity':'test@example.com','psk_mode':'shared','psk_format':'plain','shared_psk':'FIXTURE-PSK','source_interface':'GigabitEthernet0/0/0','address':'172.16.0.1/30','mtu':'1390','tcp_mss':'1350','distance':'1'}}
    supplied['crypto']={k:('|'.join(map(str,v)) if isinstance(v,list) else str(v)) for k,v in CryptoParameters().model_dump().items() if v is not None}
    for row in rows: row['value']=supplied.get(row['section'],{}).get(row['field'],row['value'])
    return rows

class Checks(unittest.TestCase):
    def test_template_incomplete(self):
        text=configuration_csv_template()['csv_text']
        self.assertIn('<<< REQUIRED >>>',text)
        rows=list(csv.DictReader(io.StringIO(text),delimiter=';'))
        self.assertTrue(all(row['description'] for row in rows))
        values={(row['section'],row['field']):row['value'] for row in rows}
        self.assertEqual(values[('crypto','ike_lifetime')],'14400')
        self.assertEqual(values[('crypto','ipsec_lifetime')],'3600')
        self.assertEqual(values[('tunnel','mtu')],'1390')
        self.assertEqual(values[('tunnel','tcp_mss')],'1350')
        r=import_configuration_csv(text)
        self.assertFalse(r['valid']);self.assertTrue(r['missing_fields']);self.assertFalse(r['apply_ready'])
        self.assertIn('management_prefix.1.value',r['missing_fields'])
    def test_complete_and_no_device_write(self):
        r=import_configuration_csv('\ufeff'+encode(filled()),[1])
        self.assertTrue(r['valid'],r)
        self.assertEqual(r['provisioning_spec']['pbr']['source_prefixes'],['10.10.10.0/24'])
        self.assertEqual(r['provisioning_spec']['protected_prefixes'],['0.0.0.0/0'])
        self.assertEqual(r['provisioning_spec']['router_wan_ip'],'192.168.2.110')
        self.assertIn('match address local 192.168.2.110',r['result']['configuration_cli_preview'])
        self.assertNotIn('ip route 0.0.0.0',r['result']['configuration_cli_preview'])
        self.assertFalse(r['apply_ready'])
    def test_basic_omits_recommended_fields_and_expands_defaults(self):
        rows=filled('basic')
        fields={(row['section'],row['field']) for row in rows}
        self.assertNotIn(('crypto','ike_encryption'),fields)
        self.assertNotIn(('tunnel','mtu'),fields)
        self.assertIn(('tunnel','headend'),fields)
        r=import_configuration_csv(encode(rows),[1])
        self.assertTrue(r['valid'],r)
        self.assertEqual(r['template_mode'],'basic')
        self.assertEqual(r['provisioning_spec']['crypto']['ike_encryption'],'aes-gcm-256')
        self.assertEqual(r['provisioning_spec']['tunnels'][0]['mtu'],1390)
        self.assertEqual(r['provisioning_spec']['pbr']['failure_behavior'],'normal-routing')
    def test_reject_unknown_secret_duplicate_formula(self):
        for change in ('secret','duplicate','formula'):
            rows=filled()
            if change=='secret': rows.append({**rows[0],'section':'crypto','field':'psk','value':'DO-NOT-ECHO'})
            if change=='duplicate': rows.append(dict(rows[0]))
            if change=='formula': rows[0]['value']='=EXTERNAL()'
            r=import_configuration_csv(encode(rows),[1])
            self.assertFalse(r['valid']);self.assertNotIn('DO-NOT-ECHO',str(r))
    def test_test_psk_is_redacted_from_public_import_and_available_only_for_apply(self):
        text=encode(filled())
        public=import_configuration_csv(text,[1])
        self.assertTrue(public['valid']);self.assertNotIn('FIXTURE-PSK',str(public));self.assertNotIn('FIXTURE-PASSWORD',str(public));self.assertNotIn('_test_psks',public)
        private=import_configuration_csv(text,[1],include_test_secrets=True)
        self.assertEqual(private['_test_psks']['100/203.0.113.20']['shared']['value'],'FIXTURE-PSK')
        self.assertEqual(private['_test_credentials']['password'],'FIXTURE-PASSWORD')
        split=filled()
        values={'psk_mode':'split','psk_format':'hex','shared_psk':'','local_psk':'A1B2','remote_psk':'C3D4'}
        for row in split:
            if row['section']=='tunnel' and row['field'] in values: row['value']=values[row['field']]
        parsed=import_configuration_csv(encode(split),[1],include_test_secrets=True)
        self.assertTrue(parsed['valid'],parsed);self.assertEqual(parsed['_test_psks']['100/203.0.113.20']['mode'],'split')
    def test_field_specific_validation_errors(self):
        cases=[
            ('device','host','not-an-ip','device.1.host: enter an IPv4 address'),
            ('crypto','dh_groups','19|14','crypto.1.dh_groups: enter unique supported groups'),
            ('source_prefix','value','10.10.10.1/24','source_prefix.1.value: enter canonical IPv4 CIDR'),
            ('ingress_interface','value','Loopback0','ingress_interface.1.value: enter a physical or VLAN'),
            ('tunnel','local_identity','invalid','tunnel.1.local_identity: enter the portal Tunnel ID/email'),
            ('tunnel','mtu','1400','tunnel.1.mtu: enter an integer from 576 to 1390'),
        ]
        for section,field,bad,expected in cases:
            with self.subTest(field=field,bad=bad):
                rows=filled()
                next(row for row in rows if row['section']==section and row['field']==field)['value']=bad
                result=import_configuration_csv(encode(rows),[1])
                self.assertFalse(result['valid'])
                self.assertTrue(any(expected in error for error in result['errors']),result)
    def test_topology_and_occupied_conflicts(self):
        self.assertFalse(import_configuration_csv(encode(filled()),[100])['valid'])
        rows=filled()
        for row in rows:
            if row['section']=='tunnel' and row['field']=='tcp_mss':row['value']='1450'
        self.assertFalse(import_configuration_csv(encode(rows),[1])['valid'])
    def test_multiple_sources(self):
        rows=filled();source=next(r for r in rows if r['section']=='source_prefix')
        rows.append({**source,'item':'2','value':'10.10.11.0/24'})
        self.assertEqual(len(import_configuration_csv(encode(rows),[1])['provisioning_spec']['pbr']['source_prefixes']),2)
    def test_bypass_rows_are_optional(self):
        rows=filled()
        for row in rows:
            if row['section']=='bypass_prefix': row['value']=''
        result=import_configuration_csv(encode(rows),[1])
        self.assertTrue(result['valid'],result)
        self.assertEqual(result['provisioning_spec']['pbr']['bypass_destination_prefixes'],[])
    def test_additional_tunnel_inherits_common_first_tunnel_fields(self):
        rows=filled()
        first=[row for row in rows if row['section']=='tunnel']
        second=[]
        replacements={'interface_name':'Tunnel101','headend':'203.0.113.21','local_identity':'test2@example.com','address':'172.16.0.5/30','source_interface':''}
        for row in first:
            copied={**row,'item':'2'}
            if copied['field'] in replacements: copied['value']=replacements[copied['field']]
            second.append(copied)
        result=import_configuration_csv(encode(rows+second),[1])
        self.assertTrue(result['valid'],result)
        self.assertIn('tunnel.2.source_interface',result['inherited_fields'])
        self.assertEqual(result['provisioning_spec']['tunnels'][1]['source_interface'],'GigabitEthernet0/0/0')
    def test_ftd_never_renders_iosxe(self):
        text=configuration_csv_template('ftd')['csv_text']
        r=import_configuration_csv(text)
        self.assertEqual(r['platform'],'ftd');self.assertIsNone(r['configuration_preview']);self.assertFalse(r['apply_ready'])
    def test_reuse_confirmation(self):
        rows=filled()
        for row in rows:
            if row['section']=='tunnel':
                if row['field']=='interface_name':row['value']='Tunnel1'
                if row['field']=='action':row['value']='reuse'
        self.assertFalse(import_configuration_csv(encode(rows),[1])['valid'])
        for row in rows:
            if row['section']=='tunnel':
                if row['field']=='reuse_confirmed':row['value']='true'
                if row['field']=='change_scope':row['value']='Reuse existing interface after review'
        self.assertTrue(import_configuration_csv(encode(rows),[1])['valid'])

if __name__=='__main__':unittest.main()
