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
def filled():
    rows=list(csv.DictReader(io.StringIO(configuration_csv_template(name='test',host='10.2.3.1')['csv_text']),delimiter=';'))
    supplied={'network':{'routing_mode':'pbr','isp_gateway':'192.168.2.1','router_wan_ip':'192.168.2.110','prefix':'SSE'},
              'management_prefix':{'value':'10.10.10.0/24'},'destination_prefix':{'value':'0.0.0.0/0'},
              'source_prefix':{'value':'10.10.10.0/24'},'bypass_prefix':{'value':'10.10.10.0/24'},
              'ingress_interface':{'value':'GigabitEthernet0/0/1'},'pbr':{'failure_behavior':'normal-routing'},
              'tunnel':{'interface_name':'Tunnel100','action':'create','headend':'203.0.113.20','local_identity':'test@example.com','source_interface':'GigabitEthernet0/0/0','address':'172.16.0.1/30','mtu':'1400','tcp_mss':'1350','distance':'1'}}
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
    def test_reject_unknown_secret_duplicate_formula(self):
        for change in ('secret','duplicate','formula'):
            rows=filled()
            if change=='secret': rows.append({**rows[0],'section':'crypto','field':'psk','value':'DO-NOT-ECHO'})
            if change=='duplicate': rows.append(dict(rows[0]))
            if change=='formula': rows[0]['value']='=EXTERNAL()'
            r=import_configuration_csv(encode(rows),[1])
            self.assertFalse(r['valid']);self.assertNotIn('DO-NOT-ECHO',str(r))
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
