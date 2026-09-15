import sys,unittest,json
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'backend'))
from secureaccess.baseline_diagnostics import diagnose_baseline
from secureaccess.discovery import parse_xml
class RPCError(Exception):
    tag='data-missing';type='application';severity='error';path=None
    info='<error-info><bad-element>id</bad-element></error-info>'
class Device:
    timeout=30
    def __init__(self):self.calls=[]
    def validate(self,source):
        self.calls.append(source)
        if source.findall('.//broken'):raise RPCError('PRIVATE-SECRET')
class Tests(unittest.TestCase):
    def test_localizes_without_exporting_values_and_restores_timeout(self):
        d=Device();snapshot=parse_xml('<data><native><hostname>PRIVATE-SECRET</hostname><broken><child><name>PRIVATE-SECRET</name></child></broken><interface><name>PRIVATE-SECRET</name></interface></native></data>')
        r=diagnose_baseline(d,snapshot)
        self.assertTrue(r['probes'][0]['accepted']);self.assertEqual(d.timeout,30)
        self.assertNotIn('PRIVATE-SECRET',json.dumps(r));self.assertFalse(r['device_written'])
        self.assertTrue(any(p['kind']=='section' for p in r['probes']))
    def test_timeout_does_not_stop_other_sections(self):
        class TimeoutExpiredError(Exception):pass
        class Slow(Device):
            def validate(self,source):
                self.calls.append(source)
                if source.findall('.//slow'):raise TimeoutExpiredError('PRIVATE-SECRET')
        d=Slow();r=diagnose_baseline(d,parse_xml('<data><native><slow><name>x</name></slow><interface><name>y</name></interface></native></data>'))
        self.assertTrue(any(p.get('exception_type')=='TimeoutExpiredError' for p in r['probes']))
        timeouts=[i for i,p in enumerate(r['probes']) if p.get('exception_type')=='TimeoutExpiredError']
        self.assertLess(timeouts[0],len(r['probes'])-1);self.assertEqual(d.timeout,30)
        self.assertNotIn('PRIVATE-SECRET',json.dumps(r))
    def test_omission_preserves_other_models_and_sections(self):
        d=Device();r=diagnose_baseline(d,parse_xml('<data><other><name>PRIVATE-SECRET</name></other><native><crypto><broken/></crypto><interface><name>x</name></interface></native></data>'))
        omit=[(probe,call) for probe,call in zip(r['probes'],d.calls) if probe['kind']=='omit-section']
        self.assertTrue(omit)
        probe,call=next((p,c) for p,c in omit if p['scope']=='/native/crypto')
        self.assertTrue(probe['accepted']);self.assertIsNotNone(call.find('other'))
        self.assertIsNotNone(call.find('native/interface'));self.assertIsNone(call.find('native/crypto'))
        self.assertNotIn('PRIVATE-SECRET',json.dumps(r))
    def test_probe_limit(self):
        d=Device();r=diagnose_baseline(d,parse_xml('<data><a/><b/><c/></data>'),max_probes=2)
        self.assertEqual(len(d.calls),2);self.assertTrue(r['truncated'])
if __name__=='__main__':unittest.main()
