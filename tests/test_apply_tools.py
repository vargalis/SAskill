import sys,unittest,runpy
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'backend'))
from secureaccess.csv_config import configuration_csv_template
from test_csv_config import filled,encode
class ToolTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.tools=runpy.run_path(str(Path(__file__).resolve().parents[1]/'scripts/server.py'))
    def invoke_without_connection(self,name,*args):
        fn=self.tools[name];g=fn.__globals__;old=g['session']
        calls=[]
        def forbidden():
            calls.append(True)
            raise AssertionError('Unexpected device connection')
        g['session']=forbidden
        try:
            result=fn(*args)
            self.assertEqual(calls,[],"Unexpected connection attempt")
            return result
        finally:g['session']=old
    def test_invalid_csv_and_ftd_never_connect(self):
        for name in ('validate_configuration_csv','prepare_configuration_apply'):
            for text in ('invalid',configuration_csv_template('ftd')['csv_text']):
                result=self.invoke_without_connection(name,text)
                self.assertFalse(result['device_written'])
    def test_foreign_csv_target_never_connects(self):
        rows=filled()
        for row in rows:
            if row['section']=='device' and row['field']=='host':row['value']='10.2.3.99'
        for name in ('validate_configuration_csv','prepare_configuration_apply'):
            result=self.invoke_without_connection(name,encode(rows));self.assertIn('target',result['error'])
    def test_unapproved_window_never_connects(self):
        result=self.invoke_without_connection('apply_configuration_plan','bad','bad',False)
        self.assertFalse(result['applied'])
    def test_missing_plan_not_consumed_no_connection(self):
        result=self.invoke_without_connection('apply_configuration_plan','missing','wrong',True)
        self.assertFalse(result['applied']);self.assertFalse(result['plan_consumed'])
if __name__=='__main__':unittest.main()
