import sys,unittest,json
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'backend'))
from secureaccess.diagnostics import details,schema_path
class RPCError(Exception):
    tag='unknown-element';type='application';severity='error'
    path="/ios:native/crypto:crypto/crypto:ikev2/crypto:keyring[crypto:name='PRIVATE-VALUE']/crypto:peer[crypto:name='OTHER-PRIVATE']/crypto:address"
    info='<error-info><bad-element>ipv4-address</bad-element><bad-value>PRIVATE-VALUE</bad-value></error-info>'
class DiagnosticTests(unittest.TestCase):
    def test_callable_errors_attribute_is_not_treated_as_rpc_error_list(self):
        class ErrorWithMethod(Exception):
            def errors(self): return [{'private':'must-not-be-called'}]
        result=details(ErrorWithMethod('private'),'routing')
        self.assertEqual(result['exception_type'],'Exception')
        self.assertNotIn('rpc_errors',result)
    def test_rpc_error_preserves_schema_information_without_values(self):
        result=details(RPCError('PRIVATE-VALUE XML password PSK'),'inline_validation',[{'step':'validate_rpc'}])
        text=json.dumps(result)
        self.assertNotIn('PRIVATE-VALUE',text);self.assertNotIn('OTHER-PRIVATE',text)
        self.assertEqual(result['rpc_errors'][0]['error_tag'],'unknown-element')
        self.assertIn('/native/crypto/ikev2/keyring/peer/address',text)
        self.assertEqual(result['rpc_errors'][0]['bad_elements'],['ipv4-address'])
    def test_unknown_path_nodes_and_malformed_predicates_not_echoed(self):
        self.assertEqual(schema_path('/native/SUPERPRIVATE'),'/native/<unknown-node>')
        self.assertIsNone(schema_path("/native[key='SUPERPRIVATE'"))
        self.assertIsNone(schema_path('/native/<SUPERPRIVATE>'))
    def test_python_exception_message_and_locals_omitted(self):
        try:raise TypeError('SUPERPRIVATE secret config XML')
        except Exception as error:result=details(error,'connect')
        self.assertEqual(result['exception_type'],'TypeError')
        self.assertNotIn('SUPERPRIVATE',json.dumps(result));self.assertTrue(result['stack'])
if __name__=='__main__':unittest.main()
