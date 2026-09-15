import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"backend"))
import unittest
from contextlib import contextmanager
@contextmanager
def raises(expected):
    try: yield
    except expected: return
    raise AssertionError('Expected exception')
def parametrize(name,values):
    def decorate(fn):
        fn.cases=values
        return fn
    return decorate
from secureaccess.workflow import PlanStore,prepare,apply,ApplyBlocked,require_capabilities

CAPS=['urn:ietf:params:netconf:capability:'+v+':1.1' for v in ('candidate','validate','confirmed-commit')]
class Session:
    server_capabilities=CAPS
    def __init__(self,fail=None):
        self.running='base';self.candidate='base';self.calls=[];self.fail=fail
    def call(self,name):
        self.calls.append(name)
        if self.fail==name: raise RuntimeError('secret PSK and XML must not escape')
    def lock(self,target): self.call('lock_'+target)
    def unlock(self,target): self.call('unlock_'+target)
    def edit_config(self,**kw):
        assert kw['target']=='candidate'
        self.candidate='new';self.call('edit')
    def validate(self,source): assert source=='candidate';self.call('validate')
    def commit(self,confirmed=False,timeout=None):
        self.call('confirmed' if confirmed else 'confirm');self.running=self.candidate
    def cancel_commit(self): self.call('cancel');self.running='base'
    def discard_changes(self): self.call('discard');self.candidate=self.running
    def close_session(self): self.call('close')
    def __enter__(self): return self
    def __exit__(self,*args): self.close_session()
class Adapter:
    adapter_id='TEST-ONLY-not-registered'
    qualified=True;healthy=True;owned=True;pre=True;match=True
    def qualified_for(self,s,spec): return self.qualified
    def fingerprint(self,s,d): return getattr(s,d)
    def build(self,s,spec): return '<config/>',[{'object':'test','action':'create'}]
    def prechecks(self,s,spec): return self.pre
    def candidate_matches(self,s,spec,payload): return self.match and s.candidate=='new'
    def candidate_changes_owned(self,s,baseline,payload): return self.owned
    def postchecks(self,s,spec,deadline): return self.healthy
def plan(s=None,a=None):
    s=s or Session();a=a or Adapter();store=PlanStore(clock=lambda:1)
    public=prepare(s,a,{},'host',store)
    return s,a,store.consume(public['plan_id'],public['approval_digest'])
def run(s,a,p,**kw): return apply(s,a,p,exclusive_window=True,clock=lambda:2,**kw)
def test_success_real_rpc_order():
    s,a,p=plan();r=run(s,a,p)
    assert r['applied'] and not r['startup_persisted']
    assert s.calls==['lock_running','lock_candidate','edit','validate','confirmed','confirm','unlock_candidate','unlock_running','close']
@parametrize('missing',['candidate','validate','confirmed-commit'])
def test_missing_capabilities_no_write(missing):
    s=Session();s.server_capabilities=[c for c in CAPS if ':'+missing+':' not in c]
    with raises(ApplyBlocked): prepare(s,Adapter(),{},'host',PlanStore())
    assert not s.calls
def test_dirty_candidate_preserved():
    s,a,p=plan();s.candidate='someone-else';r=run(s,a,p)
    assert not r['applied'] and 'edit' not in s.calls and 'discard' not in s.calls
def test_running_drift_no_edit():
    s,a,p=plan();s.running='drift';r=run(s,a,p)
    assert not r['applied'] and 'edit' not in s.calls
@parametrize('phase',['edit','validate'])
def test_failed_staging_cleanup_and_no_secret(phase):
    s,a,p=plan();s.fail=phase;r=run(s,a,p)
    assert r['rollback_status']=='staged_cleanup_verified'
    assert 'confirmed' not in s.calls and 'PSK' not in str(r)
def test_foreign_staging_not_discarded():
    s,a,p=plan();s.fail='validate';a.owned=False;r=run(s,a,p)
    assert 'discard' not in s.calls and 'preserved' in r['rollback_status']
def test_postcheck_failure_verified_rollback():
    s,a,p=plan();a.healthy=False;r=run(s,a,p,reconnect=lambda:s)
    assert not r['applied'] and r['rollback_status']=='verified' and 'confirm' not in s.calls
def test_confirm_uncertainty_never_replayed_or_cancelled():
    s,a,p=plan();s.fail='confirm';r=run(s,a,p)
    assert r['status']=='uncertain' and 'cancel' not in s.calls and s.calls.count('confirm')==1
def test_expiry_digest_and_one_use():
    s=Session();store=PlanStore(clock=lambda:1);r=prepare(s,Adapter(),{},'host',store)
    with raises(ApplyBlocked): store.consume(r['plan_id'],'wrong')
    store.consume(r['plan_id'],r['approval_digest'])
    with raises(ApplyBlocked): store.consume(r['plan_id'],r['approval_digest'])
    r=prepare(s,Adapter(),{},'host',store);store.clock=lambda:1000
    with raises(ApplyBlocked): store.consume(r['plan_id'],r['approval_digest'])
def test_qualification_precheck_and_approval_gates():
    s,a,p=plan();a.qualified=False
    with raises(ApplyBlocked): run(s,a,p)
    assert not s.calls
    a.qualified=True
    with raises(ApplyBlocked): apply(s,a,p,exclusive_window=False)
def test_lock_failure_releases_acquired_lock():
    s,a,p=plan();s.fail='lock_candidate';r=run(s,a,p)
    assert not r['applied'] and 'unlock_running' in s.calls and 'edit' not in s.calls

class TransactionTests(unittest.TestCase): pass
for name,fn in list(globals().items()):
    if name.startswith('test_') and callable(fn):
        if hasattr(fn,'cases'):
            for index,value in enumerate(fn.cases):
                def wrapper(self,fn=fn,value=value): fn(value)
                setattr(TransactionTests,name+'_'+str(index),wrapper)
        else:
            def wrapper(self,fn=fn): fn()
            setattr(TransactionTests,name,wrapper)
del fn, name
if __name__=='__main__': unittest.main()
