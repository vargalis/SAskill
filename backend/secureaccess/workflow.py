"""NETCONF candidate transaction engine. Payloads/secrets never enter results."""
from dataclasses import dataclass
from hashlib import sha256
from hmac import compare_digest
from time import monotonic
from typing import Protocol
from uuid import uuid4
import threading

class ApplyBlocked(RuntimeError):
    pass

class TransactionAdapter(Protocol):
    adapter_id: str
    def qualified_for(self, session, spec) -> bool: ...
    def fingerprint(self, session, datastore: str) -> str: ...
    def build(self, session, spec) -> tuple[str, list[dict]]: ...
    def prechecks(self, session, spec) -> bool: ...
    def candidate_matches(self, session, spec, payload: str) -> bool: ...
    def candidate_changes_owned(self, session, baseline: str, payload: str) -> bool: ...
    def postchecks(self, session, spec, deadline: float) -> bool: ...

@dataclass(frozen=True)
class PreparedPlan:
    plan_id: str
    approval_digest: str
    target: str
    baseline: str
    payload: str
    spec: object
    adapter_id: str
    expires_at: float
    diff: tuple

def require_capabilities(session):
    caps=[str(c).strip() for c in session.server_capabilities]
    def has(name): return any(c.startswith('urn:ietf:params:netconf:capability:'+name+':') for c in caps)
    missing=[name for name in ('candidate','validate','confirmed-commit') if not has(name)]
    if missing: raise ApplyBlocked('Required NETCONF capabilities missing: '+', '.join(missing))

class PlanStore:
    """Private, expiring, process-local plans. IDs are one-use even after uncertainty."""
    def __init__(self, clock=monotonic):
        self.clock=clock;self.plans={};self.lock=threading.Lock()
    def add(self, plan):
        with self.lock:
            self.plans={k:v for k,v in self.plans.items() if v.expires_at>self.clock()}
            if len(self.plans)>=64: raise ApplyBlocked('Too many pending plans')
            self.plans[plan.plan_id]=plan
    def consume(self, plan_id, digest):
        with self.lock:
            plan=self.plans.get(plan_id)
            if plan is None or plan.expires_at<=self.clock(): raise ApplyBlocked('Plan expired or unavailable; prepare again')
            if not compare_digest(plan.approval_digest,digest): raise ApplyBlocked('Approved digest does not match plan')
            del self.plans[plan_id]
            return plan

def prepare(session, adapter: TransactionAdapter, spec, target, store: PlanStore):
    require_capabilities(session)
    if not adapter.qualified_for(session,spec): raise ApplyBlocked('Adapter is not qualified for exact device schema/features/deviations')
    if adapter.prechecks(session,spec) is not True: raise ApplyBlocked('Management/underlay/ownership prechecks failed or unknown')
    baseline=adapter.fingerprint(session,'running')
    payload,diff=adapter.build(session,spec)
    if not payload or not diff: raise ApplyBlocked('No reconciled changes to apply')
    if adapter.fingerprint(session,'running') != baseline:
        raise ApplyBlocked('Running changed during preparation; prepare again')
    plan_id=str(uuid4())
    digest=sha256((plan_id+'\0'+target+'\0'+baseline+'\0'+payload).encode()).hexdigest()
    plan=PreparedPlan(plan_id,digest,target,baseline,payload,spec,adapter.adapter_id,store.clock()+900,tuple(diff))
    store.add(plan)
    return {'plan_id':plan_id,'approval_digest':digest,'target':target,'diff':diff,
            'expires_in_seconds':900,'apply_ready':True,'requires_exclusive_window':True,
            'secrets_included':False,'note':'Approve this exact diff and digest; plan is held only in server memory'}

def apply(session, adapter: TransactionAdapter, plan: PreparedPlan, *, exclusive_window: bool,
          confirm_timeout: int=180, postcheck_budget: int=60, reconnect=None, clock=monotonic):
    """Execute only a server-prepared, qualified plan; never fall back to running edits."""
    if exclusive_window is not True: raise ApplyBlocked('Exclusive configuration window must be confirmed')
    if plan.expires_at<=clock(): raise ApplyBlocked('Plan expired; prepare again')
    if adapter.adapter_id!=plan.adapter_id: raise ApplyBlocked('Adapter changed; prepare again')
    if not (30<=postcheck_budget<=300 and postcheck_budget+60<=confirm_timeout<=600):
        raise ApplyBlocked('Invalid confirmation timeout/postcheck budget')
    require_capabilities(session)
    if not adapter.qualified_for(session,plan.spec): raise ApplyBlocked('Adapter qualification changed')
    locks=[];dirty=False;commit_attempted=False;final_commit_attempted=False;confirmed=False
    rollback='not_required';stage='lock';error=None;cleanup_errors=[]
    try:
        for datastore in ('running','candidate'):
            session.lock(target=datastore);locks.append(datastore)
        stage='baseline'
        running=adapter.fingerprint(session,'running')
        if not compare_digest(running,plan.baseline): raise ApplyBlocked('Running changed since review; prepare again')
        if not compare_digest(adapter.fingerprint(session,'candidate'),running):
            raise ApplyBlocked('Candidate contains existing changes; no discard performed')
        if adapter.prechecks(session,plan.spec) is not True: raise ApplyBlocked('Prechecks failed or unknown under lock')
        payload,diff=adapter.build(session,plan.spec)
        if payload!=plan.payload or tuple(diff)!=plan.diff: raise ApplyBlocked('Reconciled payload changed; prepare again')
        stage='edit';dirty=True  # An RPC error/timeout can leave partial staged data.
        session.edit_config(target='candidate',config=plan.payload,default_operation='merge',error_option='stop-on-error')
        stage='candidate_check'
        if adapter.candidate_matches(session,plan.spec,plan.payload) is not True: raise ApplyBlocked('Candidate does not match approved desired state')
        stage='validate';session.validate(source='candidate')
        stage='confirmed_commit';commit_attempted=True
        session.commit(confirmed=True,timeout=confirm_timeout)
        stage='postchecks'
        deadline=clock()+postcheck_budget
        if hasattr(session,'timeout'): session.timeout=min(5,postcheck_budget/8)
        if adapter.postchecks(session,plan.spec,deadline) is not True or clock()>deadline:
            raise ApplyBlocked('Operational postchecks failed, unknown or timed out')
        stage='confirm';final_commit_attempted=True;session.commit();confirmed=True
    except Exception:
        # Never return exception text: RPC errors can contain XML and keys.
        error='NETCONF transaction failed or uncertain at '+stage
        if commit_attempted and not final_commit_attempted:
            rollback='pending_verified_reconnect'
            try: session.cancel_commit()
            except Exception: pass  # Closing original session triggers nonpersistent rollback.
        elif final_commit_attempted:
            rollback='final_commit_uncertain_manual_attention'
        elif dirty:
            try:
                if adapter.candidate_changes_owned(session,plan.baseline,plan.payload) is True:
                    session.discard_changes()
                    rollback='staged_cleanup_verified' if compare_digest(adapter.fingerprint(session,'candidate'),plan.baseline) else 'staged_cleanup_unverified'
                else: rollback='foreign_or_unknown_candidate_changes_preserved'
            except Exception: rollback='staged_cleanup_unverified'
    finally:
        for datastore in reversed(locks):
            try: session.unlock(target=datastore)
            except Exception: cleanup_errors.append('unlock_'+datastore)
        try:
            if callable(getattr(adapter,'release',None)): adapter.release(session)
        except Exception: cleanup_errors.append('adapter_release')
        try: session.close_session()
        except Exception: cleanup_errors.append('close_session')
    if commit_attempted and not confirmed and not final_commit_attempted and reconnect is not None:
        try:
            with reconnect() as device:
                rollback='verified' if compare_digest(adapter.fingerprint(device,'running'),plan.baseline) else 'unverified'
        except Exception: rollback='unverified'
    return {'applied':confirmed,'status':'applied' if confirmed else ('uncertain' if final_commit_attempted else 'failed'),
            'rollback_status':rollback,'error':error,'plan_id':plan.plan_id,'secrets_included':False,
            'cleanup_errors':cleanup_errors,
            'startup_persisted':False,'note':'Running configuration only; startup persistence is a separate operation'}
