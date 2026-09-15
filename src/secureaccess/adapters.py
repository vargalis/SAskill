"""Trusted adapter registry; callers cannot supply XML or qualification booleans.

Register only adapters with exact schema/feature/deviation fixtures and lab evidence.
No device is qualified merely by advertising module names.
"""
from .workflow import TransactionAdapter, ApplyBlocked

class UnsupportedDevice(ApplyBlocked):
    pass

_adapters: list[TransactionAdapter] = []

def register_adapter(adapter: TransactionAdapter):
    required = ('qualified_for','fingerprint','build','prechecks',
                'candidate_matches','candidate_changes_owned','postchecks')
    if not getattr(adapter,'adapter_id',None) or any(not callable(getattr(adapter,k,None)) for k in required):
        raise ValueError('Incomplete transaction adapter')
    if any(a.adapter_id == adapter.adapter_id for a in _adapters):
        raise ValueError('Duplicate adapter ID')
    _adapters.append(adapter)

def select_transaction_adapter(session, spec):
    matches = [a for a in _adapters if a.qualified_for(session,spec) is True]
    if len(matches) != 1:
        raise UnsupportedDevice('No unique lab-qualified adapter for exact device schema/features/deviations')
    return matches[0]

def select_adapter(inventory):
    raise UnsupportedDevice('Legacy YAML planning is read-only; apply uses reviewed CSV plans')


from .native_adapter import IOSXENativeAdapter
register_adapter(IOSXENativeAdapter())
