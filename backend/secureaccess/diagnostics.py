"""Structured debug diagnostics: never stringify errors, XML or traceback locals."""
import json,logging,re,tempfile,traceback
from logging.handlers import RotatingFileHandler
from pathlib import Path
from uuid import uuid4

TAGS=set('in-use invalid-value too-big missing-attribute bad-attribute unknown-attribute missing-element bad-element unknown-element unknown-namespace access-denied lock-denied resource-denied rollback-failed data-exists data-missing operation-not-supported operation-failed malformed-message'.split())
TYPES=set('RPCError TimeoutExpiredError OperationError SSHError AuthenticationError SSHUnknownHostError TransportError SessionCloseError ValueError TypeError AttributeError XMLSyntaxError RuntimeError ApplyBlocked UnsupportedDevice'.split())
NODES=set('rpc validate source config data rpc-reply rpc-error'.split())
for p in (Path(__file__).resolve().parent/'schemas').glob('*.yang'):
    NODES.update(re.findall(r'\b(?:leaf|leaf-list|container|list)\s+([A-Za-z_][A-Za-z0-9_.-]*)',p.read_text(encoding='utf-8')))

def schema_path(value):
    if not isinstance(value,str) or len(value)>8192:return None
    out=[];depth=0;quote=None
    for c in value:
        if depth:
            if quote:
                if c==quote:quote=None
            elif c in ('"',"'"):quote=c
            elif c=='[':depth+=1
            elif c==']':depth-=1
        elif c=='[':depth=1
        else:out.append(c)
    if depth or quote:return None
    value=''.join(out)
    if not re.fullmatch(r'/?[A-Za-z0-9_.:/-]+',value):return None
    tokens=[v.rsplit(':',1)[-1] for v in value.split('/') if v]
    return '/'+ '/'.join(v if v in NODES else '<unknown-node>' for v in tokens)

def details(error,phase,events=None):
    result={'trace_id':str(uuid4()),'phase':phase,'exception_type':type(error).__name__ if type(error).__name__ in TYPES else 'Exception',
            'raw_error_omitted':True,'raw_xml_omitted':True,'trace':list(events or [])}
    candidate=getattr(error,'errors',None)
    rpc_errors=candidate if isinstance(candidate,(list,tuple)) and candidate else [error]
    entries=[]
    for e in list(rpc_errors)[:20]:
        tag=getattr(e,'tag',None)
        item={}
        if tag in TAGS:item['error_tag']=tag
        path=schema_path(getattr(e,'path',None))
        if path:item['schema_path']=path
        for attr,allowed in [('type',{'transport','rpc','protocol','application'}),('severity',{'error','warning'})]:
            value=getattr(e,attr,None)
            if value in allowed:item['error_'+attr]=value
        info=getattr(e,'info',None)
        if isinstance(info,str):
            from .discovery import parse_xml
            try:
                names=parse_xml(info).xpath("//*[local-name()='bad-element']/text()")
                item['bad_elements']=[n.rsplit(':',1)[-1] for n in names if n.rsplit(':',1)[-1] in NODES][:10]
            except Exception:pass
        if item:entries.append(item)
    if entries:result['rpc_errors']=entries
    frames=traceback.extract_tb(error.__traceback__) if error.__traceback__ else []
    result['stack']=[{'file':Path(f.filename).name,'function':f.name,'line':f.lineno} for f in frames[-8:]
                     if re.fullmatch(r'[A-Za-z0-9_.-]+',Path(f.filename).name) and re.fullmatch(r'[A-Za-z0-9_<>]+',f.name)]
    return result

def save_debug(result):
    """Fixed-size rotating sanitized log in native user temp, not plugin cache."""
    try:
        folder=Path(tempfile.gettempdir())/'Agent-for-SecureAccess';folder.mkdir(exist_ok=True)
        path=folder/'netconf-debug.jsonl'
        handler=RotatingFileHandler(path,maxBytes=1024*1024,backupCount=2,encoding='utf-8')
        record=logging.LogRecord('secureaccess.debug',logging.INFO,'',0,json.dumps(result,ensure_ascii=False),(),None)
        try:handler.emit(record)
        finally:handler.close()
        return str(path)
    except Exception:return None
