"""Bounded inline-only probes. Partial-tree failures are clues, not proof of invalid config."""
from collections import deque
from copy import deepcopy
from time import monotonic
from lxml import etree
from .netconf_renderer import NC
from .diagnostics import details,schema_path

def diagnose_baseline(device,snapshot,max_probes=40,budget=45):
    started=monotonic();results=[];old_timeout=getattr(device,'timeout',None)
    queue=deque([([],[],'empty-control')])
    priorities=('crypto','interface','ip','route-map','policy')
    for node in snapshot:
        if etree.QName(node).localname=='native':
            for name in priorities:
                if any(etree.QName(c).localname==name for c in node):
                    queue.append(([node],[],('omit-section',name)))
    for node in snapshot:
        if etree.QName(node).localname=='native':
            # Full native snapshot already failed; inspect its sections directly.
            for child in sorted(node,key=lambda c: priorities.index(etree.QName(c).localname) if etree.QName(c).localname in priorities else len(priorities)):
                queue.append(([node],[child],'section'))
        else:queue.append(([],[node],'model'))
    try:
        while queue and len(results)<max_probes and monotonic()-started<budget:
            parents,nodes,kind=queue.popleft()
            cfg=etree.Element(f'{{{NC}}}config');parent=cfg
            omission=isinstance(kind,tuple)
            if omission:
                for original in snapshot:
                    clone=deepcopy(original)
                    if original is parents[0]:
                        for child in list(clone):
                            if etree.QName(child).localname==kind[1]:clone.remove(child)
                    cfg.append(clone)
                result={'scope':schema_path('/native/'+kind[1]),'kind':'omit-section','context':'full-snapshot-except-scope'}
            for ancestor in ([] if omission else parents):
                wrapper=etree.SubElement(parent,ancestor.tag)
                # Retain original list keys, without exporting their values.
                for child in ancestor:
                    if len(child)==0 and etree.QName(child).localname in ('name','id','tag','prefix','mask','sequence','seq_no'):
                        wrapper.append(deepcopy(child))
                parent=wrapper
            for node in nodes:parent.append(deepcopy(node))
            rawpath='/'+ '/'.join(etree.QName(n).localname for n in parents+nodes)
            if not omission:result={'scope':schema_path(rawpath) or '/','kind':kind}
            if old_timeout is not None:device.timeout=max(0.1,min(8,budget-(monotonic()-started)))
            try:
                device.validate(source=cfg);result['accepted']=True
            except Exception as error:
                result['accepted']=False
                diagnostic=details(error,'baseline_subtree_probe')
                result['exception_type']=diagnostic['exception_type']
                result['rpc_errors']=diagnostic.get('rpc_errors',[])
                missing_id=any(e.get('error_tag')=='data-missing' and 'id' in e.get('bad_elements',[]) for e in result['rpc_errors'])
                if (missing_id or diagnostic['exception_type']=='TimeoutExpiredError') and not omission and len(nodes)==1 and len(parents)<6:
                    for child in nodes[0]:
                        if len(child):queue.append((parents+nodes,[child],'section'))
                if diagnostic['exception_type'] not in ('RPCError','TimeoutExpiredError'):
                    results.append(result);break
            results.append(result)
    finally:
        if old_timeout is not None:device.timeout=old_timeout
    return {'probes':results,'probe_count':len(results),'truncated':bool(queue),'remaining_probes':len(queue),
            'device_written':False,'interpretation':'Partial trees can introduce missing dependencies; failures identify suspects only. Omission probes retain the rest of the snapshot but can also remove dependencies. Empty control tests inline support.'}
