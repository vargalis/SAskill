"""Read and explicitly approved transaction MCP tools. Secrets never appear in tool arguments or results."""
import sys
import os
import logging
logging.getLogger("ncclient").setLevel(logging.CRITICAL)
logging.getLogger("paramiko").setLevel(logging.CRITICAL)
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations
from ncclient import manager
from local_secrets import password as load_password
from secureaccess.discovery import discover, read_native, parse_xml
from secureaccess.provisioning import ProvisioningSpec, render_nonsecret
from secureaccess.netconf_renderer import render_netconf
from secureaccess.routing import read_routing
from secureaccess.wizard import WizardState, wizard_step
from secureaccess.csv_config import configuration_csv_template, import_configuration_csv

HOST = "10.2.3.1"
USER = "secureaccess-agent"
SERVICE = "Agent-for-SecureAccess/10.2.3.1"
mcp = FastMCP("Agent for SecureAccess", log_level="CRITICAL")
SERVER_BUILD = os.environ.get('SECUREACCESS_BUILD_ID','unknown')
READ_ONLY = ToolAnnotations(readOnlyHint=True, destructiveHint=False, openWorldHint=True)


def session():
    password = load_password()
    if not password:
        raise RuntimeError("credential-missing")
    return manager.connect(host=HOST, port=830, username=USER, password=password,
                           hostkey_verify=True, allow_agent=False, look_for_keys=False,
                           timeout=30, device_params={"name": "iosxe"})


@mcp.tool(annotations=READ_ONLY)
def connection_status() -> dict:
    """Check local password and host-key enrollment only; do not connect or return secrets."""
    try:
        import paramiko
        keys = paramiko.HostKeys()
        path = Path.home() / ".ssh" / "known_hosts"
        if path.exists():
            keys.load(str(path))
        return {"host": HOST, "port": 830, "username": USER,
                "credential_present": bool(load_password()),
                "host_key_enrolled": bool(keys.lookup(f"[{HOST}]:830") or keys.lookup(HOST)),
                "mode": "read-and-transactional-apply", "apply_mechanism_implemented": True, "apply_available": None}
    except Exception:
        return {"error": "Local credential/key check failed; check native secret store or explicit environment provider"}


@mcp.tool(annotations=READ_ONLY)
def inventory_capabilities() -> dict:
    """Connect to the enrolled router and read capabilities and available YANG models."""
    try:
        with session() as device:
            inventory = discover(device)
            return {"host": HOST, **inventory.as_dict(),
                    "transaction_capabilities": {f: inventory.supports(f) for f in
                                                 ("candidate", "validate", "confirmed-commit")}}
    except Exception as error:
        return {"error": "NETCONF inventory failed", "exception_type": type(error).__name__}


@mcp.tool(annotations=READ_ONLY)
def secureaccess_wizard(state: WizardState | None = None, answer: dict | None = None, back: bool = False) -> dict:
    """Run one wizard step: update/new/template. Pass returned public state to resume; no credentials or device writes. back revisits the last answer."""
    return wizard_step(state, answer, back)


@mcp.tool(annotations=READ_ONLY)
def generate_secureaccess_configuration(spec: ProvisioningSpec) -> dict:
    """Generate the full IKEv2/IPsec/keyring/VTI/static-route review configuration. No password or PSK fields; no device writes."""
    return render_nonsecret(spec)


@mcp.tool(annotations=READ_ONLY)
def generate_netconf_preview(spec: ProvisioningSpec) -> dict:
    """Offline IKEv2/IPsec/VTI/static-route XML preview for inspected 17.9 schemas. No RPCs; device qualification remains required and apply is unavailable."""
    return render_netconf(spec)


@mcp.tool(annotations=READ_ONLY)
def get_crypto_yang_schema(identifier: str) -> dict:
    """Read an allowlisted YANG model via NETCONF get-schema for adapter qualification, not running configuration."""
    if identifier not in {"Cisco-IOS-XE-crypto", "Cisco-IOS-XE-tunnel", "Cisco-IOS-XE-native", "Cisco-IOS-XE-ip", "Cisco-IOS-XE-interfaces", "Cisco-IOS-XE-acl", "Cisco-IOS-XE-route-map"}:
        return {"error": "Model outside schema qualification allowlist"}
    try:
        with session() as device:
            reply = device.get_schema(identifier=identifier, format="yang")
            tree = parse_xml(reply.xml)
            data = tree.xpath("//*[local-name()='data']/text()")
            if not data:
                return {"error": "No schema data returned"}
            return {"identifier": identifier, "yang_schema": "".join(data),
                    "warning": "Schema retrieval is not adapter qualification"}
    except Exception as error:
        return {"error": "Schema retrieval failed", "exception_type": type(error).__name__}


@mcp.tool(annotations=READ_ONLY)
def routing_summary() -> dict:
    """Read sanitized interfaces, static/default routes and supported operational RIB. No writes or crypto values."""
    try:
        with session() as device:
            return {"host": HOST, **read_routing(device)}
    except Exception as error:
        return {"error": "Routing read failed", "exception_type": type(error).__name__, "apply_available": False}


@mcp.tool(annotations=READ_ONLY)
def configuration_summary() -> dict:
    """Read running native config and return only interfaces and static-route count. No raw XML or crypto secrets."""
    try:
        with session() as device:
            tree = parse_xml(read_native(device))
            interfaces = []
            for node in tree.xpath("//*[local-name()='native']/*[local-name()='interface']/*"):
                names = node.xpath("./*[local-name()='name']/text()")
                if names:
                    interfaces.append({"name": node.tag.rsplit("}", 1)[-1] + names[0],
                                       "shutdown": bool(node.xpath("./*[local-name()='shutdown']"))})
            native_present = bool(tree.xpath("//*[local-name()='native']"))
            return {"host": HOST, "native_config_present": native_present, "interfaces": interfaces,
                    "static_route_entries": len(tree.xpath("//*[local-name()='ip']/*[local-name()='route']//*[local-name()='prefix']")),
                    "secrets_omitted": True,
                    "warning": "Summary only; does not verify reachability, operational state or crypto coverage"}
    except Exception:
        return {"error": "Configuration read failed; no raw device data returned"}


@mcp.tool(annotations=READ_ONLY)
def create_configuration_csv(platform: str = "iosxe", name: str = "", host: str = "") -> dict:
    """Create a public CSV template to fill locally. FTD is future planning only. No device I/O."""
    try:
        return configuration_csv_template(platform, name, host)
    except ValueError:
        return {"error": "Unsupported template platform", "apply_available": False}


@mcp.tool(annotations=READ_ONLY)
def preview_configuration_csv(csv_text: str, occupied_tunnel_ids: list[int] | None = None) -> dict:
    """Validate public CSV and produce configuration previews. Never applies values to a device; no secrets accepted."""
    return import_configuration_csv(csv_text, occupied_tunnel_ids)



# Plans and secret-bearing payloads remain inside this MCP process, never files.
from secureaccess.workflow import PlanStore, prepare, apply, require_capabilities, ApplyBlocked
from secureaccess.adapters import select_transaction_adapter
APPLY_PLANS = PlanStore()
MUTATION = ToolAnnotations(readOnlyHint=False, destructiveHint=True, openWorldHint=True)

@mcp.tool(annotations=READ_ONLY)
def prepare_configuration_apply(csv_text: str) -> dict:
    """Read device state and prepare a private one-use plan with public diff. No writes. Requires a qualified adapter and candidate/confirmed-commit."""
    preliminary=import_configuration_csv(csv_text)
    if not preliminary.get('valid') or preliminary.get('platform')!='iosxe':
        return {'apply_ready':False,'device_written':False,'error':'Incomplete or invalid IOS XE CSV; preview CSV first'}
    if preliminary['target']['host']!=HOST:
        return {'apply_ready':False,'device_written':False,'error':'CSV target differs from enrolled router'}
    try:
        with session() as device:
            routes = read_routing(device)
            parsed = import_configuration_csv(csv_text, routes.get('occupied_tunnel_ids'))
            if not parsed.get('valid') or parsed.get('platform') != 'iosxe':
                return {'apply_ready':False,'error':'Incomplete or invalid IOS XE CSV; use preview_configuration_csv'}
            if parsed['target']['host'] != HOST:
                return {'apply_ready':False,'error':'CSV target differs from enrolled router'}
            spec = ProvisioningSpec.model_validate(parsed['provisioning_spec'])
            adapter = select_transaction_adapter(device,parsed)
            try:
                return prepare(device,adapter,parsed,HOST,APPLY_PLANS)
            finally:
                adapter.release(device)
    except ApplyBlocked as error:
        return {'apply_ready':False,'error':str(error),'device_written':False}
    except Exception:
        return {'apply_ready':False,'error':'Apply preparation failed; no raw device or credential data returned','device_written':False}

@mcp.tool(annotations=MUTATION)
def apply_configuration_plan(plan_id: str, approval_digest: str, exclusive_window: bool,
                             confirm_timeout: int = 180, postcheck_budget: int = 60) -> dict:
    """Apply only after the user approves this exact prepared diff/digest and an exclusive change window. One-use; never auto-retry an uncertain commit. No raw XML/PSK input."""
    if exclusive_window is not True:
        return {'applied':False,'error':'Exclusive configuration window must be confirmed'}
    if not (30 <= postcheck_budget <= 300 and postcheck_budget+60 <= confirm_timeout <= 600):
        return {'applied':False,'error':'Invalid confirmation timeout/postcheck budget'}
    device = None
    consumed = False
    execution_started = False
    try:
        plan = APPLY_PLANS.consume(plan_id,approval_digest)
        consumed = True
        if plan.target != HOST:
            raise ApplyBlocked('Plan target differs from enrolled router')
        device = session()
        require_capabilities(device)
        adapter = select_transaction_adapter(device,plan.spec)
        execution_started = True
        return apply(device,adapter,plan,exclusive_window=exclusive_window,
                     confirm_timeout=confirm_timeout,postcheck_budget=postcheck_budget,reconnect=session)
    except ApplyBlocked as error:
        return {'applied':False,'error':str(error),'plan_consumed':consumed}
    except Exception:
        return {'applied':False,'status':'uncertain' if execution_started else 'failed','plan_consumed':consumed,'error':'Apply failed; inspect state before preparing another plan'}
    finally:
        if device is not None:
            try: device.close_session()
            except Exception: pass



@mcp.tool(annotations=READ_ONLY)
def validate_configuration_csv(csv_text: str) -> dict:
    """Validate the reconciled CSV on the enrolled router with NETCONF edit-config test-only. The RPC applies no configuration and works without candidate. Returns a public diff, never credentials/PSK."""
    device=None;adapter=None
    preliminary=import_configuration_csv(csv_text)
    if not preliminary.get('valid') or preliminary.get('platform')!='iosxe':
        return {'validated':False,'device_written':False,'error':'Incomplete or invalid IOS XE CSV; preview CSV first'}
    if preliminary['target']['host']!=HOST:
        return {'validated':False,'device_written':False,'error':'CSV target differs from enrolled router'}
    try:
        device=session()
        routes=read_routing(device)
        parsed=import_configuration_csv(csv_text,routes.get('occupied_tunnel_ids'))
        if not parsed.get('valid') or parsed.get('platform')!='iosxe':
            return {'validated':False,'device_written':False,'error':'Incomplete or invalid IOS XE CSV; preview CSV first'}
        if parsed['target']['host']!=HOST:
            return {'validated':False,'device_written':False,'error':'CSV target differs from enrolled router'}
        adapter=select_transaction_adapter(device,parsed)
        return {'validated':True,**adapter.validate_intent(device,parsed)}
    except ApplyBlocked as error:
        return {'validated':False,'device_written':False,'error':str(error)}
    except Exception:
        return {'validated':False,'device_written':False,'error':'Device validation rejected or unavailable; no raw RPC data returned'}
    finally:
        if adapter is not None and device is not None: adapter.release(device)
        if device is not None:
            try: device.close_session()
            except Exception: pass


@mcp.tool(annotations=READ_ONLY)
def validate_adapter_fixture(debug: bool = False) -> dict:
    """Run GCM/CBC nonproduction schema fixtures with NETCONF edit-config test-only. Unused tunnel and documentation addresses; cannot create an apply plan. No configuration changes."""
    from secureaccess.native_adapter import IOSXENativeAdapter
    from secureaccess.qualification_fixture import schema_fixture
    from secureaccess.diagnostics import details,save_debug
    results=[]
    events=[]
    phase='connect'
    try:
        with session() as device:
            phase='routing'
            routes=read_routing(device)
            adapter=IOSXENativeAdapter()
            for cbc in (False,True):
                fixture=schema_fixture(routes,HOST,cbc=cbc)
                phase='test_only_validation'
                events.append({"crypto_case":"CBC" if cbc else "GCM"})
                result=adapter.validate_intent(device,fixture,events=events,probe_baseline=debug)
                results.append({'crypto_case':'CBC/SHA256/PFS20' if cbc else 'GCM',
                                'schema_validated':result['schema_validated'],
                                'transaction_ready':result['transaction_ready']})
            return {'validated':True,'fixture_only':True,'device_written':False,'server_build':SERVER_BUILD,'results':results,
                    'note':'Schema acceptance only; no live SA/traffic/rollback test performed'}
    except Exception as error:
        result={'validated':False,'fixture_only':True,'device_written':False,'server_build':SERVER_BUILD,'results':results,'phase':phase,
                'error':'Fixture validation failed; enable debug for sanitized diagnostics'}
        if debug:
            diagnostic=details(error,phase,events)
            result['debug']=diagnostic
            result['debug_log']=save_debug(diagnostic)
        return result

if __name__ == "__main__":
    mcp.run(transport="stdio")
