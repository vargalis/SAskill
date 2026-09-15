"""Read-only local diagnosis; never prints exception payloads or credentials."""
import importlib.util
import json
import traceback
from pathlib import Path

root = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("secureaccess_server", root / "server.py")
server = importlib.util.module_from_spec(spec)
spec.loader.exec_module(server)

stage = "local-readiness"
result = {"host": server.HOST, "port": 830, "mode": "read-only"}
try:
    status = server.connection_status()
    result["connection_status"] = status
    if not status.get("credential_present") or not status.get("host_key_enrolled"):
        result["error"] = "Local readiness not established"
    else:
        stage = "ssh-authentication-and-netconf-hello"
        device = server.session()
        try:
            result["netconf_connected"] = True
            stage = "capability-inventory"
            inventory = server.discover(device)
            result["inventory"] = inventory.as_dict()
            result["transaction_capabilities"] = {f: inventory.supports(f) for f in
                ("candidate", "validate", "confirmed-commit")}
        finally:
            device.close_session()
except Exception as error:
    # Class name only, never str(error), args, traceback, RPC XML or library logs.
    result["failed_stage"] = stage
    result["exception_type"] = type(error).__name__
    result["exception_module"] = type(error).__module__
    result["failure_locations"] = [
        {"file": Path(frame.filename).name, "function": frame.name, "line": frame.lineno}
        for frame in traceback.extract_tb(error.__traceback__)
    ]
print(json.dumps(result, indent=2))
