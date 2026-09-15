import argparse
import json
from pathlib import Path
import sys

from .discovery import Inventory, discover, read_native
from .models import load_config
from .netconf import connect
from .planning import build_plan
from .secrets import EnvironmentSecrets


def main(argv=None):
    parser = argparse.ArgumentParser(description="Agent for SecureAccess (planning CLI; transactional apply through MCP)")
    parser.add_argument("command", choices=["check-config", "inventory", "dry-run", "apply"])
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--offline", action="store_true", help="Validate and plan intent without connecting")
    args = parser.parse_args(argv)
    if args.command == "apply":
        parser.exit(2, "Use MCP prepare_configuration_apply and apply_configuration_plan for reviewed CSV transactions.\n")
    try:
        config = load_config(args.config)
        if args.command == "check-config":
            print("Configuration valid; secrets were not resolved")
            return 0
        if args.offline:
            if args.command != "dry-run":
                parser.error("--offline is supported only for dry-run")
            report = build_plan(config, Inventory([], [], ["Offline: device facts unknown"])).as_dict()
        else:
            with connect(config.router, EnvironmentSecrets()) as session:
                inventory = discover(session)
                report = inventory.as_dict() if args.command == "inventory" else build_plan(
                    config, inventory, read_native(session)).as_dict()
        print(json.dumps(report, indent=2, ensure_ascii=False))
        return 0
    except Exception:
        # Do not dump ValidationError input, RPC payloads, authentication data or tracebacks.
        print("Operation failed. Check YAML fields, environment secret, known_hosts, connectivity and NETCONF access.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
