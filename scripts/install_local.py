"""Cross-platform personal plugin install/update; run as the real user."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import venv


def python_path(root, platform=None):
    platform = platform or sys.platform
    return root / ("Scripts/python.exe" if platform == "win32" else "bin/python")


def run(*args):
    subprocess.run([str(a) for a in args], check=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--codex", type=Path, help="CLI executable if absent from PATH")
    args = parser.parse_args()
    source = Path(__file__).resolve().parents[1]
    home = Path.home()
    codex_home = Path(os.environ.get("CODEX_HOME", home / ".codex"))
    helpers = codex_home / "skills/.system/plugin-creator/scripts"
    marketplace = home / ".agents/plugins/marketplace.json"
    target = home / "plugins/agent-for-secureaccess"
    codex = str(args.codex) if args.codex else shutil.which("codex")
    if not codex and sys.platform == "win32":
        candidates = list((Path(os.environ.get("LOCALAPPDATA", home / "AppData/Local")) / "OpenAI/Codex/bin").glob("*/codex.exe"))
        if candidates:
            codex = str(max(candidates, key=lambda p: p.stat().st_mtime))
    if not codex:
        parser.error("Codex CLI not found; provide --codex /path/to/codex")
    if not (helpers / "create_basic_plugin.py").is_file():
        parser.error("Codex plugin-creator helpers missing from CODEX_HOME")
    exists = (target / ".codex-plugin/plugin.json").is_file()
    if exists:
        manifest = json.loads((target / ".codex-plugin/plugin.json").read_text(encoding="utf-8-sig"))
        if manifest.get("name") != "agent-for-secureaccess":
            parser.error("Plugin identifier mismatch")
        run(sys.executable, helpers / "read_marketplace_name.py", "--marketplace-path", marketplace)
        entries = json.loads(marketplace.read_text(encoding="utf-8-sig"))["plugins"]
        matches = [e for e in entries if e.get("name") == "agent-for-secureaccess"]
        if len(matches) != 1 or matches[0].get("source") != {"source": "local", "path": "./plugins/agent-for-secureaccess"}:
            parser.error("Marketplace source mismatch")
    else:
        if target.exists():
            parser.error("Incomplete target already exists; inspect it before retrying")
        run(sys.executable, helpers / "create_basic_plugin.py", "agent-for-secureaccess", "--path", target.parent,
            "--with-marketplace", "--marketplace-path", marketplace, "--with-skills", "--with-mcp")
        shutil.copy2(source / ".codex-plugin/plugin.json", target / ".codex-plugin/plugin.json")
    if source != target:
        (target / ".codex-plugin").mkdir(parents=True, exist_ok=True)
        shutil.copy2(source / ".codex-plugin/plugin.json", target / ".codex-plugin/plugin.json")
        for folder in ("backend", "src", "scripts", "skills", "docs", "examples"):
            shutil.copytree(source / folder, target / folder, dirs_exist_ok=True,
                            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        for name in ("requirements.txt", "pyproject.toml", "README.md"):
            shutil.copy2(source / name, target / name)
    runtime = home / "plugins/.runtimes/agent-for-secureaccess"
    if not python_path(runtime).is_file():
        venv.create(runtime, with_pip=True)
    interpreter = python_path(runtime)
    run(interpreter, "-m", "pip", "install", "-r", target / "requirements.txt")
    run(interpreter, "-m", "pip", "install", "--no-deps", "-e", target)
    run(interpreter, helpers / "update_plugin_cachebuster.py", target)
    version = json.loads((target / ".codex-plugin/plugin.json").read_text(encoding="utf-8-sig"))["version"]
    config = {"mcpServers": {"secureaccess": {"command": str(interpreter), "args": ["-m", "secureaccess_mcp"],
               "env": {"SECUREACCESS_BUILD_ID": version}}}}
    (target / ".mcp.json").write_text(json.dumps(config, indent=2), encoding="utf-8")
    run(interpreter, helpers / "validate_plugin.py", target)
    name = json.loads(marketplace.read_text(encoding="utf-8-sig"))["name"]
    run(codex, "plugin", "add", f"agent-for-secureaccess@{name}")
    print("Installed. Existing OS credentials and known_hosts preserved. Open a new Codex task.")
    print(f"Native credential setup: {interpreter} {target / 'scripts/setup_local.py'} password")


if __name__ == "__main__":
    main()
