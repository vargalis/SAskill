import runpy
import sys
from pathlib import Path
scripts = Path(__file__).resolve().parents[2] / "scripts"
sys.path.insert(0, str(scripts))
runpy.run_path(str(scripts / "server.py"), run_name="__main__")
