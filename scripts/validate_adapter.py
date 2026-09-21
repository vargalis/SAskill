"""Run only inline, nonproduction router schema tests through the native store."""
from pathlib import Path
import runpy,json
if __name__=='__main__':
    tools=runpy.run_path(str(Path(__file__).with_name('server.py')))
    result=tools['validate_adapter_fixture']()
    print(json.dumps(result,ensure_ascii=False,indent=2))
    raise SystemExit(0 if result.get('validated') else 2)
