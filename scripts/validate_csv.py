"""Validate a CSV via NETCONF without edit-config or commit. No secret input/output."""
import argparse,json,runpy
from pathlib import Path
def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('csv',type=Path);args=p.parse_args()
    server=runpy.run_path(str(Path(__file__).with_name('server.py')))
    result=server['validate_configuration_csv'](args.csv.read_text(encoding='utf-8-sig'))
    print(json.dumps(result,ensure_ascii=False,indent=2))
    return 0 if result.get('validated') else 2
if __name__=='__main__':raise SystemExit(main())
