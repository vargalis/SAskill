"""Interactive comparison only: no network, no writes, no secret output."""
import getpass
import hmac
from local_secrets import password

stored = password()
if stored is None:
    raise SystemExit('Stored password missing')
entered = getpass.getpass('Enter the password that worked with manual NETCONF (hidden): ')
same = hmac.compare_digest(stored.encode('utf-8'), entered.encode('utf-8'))
del stored, entered
print('PASSWORD_MATCH' if same else 'PASSWORD_DIFFERENT')
