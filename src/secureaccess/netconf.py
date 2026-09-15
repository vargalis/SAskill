from contextlib import contextmanager
from ncclient import manager

from .models import Router
from .secrets import SecretProvider


@contextmanager
def connect(router: Router, secrets: SecretProvider, connector=manager.connect):
    """Verify SSH host keys against known_hosts; never auto-enroll unknown keys."""
    session = connector(
        host=router.host, port=router.port, username=router.username,
        password=secrets.resolve(router.password), hostkey_verify=True,
        allow_agent=False, look_for_keys=False, timeout=router.timeout,
        device_params={"name": "iosxe"},
    )
    try:
        yield session
    finally:
        session.close_session()
