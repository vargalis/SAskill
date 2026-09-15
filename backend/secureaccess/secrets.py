import os
from typing import Protocol

from .models import SecretRef


class SecretProvider(Protocol):
    def resolve(self, ref: SecretRef) -> str: ...


class EnvironmentSecrets:
    def resolve(self, ref: SecretRef) -> str:
        value = os.environ.get(ref.env)
        if not value:
            raise ValueError(f"Required secret environment variable missing: {ref.env}")
        return value
