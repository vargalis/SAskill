from ipaddress import IPv4Address, IPv4Interface, IPv4Network
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class SecretRef(StrictModel):
    env: str = Field(pattern=r"^[A-Za-z_][A-Za-z0-9_]*$")


class Router(StrictModel):
    host: str = Field(min_length=1)
    port: int = Field(default=830, ge=1, le=65535)
    username: str = Field(min_length=1)
    password: SecretRef
    timeout: int = Field(default=30, ge=1, le=120)


class Tunnel(StrictModel):
    name: str = Field(pattern=r"^Tunnel[0-9]+$")
    source_interface: str = Field(min_length=1)
    address: IPv4Interface
    mtu: int = Field(default=1400, ge=576, le=1500)


class SecureAccess(StrictModel):
    headend: IPv4Address
    local_identity: str = Field(min_length=1)
    remote_identity: str = Field(min_length=1)
    psk: SecretRef
    ike_encryption: Literal["aes-cbc-256"] = "aes-cbc-256"
    ike_integrity: Literal["sha256"] = "sha256"
    dh_group: Literal[19, 20] = 19
    ipsec_transform: Literal["esp-gcm-256"] = "esp-gcm-256"


class Routing(StrictModel):
    isp_gateway: IPv4Address
    management_network: IPv4Network
    protected_networks: list[IPv4Network] = Field(min_length=1)


class AgentConfig(StrictModel):
    router: Router
    secure_access: SecureAccess
    tunnel: Tunnel
    routing: Routing

    @model_validator(mode="after")
    def check_routes(self):
        headend = self.secure_access.headend
        gateway = self.routing.isp_gateway
        if headend == gateway:
            raise ValueError("Headend and ISP gateway must differ")
        if headend in self.tunnel.address.network or gateway in self.tunnel.address.network:
            raise ValueError("Underlay addresses cannot be on the tunnel subnet")
        if len(set(self.routing.protected_networks)) != len(self.routing.protected_networks):
            raise ValueError("Duplicate protected routes")
        return self


def load_config(path: Path) -> AgentConfig:
    if path.stat().st_size > 1_000_000:
        raise ValueError("Configuration exceeds size limit")
    return AgentConfig.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")))
