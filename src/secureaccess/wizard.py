"""Stateless conversational wizard: caller keeps public state, no network or device writes."""
from ipaddress import IPv4Address, IPv4Network
from typing import Literal
from pydantic import Field, ValidationError
from .models import StrictModel
from .provisioning import CryptoParameters, ProvisioningSpec, TunnelSpec, PBRParameters, render_nonsecret


class Target(StrictModel):
    name: str = Field(pattern=r"^[A-Za-z0-9_.-]{1,48}$")
    host: IPv4Address | None = None


class Baseline(StrictModel):
    available: bool
    change_scope: str = Field(min_length=1, max_length=1000)
    # Never carry raw running configuration or secret values in wizard state.


class Bootstrap(StrictModel):
    management_ready: bool
    netconf_ready: bool


class Network(StrictModel):
    prefix: str = Field(default="SSE", pattern=r"^[A-Za-z0-9][A-Za-z0-9_.+-]{0,47}$")
    routing_mode: Literal["static", "pbr"] = "static"
    isp_gateway: IPv4Address
    router_wan_ip: IPv4Address
    management_prefixes: list[IPv4Network] = Field(min_length=1)
    protected_prefixes: list[IPv4Network] = Field(min_length=1)


class RoutingReview(StrictModel):
    reviewed: bool
    occupied_tunnel_ids: list[int] = Field(default_factory=list)
    preserve_tunnel_ids: list[int] = Field(default_factory=list)
    operational_table_verified: bool = False


class TunnelSelection(StrictModel):
    interface_name: str = Field(pattern=r"^Tunnel[1-9][0-9]{0,9}$")
    action: Literal["create", "reuse"]


class ExistingTunnelSummary(StrictModel):
    interface_name: str = Field(pattern=r"^Tunnel[1-9][0-9]{0,9}$")
    source_interface: str | None = Field(default=None, max_length=64)
    destination: IPv4Address | None = None
    address: str | None = Field(default=None, max_length=64)
    shutdown: bool


class TunnelReuseReview(StrictModel):
    confirmed: bool
    change_scope: str = Field(min_length=1, max_length=1000)
    current_interfaces: list[ExistingTunnelSummary] = Field(min_length=1, max_length=8)


class WizardState(StrictModel):
    mode: Literal["update", "new", "template"] | None = None
    target: Target | None = None
    baseline: Baseline | None = None
    bootstrap: Bootstrap | None = None
    routing: RoutingReview | None = None
    tunnel_numbers: list[int] | None = Field(default=None, min_length=1, max_length=8)
    tunnel_selection: list[TunnelSelection] | None = Field(default=None, min_length=1, max_length=8)
    tunnel_reuse_review: TunnelReuseReview | None = None
    network: Network | None = None
    pbr: PBRParameters | None = None
    tunnels: list[TunnelSpec] | None = Field(default=None, min_length=1, max_length=8)
    crypto: CryptoParameters | None = None
    review: Literal["confirmed"] | None = None


STEPS = {
    "mode": {"question": "Что будем делать?", "choices": [
        {"value": "update", "label": "Изменить существующую конфигурацию"},
        {"value": "new", "label": "Настроить новый маршрутизатор"},
        {"value": "template", "label": "Создать шаблон"}]},
    "target": {"question": "Как назовём маршрутизатор или шаблон? Для маршрутизатора укажи также IP управления.", "fields": ["name", "host"]},
    "baseline": {"question": "Что именно меняем и есть ли безопасная сводка текущей конфигурации?", "fields": ["available", "change_scope"]},
    "bootstrap": {"question": "Доступ к управлению и NETCONF уже подготовлен?", "fields": ["management_ready", "netconf_ready"]},
    "routing": {"question": "Просмотрим таблицу маршрутизации, default route, адреса/маски интерфейсов и занятые туннели. Подтверди просмотр; укажи туннели, которые сохраняем.", "read_tool": "routing_summary", "fields": ["reviewed", "occupied_tunnel_ids", "preserve_tunnel_ids", "operational_table_verified"]},
    "tunnel_numbers": {"question": "Выбери интерфейс TunnelN и действие create (создать новый) или reuse (использовать существующий). Для reuse текущие параметры и план изменений подтверждаются отдельно; это не применение.", "fields": ["interface_name", "action"], "answer_format": {"tunnel_numbers": [{"interface_name": "TunnelN", "action": "create OR reuse"}]}},
    "network": {"question": "Выбери routing_mode: static (маршруты назначения) или pbr (выбор источников). Укажи шлюз ISP, IPv4-адрес WAN-интерфейса, сети управления и сети назначения Secure Access. В static сети управления идут через ISP; в pbr их текущие маршруты сохраняются.", "fields": ["routing_mode", "isp_gateway", "router_wan_ip", "management_prefixes", "protected_prefixes", "prefix"]},
    "pbr": {"question": "Укажи сети источников, входные интерфейсы и исключения по назначению (управление и локальные сети). Туннели используются в выбранном порядке: primary, затем secondary; если оба недоступны, normal-routing возвращает трафик в обычную RIB/ISP.", "fields": ["source_prefixes", "ingress_interfaces", "bypass_destination_prefixes", "failure_behavior"], "supported_failure_behavior": ["normal-routing"], "warning": "Поддерживается один VTI или упорядоченная пара primary/secondary; существующий default route сохраняется"},
    "tunnels": {"question": "Укажи параметры туннелей: headend, local IKE identity, source interface, адрес VTI или unnumbered interface. PSK не присылай.", "fields": ["tunnel_id", "headend", "local_identity", "source_interface", "address OR unnumbered_interface", "distance"]},
    "tunnel_reuse_review": {"question": "Проверь текущие параметры выбранных существующих TunnelN и предлагаемые параметры. Укажи границы изменения и подтверди использование этих интерфейсов. Подтверждение снимает ранее выбранное сохранение только этих туннелей; устройство не изменяется.", "fields": ["confirmed", "change_scope", "current_interfaces"], "warning": "Нужна безопасная сводка текущих параметров; секреты и raw XML не принимаются"},
    "crypto": {"question": "Подтверди crypto-параметры из настройки Secure Access: IKE encryption/PRF/DH, ESP, lifetime/DPD и PFS при необходимости.", "fields": ["ike_encryption", "prf", "dh_groups", "esp", "ike_lifetime", "ipsec_lifetime", "dpd_interval", "dpd_retries", "pfs"]},
    "review": {"question": "Проверь собранные параметры. Подтвердить создание плана/шаблона? Это не разрешение на применение.", "choices": [{"value": "confirmed", "label": "Создать план или шаблон"}]},
}


def sequence(state):
    return ["mode", "target"] + (["baseline"] if state.mode == "update" else
        ["bootstrap"] if state.mode == "new" else []) + (["routing"] if state.mode != "template" else []) + ["network"] + (["pbr"] if state.network and state.network.routing_mode == "pbr" else []) + ["tunnel_numbers", "tunnels"] + (["tunnel_reuse_review"] if any(t.action == "reuse" for t in state.tunnel_selection or []) else []) + ["crypto", "review"]


def next_step(state):
    if state.mode == "new" and state.target and state.bootstrap:
        if not state.bootstrap.management_ready or not state.bootstrap.netconf_ready:
            return "bootstrap"
    if state.tunnel_reuse_review and not state.tunnel_reuse_review.confirmed:
        return "tunnel_reuse_review"
    if state.routing and not state.routing.reviewed:
        return "routing"
    return next((s for s in sequence(state) if getattr(state, s) is None), None)


def public_summary(state):
    return state.model_dump(mode="json", exclude_none=True)


def wizard_step(state: WizardState | None = None, answer: dict | None = None, back: bool = False) -> dict:
    current = (state or WizardState()).model_copy(deep=True)
    if back and answer is not None:
        return {"error": "Use back or answer, not both", "state": public_summary(current)}
    if back:
        steps = sequence(current)
        done = [s for s in steps if getattr(current, s) is not None]
        if done:
            setattr(current, done[-1], None)
    step = next_step(current)
    if answer is not None:
        if step is None:
            return {"error": "Wizard complete; go back to revise", "state": public_summary(current)}
        if set(answer) != {step}:
            return {"error": f"Answer must contain only '{step}'", "state": public_summary(current), "step": step}
        try:
            payload = {**current.model_dump(mode="json"), **answer}
            if step == "tunnel_numbers":
                values = answer[step]
                if isinstance(values, list) and values and isinstance(values[0], dict):
                    selections = [TunnelSelection.model_validate(value) for value in values]
                    payload["tunnel_selection"] = [t.model_dump(mode="json") for t in selections]
                    payload["tunnel_numbers"] = [int(t.interface_name.removeprefix("Tunnel")) for t in selections]
                else:
                    payload["tunnel_selection"] = None  # Legacy numeric answers mean create.
                payload["tunnel_reuse_review"] = None
            candidate = WizardState.model_validate(payload)
            if candidate.pbr and (not candidate.network or candidate.network.routing_mode != "pbr"):
                raise ValueError("PBR requires PBR network mode")
            if step == "target" and candidate.mode != "template" and candidate.target.host is None:
                raise ValueError("Router management IP required")
            if candidate.tunnel_numbers:
                numbers = candidate.tunnel_numbers
                if len(set(numbers)) != len(numbers) or any(n < 1 or n > 2147483647 for n in numbers):
                    raise ValueError("Invalid tunnel numbers")
                selections = candidate.tunnel_selection or [TunnelSelection(interface_name=f"Tunnel{n}", action="create") for n in numbers]
                if [int(t.interface_name.removeprefix("Tunnel")) for t in selections] != numbers:
                    raise ValueError("Selection must match tunnel numbers")
                for selection, number in zip(selections, numbers):
                    if selection.action == "create" and candidate.routing and number in candidate.routing.occupied_tunnel_ids + candidate.routing.preserve_tunnel_ids:
                        raise ValueError("Create requires an unoccupied interface")
                    if selection.action == "reuse" and candidate.mode != "template" and (not candidate.routing or number not in candidate.routing.occupied_tunnel_ids):
                        raise ValueError("Reuse requires an observed existing interface")
            if step == "tunnel_reuse_review":
                reused = {t.interface_name for t in candidate.tunnel_selection or [] if t.action == "reuse"}
                observed = [t.interface_name for t in candidate.tunnel_reuse_review.current_interfaces]
                if set(observed) != reused or len(observed) != len(reused):
                    raise ValueError("Current summary must cover exactly the reused interfaces")
                if candidate.tunnel_reuse_review.confirmed and candidate.routing:
                    candidate.routing.preserve_tunnel_ids = [n for n in candidate.routing.preserve_tunnel_ids if f"Tunnel{n}" not in reused]
            if step == "tunnels" and [t.tunnel_id for t in candidate.tunnels] != candidate.tunnel_numbers:
                raise ValueError("Tunnel IDs must match separate selection")
            if step == "crypto":
                make_spec(candidate)  # Validate topology before review, not after confirmation.
            current = candidate
        except (ValidationError, ValueError):
            return {"error": "Invalid public parameters; check required fields, addressing and topology. Secrets are not accepted.",
                    "state": public_summary(current), "step": step, "prompt": STEPS[step]}
    step = next_step(current)
    blockers = []
    if current.routing and not current.routing.operational_table_verified:
        blockers.append("Operational routing table/default route not verified; configured static routes alone are insufficient")
    if current.mode == "update" and current.baseline and not current.baseline.available:
        blockers.append("Current baseline missing; generate desired-state preview only, not a device diff")
    if current.mode == "new" and current.bootstrap:
        if not current.bootstrap.management_ready or not current.bootstrap.netconf_ready:
            blockers.append("Initial management/NETCONF bootstrap requires local preparation before live discovery")
    if current.mode != "template" and current.target and str(current.target.host) != "10.2.3.1":
        blockers.append("Current plugin connection is enrolled only for 10.2.3.1; this target is planning-only")
    if current.pbr:
        blockers.append("PBR XML preview implemented; exact device ACL/route-map schema validation, reconciliation and operational qualification remain required")
    response = {"state": public_summary(current), "step": step or "complete", "blockers": blockers,
                "progress": {"completed": sum(getattr(current, s) is not None for s in sequence(current)), "total": len(sequence(current))},
                "apply_available": False, "state_storage": "Public state returned to caller; save locally to resume. No server-side persistence."}
    if step:
        response["prompt"] = STEPS[step]
        if step == "bootstrap" and current.bootstrap:
            response["prompt"] = {
                "question": "Сначала подготовим доступ. Есть ли рабочая консольная или администраторская SSH-сессия маршрутизатора?",
                "missing": [name for name, ready in current.bootstrap.model_dump().items() if not ready],
                "next_action": "Guide local bootstrap before collecting ISP/routes. Re-submit bootstrap readiness after verification.",
                "fields": ["management_ready", "netconf_ready"],
                "warning": "Stored credentials and host keys do not prove management or NETCONF readiness",
            }
        if step == "tunnel_numbers":
            response["occupied_tunnel_ids"] = current.routing.occupied_tunnel_ids if current.routing else []
            response["preserve_tunnel_ids"] = current.routing.preserve_tunnel_ids if current.routing else []
            response["suggested_number"] = next(n for n in range(100, 10000) if n not in response["occupied_tunnel_ids"] + response["preserve_tunnel_ids"])
            response["suggestion_verified"] = current.routing is not None
        if step == "tunnel_reuse_review":
            response["selected_existing_interfaces"] = [t.interface_name for t in current.tunnel_selection or [] if t.action == "reuse"]
            response["proposed_tunnels"] = [t.model_dump(mode="json") for t in current.tunnels or [] if f"Tunnel{t.tunnel_id}" in response["selected_existing_interfaces"]]
            response["baseline_verified"] = False
        if step == "review":
            response["summary"] = public_summary(current)
    else:
        try:
            spec = make_spec(current)
            response["provisioning_spec"] = spec.model_dump(mode="json")
            response["tunnel_interface_intent"] = [t.model_dump(mode="json") for t in current.tunnel_selection or []]
            if current.tunnel_reuse_review:
                response["blockers"].append("Existing tunnel summary is caller-held; full device reconciliation, secret preservation and choice conflicts remain unverified")
            response["result"] = render_nonsecret(spec)
            if spec.pbr:
                from .netconf_renderer import render_netconf
                response["netconf_preview"] = render_netconf(spec)
            response["artifact_kind"] = "reusable-public-config-template" if current.mode == "template" else "desired-configuration-preview"
        except (ValidationError, ValueError, AttributeError):
            response["error"] = "Incomplete or invalid state; restart or revise wizard"
    return response


def make_spec(state):
    return ProvisioningSpec(**state.network.model_dump(), tunnels=state.tunnels, crypto=state.crypto, pbr=state.pbr)
