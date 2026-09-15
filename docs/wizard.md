# Wizard: пошаговая работа в чате

## Подготовка доступа перед сетевым планом

Если управление или NETCONF не готовы, wizard остается на bootstrap. Не переходи к вопросам о маршрутах. Сначала выясни наличие локальной консоли или рабочей администраторской сессии. Без доступа предложи организовать консольное подключение либо явно выбрать offline шаблон.

При наличии сессии собери модель/IOS XE release, текущее состояние management interface и AAA без секретов, show netconf-yang status. Затем подготовь минимальный конкретный bootstrap-план: management addressing/reachability, SSH и доверенный ключ, учетная запись с нужными правами, NETCONF на 830 и подходящие AAA authentication/authorization lists. Не отправляй универсальный блок AAA поверх существующего. Пользователь выполняет bootstrap локально; секретные строки вводит самостоятельно. Существующую admin-сессию оставляет открытой до проверки нового входа. Candidate — отдельное изменение с учетом перезапуска сессий, не часть автоматической подготовки.

Подтверждай готовность после проверки доступа и NETCONF hello/capabilities. Локальное наличие credentials/known_hosts не является проверкой. Только после обоих состояний ready переходи к сети и маршрутам. Offline планирование возможно через явный выбор режима шаблона.

Начало: «Запусти wizard Agent for SecureAccess». Инструмент `secureaccess_wizard` возвращает текущий вопрос, варианты ответа, прогресс, публичное состояние и ограничения. Инструмент сам не спрашивает человека: Codex показывает вопрос и преобразует ответ в структуру следующего вызова.

Первый выбор:

- **Изменить существующий конфиг:** цель → безопасное исходное состояние и границы изменения → сети → туннели → crypto → проверка → план.
- **Новый маршрутизатор:** цель → готовность управления/NETCONF → сети → туннели → crypto → проверка → план.
- **Шаблон:** название → сети → туннели → crypto → проверка → публичный YAML-шаблон.

В каждой ветке задавай один логический блок вопросов, не весь список сразу. Туннели можно собирать по одному в чате и передать списком после готовности блока. Параметры crypto берутся из настройки Secure Access; defaults показываются как предложения, не как установленные факты. Не требуй PSK. Если пользователь хочет абстрактный шаблон без конкретных адресов, сохрани незавершенное публичное состояние и список незаполненных параметров: строгий ProvisioningSpec требует действительных значений и не принимает выдуманные адреса.

Сохранение: state возвращается клиенту, а не хранится на сервере. При паузе сохрани JSON state в рабочей папке задачи; при возобновлении прочитай его и передай в инструмент. Данные возобновленной задачи пользователь должен проверить перед использованием. Для возвращения назад передай back=true. Для изменения более раннего шага очисти его и все следующие поля, затем пройди их заново. При смене режима начни с пустого state.

Примеры вызовов:

```json
{"answer":{"mode":"template"}}
```

```json
{"state":{"mode":"template"},"answer":{"target":{"name":"branch-template"}}}
```

На последнем шаге показывай собранные параметры и спрашивай о создании плана/шаблона. Ответ передается как review="confirmed". Это не авторизация применения. Итоговый provisioning_spec сохраняй как YAML, result.configuration_cli_preview — как текстовую конфигурацию для review. Отдельно перечисли manual_secret_steps. Не объявляй туннель работоспособным без PSK и operational проверки.

На текущем этапе NETCONF-цель фиксирована на 10.2.3.1. Другие адреса допускаются для планирования, но не подключаются автоматически. Готовность management/NETCONF в wizard — заявление пользователя, а не результат live prechecks. Missing baseline допускает preview, но не device diff. Шаблоны не требуют активного подключения. Секреты для входа хранятся вне state.

Routing review: live modes now include a routing step before network parameters.
Use routing_summary for sanitized interfaces/masks, static routes, default routes
and the ietf-routing 2015-05-25 operational RIB when supported. Failures/empty data
remain unknown. EIGRP redistribution and agent return path need separate evidence.
The tunnel_numbers step explicitly selects new interface IDs, rejecting occupied
and preserved IDs for create; reuse requires a separate review. Preserve only interfaces explicitly selected by the user.
The returned state is public caller-held evidence, not fresh server verification.
Template mode never connects. No write tools were added.


## PBR planning

Network routing_mode defaults to static for existing saved states. Select pbr for
source-based traffic selection; protected_prefixes always means DESTINATIONS,
including 0.0.0.0/0. The separate pbr step collects source_prefixes,
ingress_interfaces, bypass_destination_prefixes and explicit failure_behavior.
Never infer ingress from reverse static routes. Management destinations must be
covered by bypasses. Include local destinations so local traffic follows the RIB.
Headend /32 destinations bypass PBR automatically. Existing management/static
routes and the ISP default remain untouched in PBR mode.

Preview uses extended ACL source/destination matches and ip policy route-map on
ingress, with set interface for one VTI or an ordered primary/secondary pair.
ACL deny means ordinary routing, not dropping. Do not generate ip local policy.
normal-routing fallback requires explicit confirmation and permits ISP forwarding;
fail-closed/tracking are not implemented. Verify platform support, existing policy
ownership, NAT, exclusions and operational behavior before any future apply.
PBR CLI and NETCONF XML previews are implemented. XML covers named extended ACL,
route-map source/destination matching and ingress interface policy. payload_complete
means feature coverage only; schema_validated/device_qualified/apply_ready remain
false. Exact device ACL/route-map augments must be retrieved and reconciled with
reference bundle xe/17121 before qualification. No writes or RPCs are available.

References: https://www.cisco.com/c/en/us/td/docs/routers/ios/config/17-x/ip-routing/b-ip-routing/m_iri-pbr.html
and https://www.cisco.com/c/en/us/td/docs/routers/ios/config/17-x/ip-routing/b-ip-routing/m_iri-ip-prot-indep-0.html


## Select a new or existing tunnel interface

At tunnel_numbers accept {"tunnel_numbers":[{"interface_name":"Tunnel1","action":"reuse"}]}
or a create selection with an available TunnelN. Legacy numeric lists still mean
create. IOS XE names are Tunnel followed by a positive interface number, not arbitrary
labels. Never infer a specific tunnel selection. Tunnel1 is available for explicit
reuse; no hard-coded preservation applies. Other caller-selected preservation stays.
After tunnel parameters, reuse requires tunnel_reuse_review: a sanitized current
interface summary, exact change_scope and confirmed=true. Show both current and
proposed parameters before asking confirmation. Existing crypto/secret coverage
is not verified by this summary. Confirmed reuse withdraws preservation only for
selected interfaces. This approves planning, never device writes. Reusing an
interface requires reconciliation of existing choices, addressing, shutdown and
secrets before any future application; merge preview alone is insufficient.
