# Skill SecureAccess: полное руководство оператора

[English version](user-guide.en.md) · [README](../README.md) · [Справочник транзакций](netconf-apply.md)

Руководство описывает код этого репозитория. Skill называется `secureaccess-netconf`, плагин — **Agent for SecureAccess**. Skill управляет последовательностью действий в диалоге, а локальный MCP-сервер подключается к маршрутизатору. Для полного процесса нужны оба компонента. Такая структура описана в [официальной документации OpenAI о плагинах](https://developers.openai.com/plugins/concepts/plugins).

Последовательность работы: подготовить доступ → установить плагин → зарегистрировать SSH-ключ → собрать состояние устройства → выбрать режим CSV → заполнить и проверить файл → выполнить проверку на устройстве → подготовить план → согласовать и применить → проверить результат и отдельно сохранить конфигурацию.

## 1. До начала: область применения и исходные данные

Реализованы IPv4 Cisco IOS XE IKEv2/IPsec, выбранные VTI-интерфейсы, статические маршруты и PBR. Совместимость определяется точным совпадением поставляемых YANG-схем, а не только версией IOS XE или семейством маршрутизатора. FTD/FMC/FDM поддерживается **только как шаблон планирования**. Старый YAML CLI и необязательный wizard не применяют конфигурацию.

Согласуйте с владельцем сети следующие данные:

| Данные | Необходимое решение или подтверждение |
| --- | --- |
| Устройство | Инвентарное имя и IPv4-адрес управления. В MCP-сервере NETCONF использует фиксированный TCP-порт 830. |
| Доступ | NETCONF username/password, права на чтение схем, конфигурации и operational state, а при применении — на RPC транзакции. |
| Подлинность устройства | SHA256 fingerprint SSH host key, полученный независимо от доверенного администратора или через консоль. |
| Назначение Secure Access | Выданные headend IPv4, локальный Tunnel ID/email, PSK и согласованные crypto-параметры каждого туннеля. Skill не создаёт эти объекты в портале Secure Access. |
| Underlay | ISP gateway, фактический source interface и его IPv4, текущие маршруты, NAT/firewall и доступность headend. |
| Управление | Префиксы, покрывающие обратный путь к фактическому NETCONF-клиенту, и подтверждённые маршруты в глобальной таблице. |
| Выбор трафика | Destination prefixes; для PBR — source prefixes, реальные входные LAN-интерфейсы, явные bypass destinations и согласие на fallback в обычную маршрутизацию. |
| Интерфейсы | Свободный `TunnelN` для create либо явно проверенный существующий интерфейс для reuse; адрес VTI или интерфейс для unnumbered. |
| Организация изменения | Резервная копия по принятой процедуре, консоль/доступ для восстановления, эксклюзивное окно и тестовый узел для подходящего трафика. |

Адреса, пароли и PSK из примеров не являются параметрами вашей сети. Заполненный CSV храните вне репозитория, в закрытом каталоге.

### Текущие ограничения, влияющие на подготовку

- CSV importer требует `connection.username`, `connection.password`, `psk_mode`, `psk_format` и соответствующие непустые значения PSK. Работа только через vault или только с ключами устройства **не является полноценным CSV-сценарием этой сборки**, хотя адаптер внутренне поддерживает эти источники.
- Секреты из CSV передаются во входных аргументах инструментов. Маскирование результатов не делает исходный файл или входные данные диалога/инструмента бессекретными. Используйте тестовый процесс только там, где это разрешено. Если политика запрещает такую передачу, остановитесь до отправки файла: для vault-only требуется изменение importer.
- Basic подходит для PBR. Для статической маршрутизации выбирайте **Advanced** и оставляйте поля только для PBR пустыми. Basic сейчас добавляет `pbr.failure_behavior=normal-routing`, из-за чего static CSV не проходит проверку.
- Исключения PBR для management и headend автоматически не создаются. Нужные назначения указывайте явно в строках `bypass_prefix`.
- Apply prechecks требуют, чтобы локальный IPv4 socket-адрес клиента входил в management prefix, для каждого management prefix существовал точный operational route с next-hop address, а пути возврата и к ISP не проходили через Tunnel. Одного default route недостаточно; connected management route без next-hop address, NAT со стороны клиента или другая VRF также могут не пройти проверки. Не создавайте искусственные маршруты ради прохождения проверки: сначала решите ограничение топологии или поддержки.
- PBR поддерживает один туннель либо упорядоченную пару и fallback `normal-routing`. Tracking и fail-closed отсутствуют. Static поддерживает до восьми туннелей, но protected prefixes не должны пересекаться с management; поэтому protected static default route отклоняется.
- NAT, AAA, firewall policy, BGP, лицензирование, начальная настройка маршрутизатора и сохранение running в startup не входят в генерируемую конфигурацию.

## 2. Подготовьте маршрутизатор и рабочую станцию

Уполномоченный администратор должен настроить адрес управления, рабочий SSH, подходящую учётную запись/AAA для NETCONF, NETCONF на TCP 830 и доступ к нужным YANG/operational models. Используйте процедуру для конкретного устройства: skill не включает NETCONF и не заменяет AAA. Сохраняйте существующую административную сессию или консоль до проверки нового доступа.

Обеспечьте сетевую доступность с машины, где работает локальный MCP-сервер. По принятой сетевой процедуре проверьте underlay туннеля, firewall/NAT и назначение Secure Access. Перед изменением получите актуальную резервную копию.

На рабочей станции нужны Python **3.11+**, Codex CLI с поддержкой плагинов и комплект helper-скриптов `plugin-creator`. Installer ищет helpers в `$CODEX_HOME/skills/.system/plugin-creator/scripts` либо в `~/.codex/skills/.system/plugin-creator/scripts`, если `CODEX_HOME` не задан. Нужен доступ для загрузки Python-пакетов. Выполняйте установку от того же обычного пользователя ОС, который запускает Codex, без root/Administrator.

Vault для логина использует macOS Keychain, Windows Credential Manager или Linux Secret Service. Для vault на Linux нужен доступный и разблокированный пользовательский secret service; сохранения секретов в файл как запасного варианта нет.

## 3. Установите плагин

Откройте терминал в корне репозитория. Проверьте зависимости и запустите установку:

**macOS/Linux**

```sh
python3 --version
codex --version
python3 scripts/install_local.py
```

**Windows PowerShell**

```powershell
py -3 --version
codex --version
py -3 scripts/install_local.py
```

Если Codex отсутствует в PATH, добавьте `--codex "/absolute/path/to/codex"` либо путь Windows к `codex.exe`. `scripts/windows-install.ps1` — необязательная Windows-обёртка того же installer.

Installer копирует проект в `~/plugins/agent-for-secureaccess`, создаёт virtual environment в `~/plugins/.runtimes/agent-for-secureaccess`, устанавливает зависимости и Python-пакет в editable-режиме, обновляет версию плагина, записывает локальную конфигурацию запуска MCP и регистрирует плагин в личном marketplace. В Windows `~` означает каталог профиля пользователя.

Ожидаемый результат: `Installed... Open a new Codex task.` Если отсутствуют helpers, не совпадает marketplace source или уже существует незавершённый target, сначала устраните конкретную причину. Установка только wheel или копирование одного `SKILL.md` не заменяют этот процесс: точка входа MCP использует каталог `scripts` проекта.

## 4. Задайте устройство, credentials и доверенный SSH-ключ

Все helpers запускайте Python-интерпретатором установленного runtime. Замените пример адреса и username своими значениями.

**macOS/Linux**

```sh
export SECUREACCESS_HOST="192.0.2.10"
export SECUREACCESS_USER="secureaccess-agent"
SA_PLUGIN="$HOME/plugins/agent-for-secureaccess"
SA_PY="$HOME/plugins/.runtimes/agent-for-secureaccess/bin/python"
"$SA_PY" "$SA_PLUGIN/scripts/setup_local.py" host-key
"$SA_PY" "$SA_PLUGIN/scripts/setup_local.py" password
"$SA_PY" "$SA_PLUGIN/scripts/diagnose_connection.py"
```

**Windows PowerShell**

```powershell
$env:SECUREACCESS_HOST = "192.0.2.10"
$env:SECUREACCESS_USER = "secureaccess-agent"
$saPlugin = Join-Path $env:USERPROFILE "plugins/agent-for-secureaccess"
$saPython = Join-Path $env:USERPROFILE "plugins/.runtimes/agent-for-secureaccess/Scripts/python.exe"
& $saPython "$saPlugin/scripts/setup_local.py" host-key
& $saPython "$saPlugin/scripts/setup_local.py" password
& $saPython "$saPlugin/scripts/diagnose_connection.py"
```

Действие host-key получает предлагаемый публичный ключ без аутентификации, затем просит вставить SHA256 fingerprint, полученный независимо. Запись `[host]:830` добавляется в `~/.ssh/known_hosts` только при совпадении. Не копируйте показанный fingerprint обратно, выдавая его за независимо проверенный. Если существующий ключ отличается, нужна согласованная процедура ротации.

Действие password запрашивает пароль без отображения и сохраняет его в vault ОС. Это нужно для discovery: `inventory_capabilities`, `routing_summary`, `configuration_summary`, fixture probe и диагностический скрипт не принимают credentials из CSV. `connection_status` проверяет только локальную подготовку и не доказывает доступность устройства. В диагностике ожидайте `netconf_connected: true`, затем изучите capabilities.

Необязательное сохранение PSK в native vault:

```sh
# macOS/Linux
"$SA_PY" "$SA_PLUGIN/scripts/setup_local.py" tunnel-psk
```

```powershell
# Windows PowerShell
& $saPython "$saPlugin/scripts/setup_local.py" tunnel-psk
```

Helper запрашивает номер туннеля, headend, shared/split keys и формат. Повторите для каждого туннеля. Это **не отменяет** текущего требования PSK в CSV. В CSV apply значения из CSV имеют приоритет. `tunnel_psk_status` показывает только наличие записи в vault, а не правильность ключа CSV или устройства.

Для headless login поддерживаются `SECUREACCESS_SECRET_PROVIDER=environment`, `ISR_PASSWORD`, переданный менеджером секретов процесса, и заданный `SECUREACCESS_USER`. Это provider пароля входа, а не environment provider для tunnel PSK. Не вводите секреты литералами в историю shell и не сохраняйте в source control.

### Передайте окружение процессу Codex

Переменные выше действуют только в текущем shell и дочерних процессах. Для CLI запустите `codex` из этого настроенного shell. Уже запущенное desktop-приложение не получит переменные автоматически: задайте их в фактическом launch/MCP environment средствами вашей локальной конфигурации, перезапустите приложение и до подключения проверьте target через `connection_status`. Installer не сохраняет за вас host и username.

После изменения target/environment, обновления кода или ротации сохранённых credentials перезапустите MCP-сервер. Откройте новую задачу и убедитесь, что skill и нужные инструменты доступны. Подготовленные планы теряются при перезапуске. Сервер работает с одним target за раз; host в CSV должен совпадать с `SECUREACCESS_HOST`.

## 5. Запустите skill и соберите актуальное состояние

Пример запроса в Codex:

> Используй skill secureaccess-netconf. Подготовь Cisco IOS XE Secure Access для моего зарегистрированного маршрутизатора. Начни с read-only discovery и предложи выбрать Basic или Advanced. Не применяй изменения, пока я не согласую точные diff и digest подготовленного плана.

Разрешите чтение нужного маршрутизатора. Запросите `connection_status`, `inventory_capabilities`, `routing_summary` и при необходимости `configuration_summary`. Проверьте:

1. Правильность target и работоспособность NETCONF login.
2. Advertised models/capabilities и фактически полученные operational data.
3. Source interface и его IPv4, ISP gateway, default route и обратный путь управления.
4. Занятые tunnel IDs и точные интерфейсы для create/reuse.
5. Существующие ingress policies и имена генерируемых объектов, способные вызвать конфликт.

Configured routes и operational RIB — разные виды подтверждения. Пустой результат или ошибка чтения означает неизвестное состояние, а не разрешение угадывать. Краткие sanitized summaries не содержат всех параметров для reuse; при необходимости получите разрешённое сравнение текущих и предлагаемых настроек без секретов.

Offline-подготовка шаблона возможна без доступа к устройству; проверка на устройстве и применение — нет.

## 6. Выберите режим, заполните и проверьте CSV

До создания выберите **Basic** или **Advanced**. Basic скрывает встроенные значения, Advanced показывает их. Запросите `create_configuration_csv` с `platform="iosxe"`, выбранным `mode` и подтверждёнными name/host. Сохраните частную копию вне репозитория. Файлы `examples` показывают формат и не являются готовыми deployment-конфигурациями.

Сохраните заголовок `section;item;field;value;required;description`, разделитель `;` и UTF-8 (BOM допустим). Обычно меняйте только `value`. Замените все `<<< REQUIRED >>>`. Имена полей и enum values не переводите. Для нескольких сетей скопируйте строку списка с новым положительным `item`; для нескольких туннелей — всю группу tunnel. Сохраняйте descriptions и столбец `required`. Значение `required=no` не отменяет проверку. Формулы не используйте.

| Группа CSV | Что указать и проверить |
| --- | --- |
| `meta`, `device` | Schema `2`, platform `iosxe`, выбранный режим, имя устройства и точный зарегистрированный host. |
| `connection` | Фактические username/password; сейчас обязательны оба. |
| `network` | `pbr` или `static`, ISP gateway, `router_wan_ip`, совпадающий с адресом source interface, prefix генерируемых имён. Сначала оставьте object action пустым/`reject`. |
| `management_prefix` | Management CIDRs для реального обратного пути клиента; не `0.0.0.0/0`. |
| `destination_prefix` | Защищаемые destination CIDRs. В PBR `0.0.0.0/0` означает любое назначение для выбранных sources. |
| `source_prefix`, `ingress_interface` | Source LANs для PBR и интерфейсы фактического входа трафика. Не выводите ingress из обратного маршрута. |
| `bypass_prefix` | Необязательные явные destination exemptions PBR. Deny означает обычную маршрутизацию, а не drop. Пустые строки исключений не создают. |
| `pbr` | Для PBR — `failure_behavior=normal-routing`. Для static оставьте его и все source/bypass/ingress values пустыми. |
| `tunnel`: выбор и identity | `TunnelN`, `create`/`reuse`, назначенные headend и local identity. Для reuse нужны `reuse_confirmed=true` и конкретный `change_scope`. |
| `tunnel`: адресация | Существующий source interface; ровно одно из VTI `address` и `unnumbered_interface`. Новый source loopback при явном запросе использует `/32`. |
| `tunnel`: секреты | `shared` с `shared_psk` либо `split` с обоими `local_psk` и `remote_psk`. Формат `plain`, `type6` или `hex`; у split выбранный формат общий для обоих ключей. Type 6 — уже зашифрованное значение, пригодное для target, а не plaintext для последующего шифрования. |
| `crypto`, MTU/MSS/distance | Соответствие назначенной tunnel policy. CSV допускает MTU 576–1390, MSS 536–1350 и MSS ≤ MTU−40; distance 1–254. CBC требует integrity, GCM требует пустое поле integrity. |

Basic подставляет prefix `sse`, GCM-256, PRF SHA256, DH 19/20, ESP GCM-256, без PFS, IKE lifetime 14400, IPsec lifetime 3600, DPD 10/3, MTU 1390, MSS 1350 и distance 1. Сверьте их с назначением: это defaults репозитория, а не доказательство пригодности для любой сети.

В следующих tunnel items пустые `source_interface`, `unnumbered_interface`, `mtu` и `tcp_mss` наследуются из первого item. Номер туннеля, headend, identity, numbered address, action и distance не наследуются. Для PBR числовой порядок item задаёт primary и secondary; `distance` не определяет порядок PBR.

Попросите Codex прочитать частный файл и вызвать `preview_configuration_csv`, при необходимости с актуальными occupied tunnel IDs. Продолжайте только при `valid=true`: устраните `missing_fields` и построчные `errors`, проверьте `inherited_fields`, public model и CLI/XML previews. `apply_ready=false` нормально для offline-этапа. Не выполняйте preview как CLI-скрипт маршрутизатора.

## 7. Проверьте предлагаемую конфигурацию на устройстве

Запросите `validate_configuration_csv` для того же файла. Инструмент использует login из CSV, проверяет target, обновляет tunnel inventory, сверяет семь точных model/submodule hashes из [profile.json](../backend/secureaccess/schemas/profile.json), согласует выбранные объекты с текущим состоянием и отправляет генерируемый patch через NETCONF `edit-config` с **`test-option=test-only`** в running. Commit и применение patch не выполняются.

Ожидаются `validated=true`, `schema_validated=true`, `device_written=false` и sanitized diff. Это подтверждение допустимости по схеме, а не готовности трафика. `transaction_ready` отражает наличие candidate/confirmed-commit; `false` само по себе не исключает lab-running. Отдельный validation path не сравнивает running digest после теста; проверки до/после и стабильности baseline выполняются при preparation/build.

По умолчанию конфликты отклоняются. Если генерируемые именованные объекты нужно менять, после проверки их использования и желаемого изменения задайте в Advanced `existing_objects_action=replace_named`, затем повторите preview и validation. Это не разрешает удалять посторонние next hops: competing forwarding entries у protected static prefix блокируются даже при `replace_named`; такой конфликт устраняется отдельным согласованным изменением. Management routes и посторонние keyring peers сохраняются.

При несовпадении схем нужен поддерживаемый и протестированный adapter/profile update. Не подменяйте hashes и не отключайте проверки. Prechecks также требуют operational revisions `Cisco-IOS-XE-interfaces-oper@2021-03-01`, `Cisco-IOS-XE-crypto-oper@2021-03-01` и `ietf-routing@2015-05-25`.

Необязательная локальная validation с тем же environment, без применения:

```sh
"$SA_PY" "$SA_PLUGIN/scripts/validate_csv.py" "/private/path/deployment.csv"
"$SA_PY" "$SA_PLUGIN/scripts/validate_adapter.py"
```

```powershell
& $saPython "$saPlugin/scripts/validate_csv.py" "C:\private\deployment.csv"
& $saPython "$saPlugin/scripts/validate_adapter.py"
```

Вторая команда использует сохранённый login и nonproduction GCM/CBC fixtures. Это необязательная диагностика схем, а не замена проверки вашего CSV или реального трафика. Sanitized fixture diagnostics доступны через `validate_adapter_fixture(debug=true)`.

## 8. Подготовьте, проверьте и согласуйте транзакцию

Запросите `prepare_configuration_apply` с проверенным CSV и осознанно выбранным `transaction_mode`:

| Режим | Поведение |
| --- | --- |
| `candidate` | Требует candidate, validate и confirmed-commit. При отсутствии останавливается; выбирайте, если fallback недопустим. |
| `lab-running` | Требует validate и rollback-on-error; при apply непосредственно меняет running под lock. Только для согласованной лабораторной процедуры. |
| `auto` (default) | Выбирает candidate при наличии нужных capabilities, иначе может выбрать lab-running. Всегда проверяйте возвращённый режим. |

Для test-only адаптер требует validate **1.1** в обоих режимах. Preparation повторно проверяет source addressing, management/ISP paths, наличие PSK, схемы, конфликты и стабильность running baseline. Конфигурация не применяется.

Продолжайте только при `apply_ready=true`. Проверьте **именно возвращённый diff**, target, transaction mode, `plan_id`, `approval_digest` и срок действия. Проверьте reuse, снятие shutdown на выбранных reused tunnels, crypto changes, намерение замены/сохранения PSK, порядок ACL bypass, привязку route-map и каждый маршрут. Значений секретов в diff нет; отдельно подтвердите принадлежность входных ключей нужному tunnel/headend.

Планы хранятся только в текущем MCP-процессе, действуют **900 секунд** и используются один раз. Изменение CSV, конфигурации маршрутизатора или перезапуск сервера требует новой preparation и approval. `No reconciled changes to apply` означает отсутствие новых конфигурационных изменений, но не доказывает работу трафика.

Организуйте эксклюзивное окно, остановив параллельные изменения операторов и автоматизации. Подготовьте recovery access и подходящий тестовый трафик. Явно согласуйте точные diff/digest и окно, например:

> Согласую показанный diff плана `<plan_id>` с digest `<approval_digest>` для указанного target в режиме `<transaction_mode>`. Эксклюзивное окно активно. Примени этот план один раз.

Подставьте реальные возвращённые идентификаторы. Создание шаблона, preview, validation и подтверждение reuse не разрешают apply.

## 9. Во время применения

Codex вызывает `apply_configuration_plan(plan_id, approval_digest, exclusive_window=true)`. Defaults: `confirm_timeout=180` и `postcheck_budget=60` секунд. MCP требует postcheck budget 30–300 секунд, confirm timeout не более 600 секунд и разницу минимум 60 секунд между budget и timeout; эта проверка аргументов действует и для lab-running.

Не завершайте MCP-процесс/сессию и не выполняйте параллельные изменения. Создайте разрешённый трафик от выбранного source через нужный ingress к protected destination, чтобы туннель мог установить SA и счётчики стали ненулевыми.

- **Candidate:** блокирует running и candidate, отклоняет непустые чужие candidate changes, повторно проверяет baseline, помещает/валидирует согласованный patch в candidate, выполняет nonpersistent confirmed commit и окончательно подтверждает его только после успешных bounded postchecks. При ошибке до финального подтверждения пытается откатить и проверить восстановление после reconnect. Неопределённый результат final commit не повторяется автоматически.
- **Lab-running:** блокирует running, повторно проверяет baseline, использует `test-then-set` с `rollback-on-error` и проверяет итоговую nonsecret-конфигурацию. При ошибке/неопределённости записи или configuration verification пытается выполнить owned inverse patch. После подтверждения конфигурации неуспешные или просроченные operational checks оставляют её установленной со статусом `applied_operational_pending`. **Таймера confirmed-commit в этом режиме нет.**

Postchecks проверяют состояние выбранных туннелей, ненулевые input/output counters, headend IKEv2 и двунаправленные ESP SA, underlay/management routes и ожидаемую конфигурацию. Для static также нужны ожидаемые active tunnel forwarding без конкурирующих outgoing interfaces. Эти наблюдения не заменяют application testing и измеренный failover test.

## 10. После применения: действия по результату

| Результат | Необходимое действие |
| --- | --- |
| `status=applied`, `applied=true` | Конфигурация прошла проверки режима. Lab-running отдельно возвращает `configuration_verified` и `operational_verified`. Перед отдельным сохранением startup проверьте сервис и management независимо. |
| `applied_operational_pending` | Lab-running конфигурация остаётся установленной. Проверьте headend/PSK/трафик/SA/routing через разрешённые operational tools либо выполните согласованное восстановление. Не объявляйте успех и не повторяйте план. |
| `failed` | Изучите `error`, diagnostic stage и `rollback_status`: ошибка не доказывает восстановление. При необходимости используйте recovery access. |
| `uncertain` или `final_commit_uncertain_manual_attention` | Не повторяйте попытку. Установите реальное состояние маршрутизатора через разрешённое чтение/консоль до нового плана. |
| Rollback `verified`, `staged_cleanup_verified`, `owned_inverse_verified` | Области проверки различаются: running после reconnect, очистка candidate либо nonsecret inverse verification. Сервис проверяется отдельно. Другие rollback statuses не подтверждают восстановление. |

После успешного изменения проверьте реальный application traffic, требуемый egress, management access, явные PBR bypasses, fallback в normal-routing и незатронутые сети. Interface counters — наблюдаемые суммарные значения, а не новое измерение до/после. Для pending требуется отдельная operational-проверка устройства/портала; в этом MCP-сервере нет специального инструмента повторного запуска postchecks для плана.

Каждый apply относится **только к running configuration** (`startup_persisted=false`). После приёмки сохраните running в startup отдельной разрешённой процедурой маршрутизатора; плагин этого не делает. Сохраните sanitized change record с target, diff, mode, результатом и подтверждениями проверки. Обработайте или удалите частный CSV по своей политике credentials.

## 11. Диагностика и повторное использование

| Симптом | Действие |
| --- | --- |
| Skill/tools отсутствуют или загружены старые | Завершите установку, перезапустите/перезагрузите плагин, откройте новую задачу. Проверяйте установленный source/runtime, а не только checkout. |
| Host не задан или CSV target отличается | Задайте target в реальном environment MCP, укажите тот же IPv4 в CSV и перезапустите сервер. |
| Vault недоступен/пароль отсутствует | Выполните setup от пользователя Codex, разблокируйте vault либо настройте явный environment provider логина. CSV credentials не обеспечивают discovery tools. |
| Host key неизвестен/изменился | Проверьте независимо и зарегистрируйте ключ/согласуйте ротацию. Не отключайте host-key verification. |
| Basic + static отклонён | Создайте Advanced; оставьте PBR failure behavior и source/bypass/ingress fields пустыми. |
| Management/WAN precheck не проходит | Проверьте фактический client address, точные global management routes, next-hop evidence, source IP и состояние интерфейса. Устраните реальную проблему топологии или поддержки. |
| Конфликт объекта/маршрута | Проверьте затронутые объекты. `replace_named` — осознанный выбор именованных объектов; competing static next hops требуют отдельного изменения. |
| Candidate dirty или lock denied | Согласуйте действия с владельцем; не удаляйте чужие изменения. |
| План истёк, использован или baseline изменился | Сначала установите текущий state, затем подготовьте и согласуйте новый план. Не повторяйте неопределённую попытку. |
| Схемы/operational models не совпадают | Остановите apply и соберите sanitized inventory для поддерживаемого обновления адаптера. |

Для обновления повторно запустите `scripts/install_local.py` из обновлённого репозитория от того же пользователя либо Windows update wrapper, перезапустите плагин и откройте новую задачу. Installer сохраняет OS credentials и known_hosts, но перезаписывает генерируемый MCP launch file. Проверьте environment и повторите validation; старые планы не используйте.

Необязательные developer checks из корня репозитория, в runtime с установленными test dependencies:

```sh
python -m unittest discover -s tests -q
python -m pytest -q
```

Unit tests проверяют локальную логику, но не квалифицируют реальное оборудование, forwarding и rollback. Исторические design-документы служат только справочным материалом. Рабочая процедура — это руководство и [актуальный справочник транзакций](netconf-apply.md).
