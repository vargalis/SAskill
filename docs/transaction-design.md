# Реализованный адаптер и транзакция

Текущий workflow описан в [netconf-apply.md](netconf-apply.md).
Ниже сохранён исходный проект требований этапа 1; это историческое описание.

# Безопасный workflow и границы этапа 1

## Текущий поток

YAML validation → password resolution → verified NETCONF SSH → hello inventory → optional monitoring/library get → running native get-config → prechecks → redacted intent report. Нет lock/edit/validate/commit RPC; apply запрещен.

Предварительные проверки сейчас охватывают candidate, validate, confirmed-commit, наличие native-модуля, чтение конфигурации, существование source interface и конфликт имени Tunnel. Они не подтверждают WAN up, маршрут до headend, доступность management, IKE или IPsec.

## Выбор YANG пути

Будущий registry должен связывать адаптер с платформой/release и точными схемами, features/deviations. Получать схемы через advertised monitoring get-schema или доверенный Cisco YANG bundle. Не скачивать произвольные URL из capability. Проверить writable augments native crypto/interface/routes, key encoding, identity type, enums и operational paths. Тестовые payloads должны быть подтверждены устройством в lab.

Порядок fallback: qualified native adapter → другой явно квалифицированный NETCONF model path → остановка с объяснением отсутствующей поддержки. Нельзя считать наличие слова crypto достаточным доказательством. CLI диагностика не получает разрешения на конфигурацию. Ни generic XML, ни CLI-over-NETCONF RPC не обходят этот gate.

## Будущая транзакция (еще не реализована)

1. Проверить schema-qualified adapter, обязательные capabilities, management/underlay routes, ownership объектов и отсутствие pending confirmed commit. Собрать безопасный семантический diff.
2. Согласовать эксклюзивное окно конфигурации. Lock running и candidate; обнаружить чужие candidate changes и остановиться, не discard/copy поверх них. Lock candidate не исключает CLI writers на всех IOS XE; требуется эксплуатационная блокировка иных writers.
3. Повторно прочитать running под lock, сверить fingerprint с одобренным планом. Render только owned nodes с секретами в памяти; edit-config candidate, validate candidate.
4. Confirmed commit с явно заданным timeout и запасом относительно timeout всех post-checks. Не использовать persistent commit первого адаптера: закрытие исходной сессии/истечение таймера должно приводить к откату по RFC, с обязательным lab-тестом конкретного IOS XE.
5. Проверить management, WAN/headend underlay path, VTI состояние, IKEv2 SA, IPsec SA/counters и требуемые статические маршруты через квалифицированные operational models. Interface up сам по себе недостаточен. Post-check исключение/unknown означает fail.
6. Только успешные проверки разрешают окончательный commit. До подтверждения при ошибке: cancel-commit, если доступен confirmed-commit 1.1; иначе не подтверждать, закрыть сессию/дождаться таймера. Проверить restored running после reconnect. До первого commit очистить только собственные staged changes.
7. Освободить locks, закрыть сессию. Не сообщать rollback success без проверки. После окончательного commit rollback по confirmed timer уже невозможен: проблемы persistence требуют отдельной процедуры. Running→startup persistence не считать автоматически выполненной.

## Секреты и артефакты

PSK/password запрещены в YAML как значения. Provider получает только SecretRef. XML с ключом не сохраняется, не логируется и не добавляется в diff. Inventory может содержать адреса/метаданные — это operational artifact для внутреннего использования. Не выводить исключения библиотек, которые способны включать входные данные. Модель XML parser отключает внешние сущности и сетевые обращения.
