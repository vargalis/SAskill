# Windows, macOS и Linux

Требования: Python 3.11+, Codex CLI с поддержкой plugins и системными plugin-creator helpers. Плагин использует локальный stdio MCP. Поддержка Linux относится к локальному MCP/CLI, а не обещанию наличия desktop-приложения Codex на Linux.

На macOS/Linux из каталога плагина:

```sh
python3 scripts/install_local.py
```

На Windows:

```powershell
py -3 scripts/install_local.py
```

Исходники находятся в ~/plugins/agent-for-secureaccess, runtime в ~/plugins/.runtimes/agent-for-secureaccess. На Windows используются Scripts/python.exe, на macOS/Linux bin/python. MCP config записывается в UTF-8 без BOM с путями конкретной установки. Сборка исходников содержит переносимый module entrypoint python -m secureaccess_mcp; не копируйте сгенерированный Windows MCP config на другую ОС.

Если codex отсутствует в PATH, используйте --codex /полный/путь/codex. На Windows дополнительно проверяется стандартная папка приложения. CODEX_HOME используется для поиска системных helpers; personal marketplace остается в ~/.agents/plugins/marketplace.json. Без helpers установщик сообщает об ограничении, не создает выдуманный marketplace format.

Секреты: Windows Credential Manager, macOS Keychain, Linux Secret Service (нужна доступная D-Bus user session и разблокированное хранилище, например GNOME Keyring). setup_local.py password записывает только в системное хранилище. При недоступности хранилища ошибка не приводит к сохранению пароля в файле. Доступ macOS Keychain может потребовать локального разрешения пользователем.

Headless Linux: передайте SECUREACCESS_SECRET_PROVIDER=environment и ISR_PASSWORD через среду процесса/secret manager. Не присылайте пароль в чат, не помещайте его в .mcp.json, YAML или аргументы команд. Provider выбирается явно; не выполняйте setup_local.py password для environment mode. Этот режим работает и на Windows/macOS.

SSH known_hosts использует Path.home()/.ssh/known_hosts. Применяется одинаковая проверка SSH host key на всех ОС. Секреты не мигрируют между ОС автоматически — на каждом компьютере нужно заново подготовить password/key. NETCONF protocol, генератор и wizard общие для всех платформ.

Фактическая проверка: Windows execution и MCP stdio; platform selection и Linux installer flow проверяются симуляцией. Нативные macOS Keychain/Linux D-Bus и реальная установка на этих ОС требуют проверки на соответствующих системах.
