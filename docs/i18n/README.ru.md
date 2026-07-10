# openwebservermanager

openwebservermanager — это самостоятельная веб-консоль для управления серверными активами, зашифрованными учетными записями подключения, SSH-терминалами в браузере, RDP-рабочими столами, передачей файлов, записями сеансов и журналами аудита.

Документация по умолчанию: [简体中文](../../README.md)

Руководство по развертыванию: [Русский](DEPLOYMENT.ru.md) | [简体中文](../../DEPLOYMENT.md)

## Возможности

- Go backend со встроенным статическим frontend.
- Frontend в стиле новой UI-схемы NewAPI: Rsbuild, React 19, TypeScript, Tailwind CSS v4, TanStack Router, TanStack Query, TanStack Table, Base UI, i18next и Zustand.
- Создание администратора при первом запуске.
- SSH: мост WebSocket к SSH PTY с паролем, приватным ключом и passphrase, а также управляемые политиками просмотр SFTP, загрузка, скачивание, удаление и журналы аудита.
- Agent gateway: удаленные узлы сами подключаются к серверу управления и передают приватный SSH/SFTP через аутентифицированные двунаправленные TCP-потоки с аудитом, без скрытого перехода на прямое соединение.
- RDP: WebSocket tunnel Guacamole к `guacd`; учетные данные остаются на сервере.
- Локальное JSON-хранилище с AES-GCM шифрованием секретных полей.
- Индекс RDP-записей и ZIP-загрузка для администраторов.
- GitHub Actions сборки для Linux, Windows и macOS.

## Быстрый запуск

```powershell
go run ./cmd/openwebservermanager
```

URL по умолчанию: `http://127.0.0.1:23876`. Каталог данных: `data/`.

Перед хранением реальных учетных данных задайте стабильный мастер-ключ:

```powershell
$env:OPENWEBSERVERMANAGER_MASTER_KEY = "replace-with-a-long-random-secret"
go run ./cmd/openwebservermanager
```

При первом запуске откройте `/login` и создайте пароль администратора.

## RDP и guacd

Для RDP нужен Apache Guacamole `guacd`. Укажите `OPENWEBSERVERMANAGER_GUACD_HOST` и `OPENWEBSERVERMANAGER_GUACD_PORT` или поместите бинарный файл в `runtime/guacd/<goos>/`.

Записи сохраняются в `data/recordings/{session_id}/`; каталоги передачи файлов — в `data/drives/{session_id}/`.

## Разработка

```powershell
npm --prefix frontend install
npm --prefix frontend run dev
npm --prefix frontend run build
go test ./...
```

## Развертывание

См. [DEPLOYMENT.ru.md](DEPLOYMENT.ru.md).

```powershell
.\scripts\deploy.ps1
```

## Релизы

Обновите `VERSION`, затем отправьте semantic version tag:

```powershell
git tag v1.0.11
git push origin v1.0.11
```
