# Руководство по развертыванию openwebservermanager

Язык по умолчанию: [简体中文](../../DEPLOYMENT.md)

Это руководство описывает развертывание openwebservermanager на Linux или Windows для браузерных SSH/RDP рабочих областей.

Порт по умолчанию: `23876`.

## Требования

- Go 1.25 или новее.
- Node.js 22 или новее для сборки frontend.
- Стабильный `OPENWEBSERVERMANAGER_MASTER_KEY`.
- Для RDP: Apache Guacamole `guacd` и FreeRDP runtime.

## Быстрое развертывание

```powershell
.\scripts\deploy.ps1
```

Скрипт архивирует текущий Git HEAD, загружает его на сервер, собирает frontend/backend, создает systemd service и слушает `0.0.0.0:23876`.

Параметры:

```powershell
.\scripts\deploy.ps1 `
  -HostName "your.server.ip" `
  -UserName "ubuntu" `
  -KeyPath "$env:USERPROFILE\.ssh\openwebservermanager_deploy_rsa" `
  -RemoteRoot "/opt/openwebservermanager" `
  -Port 23876
```

## Ручное развертывание Linux

```bash
git clone https://github.com/weige2008/openwebservermanager.git
cd openwebservermanager
npm --prefix frontend ci
npm --prefix frontend run build
go test ./...
go build -trimpath -ldflags "-s -w" -o /opt/openwebservermanager/bin/openwebservermanager ./cmd/openwebservermanager
```

Основные переменные:

```bash
OPENWEBSERVERMANAGER_ADDR=0.0.0.0:23876
OPENWEBSERVERMANAGER_DATA_DIR=/opt/openwebservermanager/data
OPENWEBSERVERMANAGER_MASTER_KEY=replace-with-a-long-random-secret
OPENWEBSERVERMANAGER_GUACD_HOST=127.0.0.1
OPENWEBSERVERMANAGER_GUACD_PORT=4822
```

В production используйте systemd и HTTPS reverse proxy.

## Release package

Скачайте архив из GitHub Releases и запустите:

```bash
OPENWEBSERVERMANAGER_ADDR=0.0.0.0:23876 \
OPENWEBSERVERMANAGER_DATA_DIR=./data \
OPENWEBSERVERMANAGER_MASTER_KEY=replace-with-a-long-random-secret \
./openwebservermanager
```

## Agent gateway

Создайте Agent gateway в консоли и выпустите одноразово отображаемый регистрационный токен. На узле с доступом к целевой приватной сети выполните:

```bash
OPENWEBSERVERMANAGER_AGENT_TOKEN='gateway_id.registration_secret' ./openwebservermanager-agent -server https://manager.example.com -name edge-office-1
```

Agent требует только исходящего доступа к серверу управления. После назначения через группу шлюзов SSH/SFTP передается по аутентифицированным двунаправленным TCP-потокам с аудитом; при недоступности шлюза скрытого перехода на прямое соединение нет. Для `/api/agent/` обратный прокси должен отключить буферизацию запросов и ответов и увеличить тайм-ауты.

## guacd

Для RDP нужен `guacd`:

```bash
sudo systemctl enable --now guacd
```

Настройте `OPENWEBSERVERMANAGER_GUACD_HOST=127.0.0.1` и `OPENWEBSERVERMANAGER_GUACD_PORT=4822`.

Выпуски Linux amd64 и Windows amd64 также содержат проверенные среды в `runtime/guacd/linux/bin/guacd` и `runtime/guacd/windows/bin/guacd.exe`. Необходимые DLL Cygwin уже включены в пакет Windows.

## Первый запуск

Откройте `http://<server-ip>:23876/login` и создайте первый пароль администратора.

## Проверка

```bash
curl -fsS http://127.0.0.1:23876/api/public/config
systemctl is-active openwebservermanager
npm --prefix frontend audit
go test ./...
go vet ./...
go run golang.org/x/vuln/cmd/govulncheck@v1.5.0 ./...
```
