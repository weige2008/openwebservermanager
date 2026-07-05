# Guide de déploiement openwebservermanager

Langue par défaut : [简体中文](../../DEPLOYMENT.md)

Ce guide explique comment déployer openwebservermanager sur Linux ou Windows et exposer les espaces de travail SSH/RDP dans le navigateur.

Port par défaut : `23876`.

## Prérequis

- Go 1.25 ou plus récent.
- Node.js 22 ou plus récent pour construire le frontend.
- Une clé stable `OPENWEBSERVERMANAGER_MASTER_KEY`.
- Pour RDP : Apache Guacamole `guacd` et FreeRDP runtime.

## Déploiement rapide

```powershell
.\scripts\deploy.ps1
```

Le script archive le Git HEAD courant, l’envoie au serveur, construit le frontend et le backend, écrit un service systemd et écoute sur `0.0.0.0:23876`.

Paramètres personnalisés :

```powershell
.\scripts\deploy.ps1 `
  -HostName "your.server.ip" `
  -UserName "ubuntu" `
  -KeyPath "$env:USERPROFILE\.ssh\openwebservermanager_deploy_rsa" `
  -RemoteRoot "/opt/openwebservermanager" `
  -Port 23876
```

## Déploiement Linux manuel

```bash
git clone https://github.com/weige2008/openwebservermanager.git
cd openwebservermanager
npm --prefix frontend ci
npm --prefix frontend run build
go test ./...
go build -trimpath -ldflags "-s -w" -o /opt/openwebservermanager/bin/openwebservermanager ./cmd/openwebservermanager
```

Variables principales :

```bash
OPENWEBSERVERMANAGER_ADDR=0.0.0.0:23876
OPENWEBSERVERMANAGER_DATA_DIR=/opt/openwebservermanager/data
OPENWEBSERVERMANAGER_MASTER_KEY=replace-with-a-long-random-secret
OPENWEBSERVERMANAGER_GUACD_HOST=127.0.0.1
OPENWEBSERVERMANAGER_GUACD_PORT=4822
```

En production, utilisez systemd et un reverse proxy HTTPS.

## Paquet de release

Téléchargez l’archive adaptée depuis GitHub Releases, puis lancez :

```bash
OPENWEBSERVERMANAGER_ADDR=0.0.0.0:23876 \
OPENWEBSERVERMANAGER_DATA_DIR=./data \
OPENWEBSERVERMANAGER_MASTER_KEY=replace-with-a-long-random-secret \
./openwebservermanager
```

## Reverse proxy

Configurez HTTPS et les en-têtes WebSocket upgrade :

```nginx
proxy_pass http://127.0.0.1:23876;
proxy_http_version 1.1;
proxy_set_header Upgrade $http_upgrade;
proxy_set_header Connection "upgrade";
```

N’activez `OPENWEBSERVERMANAGER_TRUST_PROXY_HEADERS=1` que si le proxy est fiable.

## guacd

RDP nécessite `guacd` :

```bash
sudo systemctl enable --now guacd
```

Configurez `OPENWEBSERVERMANAGER_GUACD_HOST=127.0.0.1` et `OPENWEBSERVERMANAGER_GUACD_PORT=4822`.

## Première initialisation

Ouvrez `http://<server-ip>:23876/login` et créez le premier mot de passe administrateur.

## Vérification

```bash
curl -fsS http://127.0.0.1:23876/api/public/config
systemctl is-active openwebservermanager
npm --prefix frontend audit
go test ./...
go vet ./...
go run golang.org/x/vuln/cmd/govulncheck@v1.5.0 ./...
```
