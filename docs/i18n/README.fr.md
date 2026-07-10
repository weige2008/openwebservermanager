# openwebservermanager

openwebservermanager est une console web auto-hébergée pour gérer les serveurs, les comptes de connexion chiffrés, les terminaux SSH dans le navigateur, les bureaux RDP, les transferts de fichiers, les enregistrements de session et les journaux d’audit.

Documentation par défaut : [简体中文](../../README.md)

Guide de déploiement : [Français](DEPLOYMENT.fr.md) | [简体中文](../../DEPLOYMENT.md)

## Fonctionnalités

- Backend Go avec frontend statique embarqué.
- Frontend aligné sur les conventions UI NewAPI : Rsbuild, React 19, TypeScript, Tailwind CSS v4, TanStack Router, TanStack Query, TanStack Table, Base UI, i18next et Zustand.
- Création du premier administrateur au premier lancement.
- SSH : pont WebSocket vers SSH PTY, avec mot de passe, clé privée et passphrase, ainsi que navigation SFTP, envoi, téléchargement, suppression et journaux d'audit contrôlés par les stratégies d'autorisation.
- Passerelle Agent : les nœuds distants se connectent au gestionnaire en sortie et relaient SSH/SFTP privé via des flux TCP bidirectionnels authentifiés et audités, sans repli silencieux vers une connexion directe.
- RDP : tunnel WebSocket Guacamole vers `guacd`; les identifiants restent côté serveur.
- Stockage JSON local avec champs sensibles chiffrés en AES-GCM.
- Index des enregistrements RDP et téléchargement ZIP pour les administrateurs.
- Builds GitHub Actions pour Linux, Windows et macOS.

## Démarrage rapide

```powershell
go run ./cmd/openwebservermanager
```

URL par défaut : `http://127.0.0.1:23876`. Répertoire de données par défaut : `data/`.

Définissez une clé maître stable avant d’utiliser de vrais identifiants :

```powershell
$env:OPENWEBSERVERMANAGER_MASTER_KEY = "replace-with-a-long-random-secret"
go run ./cmd/openwebservermanager
```

Ouvrez `/login` au premier lancement pour créer le mot de passe administrateur.

## RDP et guacd

RDP nécessite Apache Guacamole `guacd`. Configurez `OPENWEBSERVERMANAGER_GUACD_HOST` et `OPENWEBSERVERMANAGER_GUACD_PORT`, ou placez le binaire dans `runtime/guacd/<goos>/`.

Les enregistrements sont dans `data/recordings/{session_id}/`; les dossiers de transfert dans `data/drives/{session_id}/`.

## Développement

```powershell
npm --prefix frontend install
npm --prefix frontend run dev
npm --prefix frontend run build
go test ./...
```

## Déploiement

Voir [DEPLOYMENT.fr.md](DEPLOYMENT.fr.md).

```powershell
.\scripts\deploy.ps1
```

## Publication

Mettez à jour `VERSION`, puis poussez un tag sémantique :

```powershell
git tag v1.0.11
git push origin v1.0.11
```
