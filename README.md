# Correction nginx2root pour 3CX Linux

Script a executer **sur votre serveur 3CX Linux**, en root, pour appliquer la correction provisoire des failles **nginx2root** (CVE-2026-123007 et CVE-2026-123633) tant que 3CX n'a pas publie un nginx 1.30.7 ou plus recent.

Les versions actuelles de 3CX V20 pour Linux livrent leur propre nginx (souvent 1.30.6) avec HTTP/2 active. Deux des failles nginx2root s'appuient sur HTTP/2. Ce script desactive HTTP/2 dans la configuration, bloque le chargement automatique du module noyau SCTP, et peut optionnellement mettre a jour les paquets nginx Debian (sans toucher au binaire nginx fourni par 3CX).

Guide public dont ce script s'inspire :

https://portal.incentre.net/news/view/32/nginx2root--what-it-means-for-3cx-phone-systems--and-how-to-mitigate-it/

## Prerequisites

- Un serveur **3CX V20 pour Linux** (Debian). Les 3CX Windows ne sont pas pris en charge.
- Un acces **root** (`sudo`).
- Les outils habituels de Debian (`bash`, `curl`, `dpkg`, `systemctl`). `curl` doit gerer `--http2`.
- **Avant `--apply`** : prenez un snapshot de la machine (ou une sauvegarde 3CX recente). Le script cree aussi une sauvegarde de la configuration nginx dans `/root/nginx2root-<date>/`, mais un snapshot reste recommande.

## Controle, puis correction

Copiez le fichier `nginx2root-3cx-fix.sh` sur le serveur, puis :

```bash
# 1. Controle seul (aucune modification) : le script indique ce qui changerait
sudo bash nginx2root-3cx-fix.sh

# 2. Si le resultat est "A CORRIGER", appliquez la correction
sudo bash nginx2root-3cx-fix.sh --apply
```

Le mode par defaut est le controle. `--apply` doit etre demande explicitement.

Options utiles :

- `--restart` : redemarre nginx au lieu d'un simple rechargement (`reload` par defaut, pour eviter une coupure des sessions web).
- `--debian-upgrade` : met a jour uniquement les paquets nginx Debian deja installes. Le binaire nginx de 3CX est protege (empreinte SHA-256) et restaure s'il est modifie. Desactive par defaut.
- `--only-3cx` : ne modifie que les fichiers de configuration nginx de 3CX.
- `--help` : affiche l'aide.

## Verification depuis l'exterieur

A la fin, le script affiche la commande a lancer **depuis un autre poste** (pas depuis le serveur lui-meme). Elle doit afficher `1.1` :

```bash
curl --http2 -skI -o /dev/null -w '%{http_version}\n' https://VOTRE-FQDN/
```

Si la console d'administration 3CX utilise le port 5001 :

```bash
curl --http2 -skI -o /dev/null -w '%{http_version}\n' https://VOTRE-FQDN:5001/
```

Si la commande affiche `2`, HTTP/2 est encore propose sur ce port.

## Retour arriere

Pour revenir a la configuration nginx precedente (derniere sauvegarde `/root/nginx2root-*`, ou un dossier precis) :

```bash
sudo bash nginx2root-3cx-fix.sh --rollback
sudo bash nginx2root-3cx-fix.sh --rollback /root/nginx2root-AAAAMMJJ-HHMMSS
```

Le retour arriere restaure les fichiers de configuration, teste `nginx -t`, puis recharge nginx. Il **ne retire pas** le blocage SCTP et **ne retrograde pas** d'eventuels paquets nginx Debian.

## Ce que le script modifie (avec `--apply` uniquement)

- Tous les fichiers de configuration nginx charges (`nginx -T`) et ceux de `/var/lib/3cxpbx` : `http2 on;` devient `http2 off;`, et `http2` est retire des lignes `listen`. Le script ne modifie jamais un lien symbolique, uniquement le fichier reel.
- Une sauvegarde est ecrite dans `/root/nginx2root-<date>/` (fichier `MANIFEST` et copies des fichiers modifies). Si `nginx -t` echoue, la sauvegarde est restauree automatiquement.
- Un rechargement de nginx (`systemctl reload nginx`), ou un redemarrage si vous avez passe `--restart`.
- Le fichier `/etc/modprobe.d/disable-sctp.conf` recoit la ligne `install sctp /bin/false`. Si le module `sctp` est deja charge, le script le signale et **ne le decharge pas**.
- Avec `--debian-upgrade` seulement : mise a jour ciblee des paquets nginx Debian, avec protection du binaire 3CX.

Si la correction est deja en place, `--apply` ne change rien (comportement idempotent).

Un journal est ajoute dans `/var/log/nginx2root.log`.

## Resultat et codes de sortie

Le script termine par une ligne `RESULTAT:` :

| Resultat | Signification | Code |
|---|---|---|
| `DEJA CORRIGE` | Rien a faire | 0 |
| `A CORRIGER (lancer avec --apply)` | Le controle a trouve un point a corriger | 0 |
| `CORRIGE` | La correction a ete appliquee | 0 |
| `RESTAURE` | Retour arriere effectue | 0 |
| `ECHEC (configuration restauree)` | Erreur ; la configuration a ete remise en place si possible | 1 |
| `ECHEC (HTTP/2 toujours propose)` | Apres `--apply`, HTTP/2 est encore offert | 3 |
| `NON 3CX` | Le paquet `3cxpbx` n'est pas installe | 2 |

## Points d'attention

- Une **mise a jour 3CX** peut reecrire `nginx.conf` et reactiver HTTP/2. Relancez le controle (puis `--apply` si besoin) apres chaque mise a jour, tant que le nginx livre par 3CX est inferieur a 1.30.7.
- Une fois 3CX livre avec nginx 1.30.7 ou plus, installez cette version et **redemarrez** nginx (un reload garderait l'ancien binaire). Vous pourrez alors reactiver HTTP/2 si vous le souhaitez. Conservez le blocage SCTP jusqu'a ce que le noyau soit corrige.
- Ce script ne s'applique pas a **3CX pour Windows**.
- Faites un snapshot (ou une sauvegarde 3CX) avant `--apply`.
