# TODO — Audit & optimisations `npm-api.sh`

> Audit du 2026-06-01 (v3.3.0). Chaque point a été **vérifié dans le code** (numéros de ligne indicatifs, à revérifier avant correction).
> **Hors scope :** la famille `--backup-host`, `--backup-host-list`, `--restore-host`, `--restore-backup`, `--clean-hosts` est volontairement **désactivée / non implémentée** — on n'y touche pas pour l'instant.

---

## 🔴 HIGH — bugs réels

- [x] **`redirect_host_list` : même bug d'alignement que `host_list`** — ✅ **corrigé en v3.3.0** (`truncate_pad` + multi-ligne des domaines + `truncate_pad` sur FORWARD DOMAIN).

- [x] **`list_cert_all` : statistiques Valid/Expired toujours fausses** — ✅ **corrigé en v3.3.0** (utilise le booléen `.expired` de l'API au lieu de comparer une chaîne ISO à `now`). Vérifié en live (Total 47 / Valid 47 / Expired 0, cohérent avec la liste).

- [x] **`cert_delete` / `cert_purge_files` : aucune vérif que le cert est encore référencé par un host** — ✅ **corrigé en v3.3.0**. Avant la confirmation, le script liste les proxy/redirection hosts référençant le cert ; avertissement pour le soft-delete, et **`--purge` refusé** tant que le cert est utilisé.

- [x] **`access_list_create` exécuté en plein parsing ; le dispatch est du code mort** — ✅ **corrigé en v3.3.0** (case alignée sur `--access-list-update` : stocke `ACCESS_LIST_CREATE_ARGS` + `ACCESS_LIST_CREATE=true`, exécution déplacée dans le bloc de dispatch).

## 🟠 MED — incohérences

- [x] **`--pass-auth` asymétrique create vs update** — ✅ **corrigé en v3.3.0** (`access_list_create` consomme et valide `true|false` comme `access_list_update`).

- [x] **`user_create` force toujours `roles: ["admin"]`** — ✅ **corrigé en v3.3.0** (défaut **standard** ; nouveau flag `--user-create … --admin` pour le rôle admin).

- [x] **`user_create` écrit la réponse API dans `/tmp/npm_debug.log` en clair** — ✅ **corrigé en v3.3.0** (ligne de debug supprimée).

- [x] **`host_acl_enable`/`host_acl_disable` : mauvais chemin jq + pas de check HTTP** — ✅ **corrigé en v3.3.0** (`-w "HTTPSTATUS"` + statut 200 + `.error.message` + `exit 1` en échec).

- [x] **`host_show` : mauvais champ websocket + `colorize_boolean` mal utilisé** — ✅ **corrigé en v3.3.0** (`.allow_websocket_upgrade` + scheme affiché en clair). Vérifié en live (`Scheme: http`, `Websocket Upgrade: true`).

- [x] **`--cert-show-all` documenté mais non implémenté** — ✅ **corrigé en v3.3.0** (ajouté comme alias de `--cert-list`). Vérifié en live.

- [x] **`cert_delete` : `exit 1` quand l'utilisateur annule** — ✅ **corrigé en v3.3.0** (`exit 0` sur annulation volontaire).

- [x] **`--info` n'a pas de branche de dispatch dédiée** — ✅ **corrigé en v3.3.0** (branche `elif [ "$INFO" = true ]` ajoutée).

- [x] **Globals non initialisés sous `set -u`** — ✅ **corrigé en v3.3.0** (`CERT_ID`, `GENERATED_CERT_ID`, `USER_ID`, `search_term` initialisés dans le bloc du haut).

- [x] **Codes de sortie incohérents** (`return 1` ⇒ exit 0 en échec) — ✅ **corrigé en v3.3.0** : `host_enable`/`host_disable` et `redirect_host_enable`/`redirect_host_disable` renvoient `return 1` sur tous les chemins d'échec. `host_ssl_enable` était déjà correct (`HTTPSTATUS` + `return 1`).

- [~] **`$?` après substitution de commande** dans `host_enable/disable/ssl_enable` — **revérifié** : pour `VAR=$(curl …)` le `$?` capture bien le statut de curl (pas un bug). Reste valable : `curl -s` masque les 4xx/5xx — compensé par le check `jq -e '.error'`. Amélioration possible (statut HTTP explicite) mais non bloquante.

- [ ] **`"$1"` non gardé après `shift`** (famille backup/restore **désactivée** — hors scope tant qu'on ne réactive pas ces cases).

## 🟡 LOW — qualité / cosmétique

- [x] **3 blocs jq de formatage cert quasi identiques** — ✅ **corrigé en v3.3.0** (helper `cert_colorize` + chaîne partagée `CERT_JQ_FMT` ; incohérence `Provider :`/`Provider:` résolue). Vérifié en live.
- [x] **Textes d'usage en français** isolés — ✅ **corrigé en v3.3.0** (`--host-update` et `--access-list-show` traduits en anglais). Vérifié en live.
- [~] **`pad`/`truncate_pad` : glyphes multi-octets** — **non modifié** : `✘` et `…` s'affichent en 1 cellule = 1 code point, donc **pas de décalage réel** ; toucher `pad` risquerait de casser l'alignement corrigé. À revoir seulement si un glyphe large (emoji) est introduit dans ces colonnes.
- [x] **`access_list` : libellé en dur + pas de troncature + `%d` sur null** — ✅ **corrigé en v3.3.0** (`.proxy_host_count // 0`, `name` tronqué via `truncate_pad`, colonne à largeur fixe). Vérifié en live (compte 2 chiffres ne casse plus la box).
- [x] **Regex de confirmation incohérentes** — ✅ **corrigé en v3.3.0** (tout sur `^[Yy]$`).
- [x] **Stubs morts `-O`/`-J`** — ✅ **corrigé en v3.3.0** (cases supprimées).
- [x] **`cert_generate` : double `GET /nginx/certificates` redondant** — ✅ **corrigé en v3.3.0** (2e bloc dupliqué supprimé).

## ⚡ Optimisations générales (transverses)

- [x] **Token relu ~81×** via `$(cat "$TOKEN_FILE")` — ✅ **corrigé en v3.3.0** : cache global `$TOKEN` peuplé dans `check_token_notverbose`, en-têtes en `${TOKEN:-$(cat "$TOKEN_FILE")}` (repli sûr si non peuplé). 81 occurrences remplacées. Vérifié en live (auth OK sur 5 commandes).
- [x] **`host_list` : 1 `curl` par host** pour le domaine du cert — ✅ **corrigé en v3.3.0** : `/nginx/certificates` récupéré **une seule fois**, table `id → domaines` (`CERT_DOMAINS`), lookup local. Vérifié en live (CERT DOMAIN correct, ~0,5s).
- [x] **`full_backup`** — analysé : la boucle par host est **légitime** (récupère des ressources distinctes par host/cert : nginx.conf, logs, contenu PEM + clé privée — absents de la liste bulk), donc rien à éliminer comme dans `host_list`. Le token profite déjà du cache `$TOKEN`. **Corrigé au passage** : double comptage de `success_count` par cert. Vérifié en live (`--backup` exit 0, Success/Error 112/0, 982 fichiers).
- [x] **Garde-fous `set -e` / statut HTTP** — ✅ **corrigé en v3.3.0** : les 11 comparaisons `[ "$HTTP_STATUS" -eq … ]` sont protégées par `${VAR:-0}` (réponse vide → branche d'erreur propre au lieu d'un abandon), et les 10 `((var++))` (qui abandonnaient sous `set -e` quand la variable valait 0) convertis en `var=$((var + 1))`. _(reste : `// empty` systématique sur les `jq -r` — non fait, plus large.)_
- [x] **Bloc d'init des globals** — ✅ **corrigé en v3.3.0** : booléens `0` → `false` (`HTTP2_SUPPORT`, `SSL_FORCED`, `HSTS_ENABLED`, `HSTS_SUBDOMAINS`, même classe que le fix Issue #23), doublon `AUTO_YES` supprimé. Vérifié : aucune comparaison entière sur ces vars, affichage `--show-default` inchangé.
