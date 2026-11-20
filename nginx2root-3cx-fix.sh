#!/bin/bash
# nginx2root-3cx-fix.sh: interim mitigation for nginx2root on a single
# 3CX Linux server (CVE-2026-123007, CVE-2026-123633: HTTP/2 in nginx).
# No fixed 3CX build exists yet for the bundled nginx.
#
# Contact < cyrille.georgel@cx-engine.com >
#
# Run locally as root on the 3CX host:
#   sudo bash nginx2root-3cx-fix.sh           # check only (default)
#   sudo bash nginx2root-3cx-fix.sh --apply
#
# The script inventories every nginx binary (running process, 3CX package,
# Debian packages, dpkg diversions), decides vulnerability from the version
# (fixed at 1.30.7 / 1.31.9, or a Debian changelog backport), and finds
# every config file from nginx -T plus /var/lib/3cxpbx. Paths are resolved
# with readlink -f; a symlink is never the target of sed -i.
# Backups go to /root/nginx2root-<timestamp>/ (MANIFEST, real-path copies
# via mkdir -p, cp -p and cmp). nginx -t is required; on failure the
# backup is restored automatically. SCTP autoload is blocked on --apply
# (the module is flagged if already loaded, never unloaded). A local curl
# is run on every SSL listen port. The default is idempotent and read-only.

set -uo pipefail
export LC_ALL=C

FIXED_STABLE="1.30.7"
FIXED_MAINLINE="1.31.9"
CVE_MAIN="CVE-2026-123007"
SCTP_CONF="/etc/modprobe.d/disable-sctp.conf"
SCTP_LINE="install sctp /bin/false"
HOST_LOG="/var/log/nginx2root.log"
BACKUP_PREFIX="/root/nginx2root"
NGINX_BIN_DEFAULT="/usr/sbin/nginx"
H2_RE='^[[:space:]]*http2[[:space:]]+on[[:space:]]*;|^[[:space:]]*listen[[:space:]][^#;]*[[:space:]]http2([[:space:]]|;)'

MODE="check"
DO_RESTART=0
DO_DEB_UPG=0
ONLY3CX=0
ROLLBACK_DIR=""

NGINX_BIN=""
NGINX_REAL=""
NGINX_VER=""
PBX_VER=""
OWNER=""
DEB_STATE="n/a"
HOST_NAME=""
TS=""
BACKUP_DIR=""
BAK_USED=""
RUN_BIN=""
ANY_VULN=0
NB_BINS=0
SKIP_H2=0
HTTP2_ACTIVE="no"
LOCAL_CURL=""
SCTP_LOADED="no"
SCTP_CONF_STATE="no"
SCTP_FLAG="no"
STILL=0
VERIFY_FQDN=""
declare -a DEB_PKG_ARR=()
declare -A BINS=()
declare -A CONF=()
declare -a TO_FIX=()

usage() {
    cat <<EOF
Usage: sudo bash $(basename "$0") [--check] [--only-3cx] [--debian-upgrade] [--restart]
       sudo bash $(basename "$0") --apply     [memes options]
       sudo bash $(basename "$0") --rollback [dossier] [--restart]

Correction provisoire de nginx2root sur un serveur 3CX Linux
(CVE-2026-123007 / CVE-2026-123633). Par defaut le script ne fait que
controler (aucune modification).

  --check              Controle seul (defaut). N'affiche que ce qui
                       changerait, sans modifier le serveur.
  --apply              Applique la correction (option explicite).
  --rollback [dossier] Restaure la derniere sauvegarde /root/nginx2root-*
                       (ou le dossier indique), teste nginx -t, puis
                       recharge nginx. Ne retire pas le blocage SCTP et
                       ne retrograde pas les paquets nginx Debian.
  --only-3cx           Limite la modification aux fichiers de
                       configuration nginx de 3CX.
  --debian-upgrade     Met a jour uniquement les paquets nginx Debian
                       deja installes (jamais un apt upgrade complet).
                       Le binaire nginx fourni par 3CX est protege par
                       une empreinte SHA-256 et restaure s'il change.
                       Desactive par defaut.
  --restart            Redemarre nginx (systemctl restart) au lieu d'un
                       simple rechargement (reload). Desactive par defaut.
  -h, --help           Affiche cette aide.

Journal : ${HOST_LOG}
Sauvegardes : ${BACKUP_PREFIX}-<horodatage>/

Codes de sortie :
  0  OK (deja corrige, corrige, ou controle termine)
  1  erreur (la configuration a ete restauree si une sauvegarde existait)
  2  ce serveur n'est pas un 3CX Linux
  3  HTTP/2 est encore propose apres --apply

Relancer ce script apres chaque mise a jour 3CX tant que nginx < ${FIXED_STABLE}.

Documentation publique :
  https://portal.incentre.net/news/view/32/nginx2root--what-it-means-for-3cx-phone-systems--and-how-to-mitigate-it/
Script d'origine : Encom Conseil, encom-3cx-nginx2root.sh.
EOF
}

# ---------------------------------------------------------------------------
# Logging and final verdict (user-facing text is French, without accents)
# ---------------------------------------------------------------------------
log() {
    local line
    line="[$(date '+%F %T')] $*"
    printf '%s\n' "$line" | tee -a "$HOST_LOG"
}

die() {
    # $1 exit code, $2 RESULTAT label, $3 optional detail
    local code="$1" label="$2" detail="${3:-}"
    [ -n "$detail" ] && log "$detail"
    print_recap
    printf '\nRESULTAT: %s\n' "$label"
    print_verify_hint
    exit "$code"
}

print_recap() {
    printf '\n--- Recapitulatif ---\n'
    printf 'Hote            : %s\n' "${HOST_NAME:-?}"
    printf '3CX             : %s\n' "${PBX_VER:-?}"
    printf 'nginx           : %s (%s, paquet %s)\n' "${NGINX_VER:-?}" "${NGINX_REAL:-?}" "${OWNER:-?}"
    printf 'Binaires nginx  : %s (vulnerable: %s)\n' "${NB_BINS:-?}" "$( [ "${ANY_VULN:-0}" -eq 1 ] && echo oui || echo non )"
    printf 'HTTP/2          : %s\n' "$( [ "${HTTP2_ACTIVE:-no}" = yes ] && echo actif || echo desactive )"
    printf 'Blocage SCTP    : %s (module charge: %s)\n' \
        "$( [ "${SCTP_CONF_STATE:-no}" = yes ] && echo present || echo absent )" \
        "${SCTP_LOADED:-?}"
    printf 'Curl local      : %s\n' "${LOCAL_CURL:-n/a}"
    printf 'Sauvegarde      : %s\n' "${BAK_USED:-aucune}"
    printf 'Journal         : %s\n' "$HOST_LOG"
}

print_verify_hint() {
    local fqdn="${VERIFY_FQDN:-${HOST_NAME:-pbx.exemple.fr}}"
    printf '\nPour verifier depuis l'\''exterieur (la commande doit afficher 1.1) :\n'
    printf '  curl --http2 -skI -o /dev/null -w '\''%%{http_version}\\n'\'' https://%s/\n' "$fqdn"
    printf 'Si la console web utilise le port 5001 :\n'
    printf '  curl --http2 -skI -o /dev/null -w '\''%%{http_version}\\n'\'' https://%s:5001/\n' "$fqdn"
    printf '\nRelancer ce script apres chaque mise a jour 3CX tant que nginx < %s.\n' "$FIXED_STABLE"
}

# ---------------------------------------------------------------------------
# Discovery helpers (same logic as the fleet on-host payload)
# ---------------------------------------------------------------------------
nginx_ver_of() {
    local bin="$1"
    [ -n "$bin" ] && [ -x "$bin" ] || return 0
    "$bin" -v 2>&1 | sed -n 's#.*nginx/\([0-9][0-9.]*\).*#\1#p'
}

discover_nginx_bin() {
    local es path
    NGINX_BIN="$(command -v nginx 2>/dev/null || true)"
    if [ -z "$NGINX_BIN" ] && [ -x "$NGINX_BIN_DEFAULT" ]; then
        NGINX_BIN="$NGINX_BIN_DEFAULT"
    fi
    es="$(systemctl show -p ExecStart --value nginx 2>/dev/null || true)"
    path="$(printf '%s' "$es" | sed -n 's/.*path=\([^ ;]*\).*/\1/p')"
    if [ -n "$path" ] && [ -x "$path" ]; then
        NGINX_BIN="$path"
    fi
}

# Prefer systemd -c when present, else nginx -t.
run_nginx_test() {
    local es args cflag
    es="$(systemctl show -p ExecStart --value nginx 2>/dev/null || true)"
    args="$(printf '%s' "$es" | sed -n 's/.*argv\[\]=\([^;]*\).*/\1/p')"
    cflag=""
    if printf '%s' "$args" | grep -Eq -- '(^|[[:space:]])-c[[:space:]]+[^[:space:]]+'; then
        cflag="$(printf '%s' "$args" | sed -n 's/.*-c[[:space:]]\{1,\}\([^[:space:]]*\).*/\1/p')"
    fi
    if [ -n "$cflag" ]; then
        "$NGINX_BIN" -t -c "$cflag"
    else
        "$NGINX_BIN" -t
    fi
}

restart_or_reload_nginx() {
    if [ "$DO_RESTART" -eq 1 ]; then
        log "Redemarrage de nginx (systemctl restart nginx)."
        systemctl restart nginx
    else
        log "Rechargement de nginx (systemctl reload nginx)."
        systemctl reload nginx
    fi
}

collect_deb_pkgs() {
    local p
    DEB_PKG_ARR=()
    while IFS= read -r p; do
        [ -n "$p" ] || continue
        DEB_PKG_ARR+=("$p")
    done < <(dpkg-query -W -f='${binary:Package} ${Status}\n' 'nginx' 'nginx-*' 'libnginx-mod-*' 2>/dev/null \
             | awk '/install ok installed/{print $1}' | sort -u)
    if [ "${#DEB_PKG_ARR[@]}" -gt 0 ]; then
        DEB_STATE="present"
    else
        DEB_STATE="none"
    fi
}

refresh_sctp_facts() {
    if [ -r /proc/modules ] && grep -q '^sctp[[:space:]]' /proc/modules; then
        SCTP_LOADED="oui"
    else
        SCTP_LOADED="non"
    fi
    if [ -f "$SCTP_CONF" ] && grep -Fxq "$SCTP_LINE" "$SCTP_CONF"; then
        SCTP_CONF_STATE="yes"
    else
        SCTP_CONF_STATE="no"
    fi
    if [ "$SCTP_LOADED" = oui ]; then
        SCTP_FLAG="flagged"
    else
        SCTP_FLAG="no"
    fi
}

# 1.9.5 <= v < 1.30.7  or  1.31.0 <= v < 1.31.9
ver_lt() { [ "$1" != "$2" ] && [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -1)" = "$1" ]; }
is_vulnerable() {
    local v="$1"
    [ -z "$v" ] && return 0
    ver_lt "$v" "1.9.5" && return 1
    ver_lt "$v" "$FIXED_STABLE" && return 0
    ver_lt "$v" "1.31.0" && return 1
    ver_lt "$v" "$FIXED_MAINLINE" && return 0
    return 1
}

debian_backport_fixed() {
    zgrep -qs "$CVE_MAIN" /usr/share/doc/nginx*/changelog.Debian.gz 2>/dev/null
}

add_bin() {
    local r
    [ -n "${1:-}" ] || return 0
    r="$(readlink -f "$1" 2>/dev/null)" || return 0
    [ -f "$r" ] && [ -x "$r" ] && BINS["$r"]=1
}

add_conf() {
    local r
    r="$(readlink -f "$1" 2>/dev/null)" || return 0
    [ -f "$r" ] && CONF["$r"]=1
}

is_3cx_file() {
    case "$1" in
        /var/lib/3cxpbx/*) return 0 ;;
    esac
    [ "$(dpkg -S "$1" 2>/dev/null | cut -d: -f1)" = "3cxpbx" ]
}

inventory_bins() {
    local b v o state run pid
    BINS=()
    pid="$(pgrep -o -x nginx 2>/dev/null || true)"
    RUN_BIN=""
    if [ -n "$pid" ]; then
        RUN_BIN="$(readlink -f "/proc/${pid}/exe" 2>/dev/null || true)"
    fi
    log "Binaire nginx en cours d'execution : ${RUN_BIN:-aucun processus nginx}"
    add_bin "$NGINX_REAL"
    add_bin "$RUN_BIN"
    if [ "${#DEB_PKG_ARR[@]}" -gt 0 ]; then
        while IFS= read -r b; do
            add_bin "$b"
        done < <(dpkg -L "${DEB_PKG_ARR[@]}" 2>/dev/null | grep -E '/s?bin/nginx$' || true)
    fi
    while IFS= read -r b; do
        add_bin "$b"
    done < <(dpkg-divert --list 2>/dev/null | grep -oE '/[^ ]*nginx[^ ]*' || true)
    while IFS= read -r -d '' b; do
        add_bin "$b"
    done < <(find /usr/sbin /usr/local/sbin /usr/bin /var/lib/3cxpbx -xdev -type f -name 'nginx*' -perm -u+x -print0 2>/dev/null)

    dpkg-divert --list 2>/dev/null | grep -i nginx | sed 's/^/      diversion : /' | tee -a "$HOST_LOG" || true

    ANY_VULN=0
    NB_BINS=0
    for b in "${!BINS[@]}"; do
        v="$(nginx_ver_of "$b")"
        [ -n "$v" ] || continue
        NB_BINS=$((NB_BINS + 1))
        o="$(dpkg -S "$b" 2>/dev/null | head -1 | cut -d: -f1)"
        o="${o:-aucun paquet}"
        state="vulnerable"
        if [ "$o" != "3cxpbx" ] && [ "$o" != "aucun paquet" ] && debian_backport_fixed; then
            state="corrige (retroportage Debian)"
        elif ! is_vulnerable "$v"; then
            state="corrige"
        fi
        [ "$state" = "vulnerable" ] && ANY_VULN=1
        run=""
        [ "$b" = "$RUN_BIN" ] && run=" [EN COURS]"
        log "Binaire : $b - nginx $v - paquet $o - $state$run"
    done
    [ "$NB_BINS" -gt 1 ] && log "ATTENTION : ${NB_BINS} binaires nginx sont presents sur ce serveur."

    if [ "$ANY_VULN" -eq 0 ] && [ "$NB_BINS" -gt 0 ]; then
        log "Tous les binaires nginx presents sont corriges : la configuration HTTP/2 est laissee en l'etat."
        SKIP_H2=1
    else
        log "Au moins un binaire nginx vulnerable est present (correctif amont : ${FIXED_STABLE} / ${FIXED_MAINLINE}) : HTTP/2 doit etre desactive."
        SKIP_H2=0
    fi
}

inventory_confs() {
    local f r tag
    CONF=()
    TO_FIX=()
    HTTP2_ACTIVE="no"
    [ -e /etc/nginx/sites-enabled/3cxpbx ] && add_conf /etc/nginx/sites-enabled/3cxpbx
    while IFS= read -r -d '' f; do
        add_conf "$f"
    done < <(find /var/lib/3cxpbx -type f -path '*nginx*' -name '*.conf' -print0 2>/dev/null)
    while IFS= read -r f; do
        r="$(readlink -f "$f" 2>/dev/null)" || continue
        if [ "$ONLY3CX" -eq 0 ] || is_3cx_file "$r"; then
            add_conf "$r"
        fi
    done < <("$NGINX_BIN" -T 2>/dev/null | sed -n 's/^# configuration file \(.*\):$/\1/p')

    if [ "$SKIP_H2" -eq 0 ]; then
        for f in "${!CONF[@]}"; do
            if grep -qE "$H2_RE" "$f"; then
                TO_FIX+=("$f")
                HTTP2_ACTIVE="yes"
                if is_3cx_file "$f"; then tag="3CX"; else tag="autre"; fi
                log "HTTP/2 actif ($tag) : $f"
                grep -nE "$H2_RE" "$f" | sed 's/^/      /' | tee -a "$HOST_LOG" || true
            fi
        done
        [ "${#TO_FIX[@]}" -eq 0 ] && log "Aucun fichier de configuration n'a HTTP/2 active."
    else
        for f in "${!CONF[@]}"; do
            if grep -qE "$H2_RE" "$f"; then
                HTTP2_ACTIVE="yes"
            fi
        done
    fi
}

# Sets DEB_UPG (space-separated package list). In apply mode, runs apt-get update first.
collect_deb_upgrades() {
    local p held inst cand
    DEB_UPG=""
    [ "$DO_DEB_UPG" -eq 1 ] || return 0
    [ "${#DEB_PKG_ARR[@]}" -gt 0 ] || return 0
    held="$(apt-mark showhold 2>/dev/null | grep -E '^(nginx|libnginx-mod)' | tr '\n' ' ' || true)"
    [ -n "$held" ] && log "Paquets nginx bloques (hold), non mis a jour : $held"
    if [ "$MODE" = apply ]; then
        apt-get update -qq >>"$HOST_LOG" 2>&1 || log "ATTENTION : apt-get update a echoue."
    fi
    for p in "${DEB_PKG_ARR[@]}"; do
        case " $held " in
            *" $p "*) continue ;;
        esac
        inst="$(apt-cache policy "$p" 2>/dev/null | awk '/Installed:/{print $2}')"
        cand="$(apt-cache policy "$p" 2>/dev/null | awk '/Candidate:/{print $2}')"
        if [ -n "$cand" ] && [ "$cand" != "(none)" ] && [ "$inst" != "$cand" ]; then
            DEB_UPG="${DEB_UPG} $p"
            log "Mise a jour Debian disponible : $p $inst -> $cand"
        fi
    done
    DEB_UPG="${DEB_UPG# }"
    if [ -z "$DEB_UPG" ]; then
        log "Aucune mise a jour de paquet nginx Debian n'est disponible (correctif Debian pas encore publie ?)."
    fi
}

guess_verify_fqdn() {
    local fqdn
    fqdn="$("$NGINX_BIN" -T 2>/dev/null | grep -E '^[[:space:]]*server_name[[:space:]]' \
        | awk '{gsub(";","",$2); print $2}' | grep -vE '^(_|localhost)$' | head -1 || true)"
    if [ -z "$fqdn" ]; then
        fqdn="${HOST_NAME}"
    fi
    VERIFY_FQDN="$fqdn"
}

local_curl_check() {
    local fqdn ports p hv parts=""
    STILL=0
    guess_verify_fqdn
    fqdn="$VERIFY_FQDN"
    ports="$("$NGINX_BIN" -T 2>/dev/null | grep -E '^[[:space:]]*listen[[:space:]].*[[:space:]]ssl' \
        | awk '{print $2}' | sed 's/;//; s/.*://' | grep -E '^[0-9]+$' | sort -un || true)"
    if [ -z "$ports" ]; then
        LOCAL_CURL="aucun_port_ssl"
        log "Curl local : aucun port SSL trouve dans nginx -T."
        return 0
    fi
    for p in $ports; do
        if [ -n "$fqdn" ]; then
            hv="$(curl -sk --http2 --max-time 5 --resolve "${fqdn}:${p}:127.0.0.1" -o /dev/null \
                -w '%{http_version}' "https://${fqdn}:${p}/" 2>/dev/null || true)"
        else
            hv="$(curl -sk --http2 --max-time 5 -o /dev/null -w '%{http_version}' \
                "https://127.0.0.1:${p}/" 2>/dev/null || true)"
        fi
        [ -n "$hv" ] || hv="vide"
        parts="${parts:+$parts,}${p}=${hv}"
        case "$hv" in
            2)
                if [ "$ANY_VULN" -eq 1 ]; then
                    log "Port ${p} : HTTP/2 TOUJOURS PROPOSE."
                    STILL=1
                else
                    log "Port ${p} : HTTP/2 propose, nginx ${NGINX_VER} est corrige - OK."
                fi
                ;;
            1.1) log "Port ${p} : HTTP/1.1 uniquement - OK." ;;
            *)   log "Port ${p} : pas de reponse locale (${hv}) - verifier depuis l'exterieur." ;;
        esac
    done
    LOCAL_CURL="$parts"
}

write_sctp_conf() {
    refresh_sctp_facts
    if [ "$SCTP_CONF_STATE" = yes ]; then
        return 0
    fi
    if [ -f "$SCTP_CONF" ]; then
        printf '%s\n' "$SCTP_LINE" >> "$SCTP_CONF"
    else
        printf '%s\n' "$SCTP_LINE" > "$SCTP_CONF"
    fi
    refresh_sctp_facts
    [ "$SCTP_CONF_STATE" = yes ]
}

latest_backup_dir() {
    local f latest=""
    for f in "$BACKUP_PREFIX"-*; do
        [ -d "$f" ] || continue
        if [ -z "$latest" ] || [ "$f" -nt "$latest" ]; then
            latest="$f"
        fi
    done
    printf '%s' "$latest"
}

restore_backup_dir() {
    local dir="$1" f
    [ -d "$dir" ] || return 1
    (
        cd "$dir" || exit 1
        find . -type f ! -name 'MANIFEST' ! -path './binary/*' -print0 \
            | while IFS= read -r -d '' f; do
                cp -p "$f" "/${f#./}"
                log "  restaure /${f#./}"
            done
    )
}

rollback_now() {
    local why="${1:-echec de la correction}"
    log "ECHEC : restauration automatique depuis $BACKUP_DIR ($why)."
    if [ -d "$BACKUP_DIR" ]; then
        restore_backup_dir "$BACKUP_DIR" || true
        run_nginx_test >>"$HOST_LOG" 2>&1 && restart_or_reload_nginx >>"$HOST_LOG" 2>&1 || true
    fi
    BAK_USED="$BACKUP_DIR"
    die 1 "ECHEC (configuration restauree)" "$why"
}

# ---------------------------------------------------------------------------
# Modes
# ---------------------------------------------------------------------------
do_check() {
    log "=== Controle nginx2root - ${HOST_NAME} - 3cxpbx ${PBX_VER} - nginx ${NGINX_VER:-?} (${NGINX_REAL}, paquet ${OWNER}) ==="
    log "Paquets nginx Debian installes : ${DEB_PKG_ARR[*]:-aucun}"
    log "Mode CONTROLE (lecture seule). Aucune modification."
    inventory_bins
    inventory_confs
    collect_deb_upgrades
    [ -n "${DEB_UPG:-}" ] && DEB_STATE="update_available"
    local_curl_check
    refresh_sctp_facts
    if [ "${#TO_FIX[@]}" -gt 0 ] || [ "$SCTP_CONF_STATE" = no ] || [ -n "${DEB_UPG:-}" ]; then
        [ "${#TO_FIX[@]}" -gt 0 ] && log "A modifier : HTTP/2 actif dans ${#TO_FIX[@]} fichier(s)."
        [ "$SCTP_CONF_STATE" = no ] && log "A modifier : blocage SCTP absent."
        [ -n "${DEB_UPG:-}" ] && log "A modifier : mise a jour Debian disponible (${DEB_UPG})."
        [ "$SCTP_FLAG" = flagged ] && log "ATTENTION : le module sctp est deja charge ; le blocage ne le decharge pas."
        die 0 "A CORRIGER (lancer avec --apply)"
    fi
    if [ "$SKIP_H2" -eq 1 ]; then
        log "Tous les binaires sont corriges ; HTTP/2 est laisse en l'etat."
    else
        log "Deja corrige : aucune action necessaire."
    fi
    [ "$SCTP_FLAG" = flagged ] && log "ATTENTION : le module sctp est deja charge ; le blocage ne le decharge pas."
    [ "$STILL" -eq 1 ] && log "ATTENTION : le curl local propose encore HTTP/2."
    die 0 "DEJA CORRIGE"
}

do_apply() {
    local bin_sha="" f changed=0
    log "=== Application nginx2root - ${HOST_NAME} - 3cxpbx ${PBX_VER} - nginx ${NGINX_VER:-?} (${NGINX_REAL}, paquet ${OWNER}) ==="
    log "Paquets nginx Debian installes : ${DEB_PKG_ARR[*]:-aucun}"
    inventory_bins
    inventory_confs
    collect_deb_upgrades

    if [ "${#TO_FIX[@]}" -eq 0 ] && [ -z "${DEB_UPG:-}" ] && [ "$SCTP_CONF_STATE" = yes ]; then
        local_curl_check
        refresh_sctp_facts
        [ "$SCTP_FLAG" = flagged ] && log "ATTENTION : le module sctp est deja charge ; le blocage ne le decharge pas."
        die 0 "DEJA CORRIGE"
    fi

    if [ "${#TO_FIX[@]}" -gt 0 ] || [ -n "${DEB_UPG:-}" ]; then
        mkdir -p "$BACKUP_DIR/binary" && chmod 700 "$BACKUP_DIR"
        printf 'host=%s date=%s 3cx=%s nginx=%s owner=%s deb=%s\n' \
            "$HOST_NAME" "$TS" "$PBX_VER" "$NGINX_VER" "$OWNER" "${DEB_PKG_ARR[*]:-}" \
            > "$BACKUP_DIR/MANIFEST"
        cp -p "$NGINX_REAL" "$BACKUP_DIR/binary/nginx"
        bin_sha="$(sha256sum "$NGINX_REAL" | awk '{print $1}')"
        BAK_USED="$BACKUP_DIR"
        changed=1
        log "Sauvegarde creee : $BACKUP_DIR"
    fi

    if [ -n "${DEB_UPG:-}" ]; then
        log "Mise a jour Debian ciblee : $DEB_UPG"
        # shellcheck disable=SC2086
        if DEBIAN_FRONTEND=noninteractive apt-get install -y --only-upgrade \
            -o Dpkg::Options::=--force-confold -o Dpkg::Options::=--force-confdef \
            $DEB_UPG >>"$HOST_LOG" 2>&1; then
            DEB_STATE="upgraded"
        else
            DEB_STATE="upgrade_failed"
            log "ATTENTION : la mise a jour apt a echoue (voir $HOST_LOG). Poursuite de la correction HTTP/2."
        fi
        if [ "$OWNER" = "3cxpbx" ] && [ "$(sha256sum "$NGINX_REAL" | awk '{print $1}')" != "$bin_sha" ]; then
            log "ALERTE : le binaire nginx de 3CX a ete modifie par apt : restauration du binaire 3CX."
            cp -p "$BACKUP_DIR/binary/nginx" "$NGINX_REAL"
            DEB_STATE="bin3cx_restored"
        fi
        if debian_backport_fixed; then
            log "Paquet Debian : ${CVE_MAIN} est present dans le changelog (correctif Debian applique)."
            [ "$DEB_STATE" = "upgraded" ] && DEB_STATE="fixed"
        else
            log "Paquet Debian : ${CVE_MAIN} est absent du changelog (pas encore corrige cote Debian)."
        fi
        NGINX_VER="$(nginx_ver_of "$NGINX_BIN")"
    fi

    for f in "${TO_FIX[@]}"; do
        if [ -L "$f" ]; then
            log "Refus de modifier le lien symbolique $f."
            rollback_now "refus de modifier le lien symbolique $f"
        fi
        # Do not use cp --parents (it failed on some 3CX hosts). Create the
        # destination directory, copy, then compare to confirm the backup.
        if mkdir -p "${BACKUP_DIR}$(dirname "$f")" \
            && cp -p "$f" "${BACKUP_DIR}${f}" \
            && cmp -s "$f" "${BACKUP_DIR}${f}"; then
            :
        else
            rollback_now "sauvegarde impossible pour $f"
        fi
        sed -i -E \
            -e 's/^([[:space:]]*)http2[[:space:]]+on[[:space:]]*;/\1http2 off;/' \
            -e '/^[[:space:]]*listen[[:space:]]/ s/[[:space:]]+http2([[:space:]]|;)/\1/' \
            "$f"
        log "Modifie : $f (sauvegarde : ${BACKUP_DIR}${f})"
    done

    if [ "${#TO_FIX[@]}" -gt 0 ] || [ -n "${DEB_UPG:-}" ]; then
        if ! run_nginx_test >>"$HOST_LOG" 2>&1; then
            rollback_now "nginx -t a echoue, configuration restauree"
        fi
        if ! restart_or_reload_nginx; then
            rollback_now "rechargement/redemarrage nginx a echoue, configuration restauree"
        fi
        sleep 3
        if ! systemctl is-active --quiet nginx; then
            rollback_now "nginx n'est plus actif apres rechargement, configuration restauree"
        fi
        inventory_confs
        if [ "${#TO_FIX[@]}" -gt 0 ]; then
            rollback_now "HTTP/2 n'a pas ete desactive, configuration restauree"
        fi
    fi

    if [ "$SCTP_CONF_STATE" != yes ]; then
        if ! write_sctp_conf; then
            die 1 "ECHEC (configuration restauree)" "impossible d'ecrire $SCTP_CONF"
        fi
        changed=1
        log "Chargement automatique de SCTP bloque ($SCTP_CONF)."
    fi
    refresh_sctp_facts
    if [ "$SCTP_FLAG" = flagged ]; then
        log "ATTENTION : le module sctp est deja charge ; le blocage ne le decharge pas."
    fi

    local_curl_check
    log "Sauvegarde : ${BAK_USED:-aucune}  |  Retour arriere : $0 --rollback ${BAK_USED:-}"
    log "A refaire apres chaque mise a jour 3CX tant que nginx < ${FIXED_STABLE}."

    if [ "$STILL" -eq 1 ]; then
        print_recap
        printf '\nRESULTAT: ECHEC (HTTP/2 toujours propose)\n'
        print_verify_hint
        exit 3
    fi
    if [ "$changed" -eq 0 ]; then
        die 0 "DEJA CORRIGE"
    fi
    die 0 "CORRIGE"
}

do_rollback() {
    local dir
    log "=== Retour arriere nginx2root - ${HOST_NAME} ==="
    if [ -n "$ROLLBACK_DIR" ]; then
        dir="$ROLLBACK_DIR"
    else
        dir="$(latest_backup_dir)"
    fi
    if [ -z "$dir" ] || [ ! -d "$dir" ]; then
        die 1 "ECHEC (configuration restauree)" "aucun dossier de sauvegarde trouve sous ${BACKUP_PREFIX}-*"
    fi
    BAK_USED="$dir"
    log "Restauration des fichiers de configuration depuis $dir."
    log "NOTE : les paquets Debian eventuellement mis a jour ne sont pas retrogrades. Le blocage SCTP est laisse en place."
    if ! restore_backup_dir "$dir"; then
        die 1 "ECHEC (configuration restauree)" "echec de la restauration de $dir"
    fi
    if ! run_nginx_test >>"$HOST_LOG" 2>&1; then
        die 1 "ECHEC (configuration restauree)" "nginx -t a echoue apres restauration de $dir"
    fi
    if ! restart_or_reload_nginx; then
        die 1 "ECHEC (configuration restauree)" "rechargement/redemarrage nginx a echoue apres restauration de $dir"
    fi
    inventory_bins
    inventory_confs
    local_curl_check
    refresh_sctp_facts
    die 0 "RESTAURE"
}

# ---------------------------------------------------------------------------
# Arguments and main
# ---------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help)        usage; exit 0 ;;
        --check)          MODE="check"; shift ;;
        --apply)          MODE="apply"; shift ;;
        --rollback)
            MODE="rollback"
            shift
            if [[ $# -gt 0 && "$1" != -* ]]; then
                ROLLBACK_DIR="$1"
                shift
            fi
            ;;
        --restart)        DO_RESTART=1; shift ;;
        --debian-upgrade) DO_DEB_UPG=1; shift ;;
        --only-3cx)       ONLY3CX=1; shift ;;
        *)
            usage >&2
            echo "ERREUR: option inconnue : $1" >&2
            exit 1
            ;;
    esac
done

[ "$(id -u)" -eq 0 ] || { echo "A lancer en root : sudo bash $(basename "$0")" >&2; exit 1; }

HOST_NAME="$(hostname -f 2>/dev/null || hostname)"
TS="$(date +%Y%m%d-%H%M%S)"
BACKUP_DIR="${BACKUP_PREFIX}-${TS}"
DEB_UPG=""

os="$(uname -s 2>/dev/null || echo unknown)"
if [ "$os" != "Linux" ]; then
    echo "Ce script ne prend en charge que 3CX sur Linux (systeme detecte : $os)." >&2
    printf '\nRESULTAT: NON PRIS EN CHARGE (Windows, uniquement 3CX Linux)\n'
    exit 1
fi

mkdir -p "$(dirname "$HOST_LOG")" 2>/dev/null || true
touch "$HOST_LOG" 2>/dev/null || true

if ! dpkg -s 3cxpbx >/dev/null 2>&1; then
    log "Paquet 3cxpbx absent : ce script est destine aux serveurs 3CX Linux."
    printf '\nRESULTAT: NON 3CX\n'
    exit 2
fi
PBX_VER="$(dpkg-query -W -f='${Version}' 3cxpbx 2>/dev/null || true)"

discover_nginx_bin
if [ -z "$NGINX_BIN" ] || [ ! -x "$NGINX_BIN" ]; then
    log "Binaire nginx introuvable."
    die 1 "ECHEC (configuration restauree)" "binaire nginx introuvable"
fi
NGINX_REAL="$(readlink -f "$NGINX_BIN" 2>/dev/null || true)"
OWNER="$(dpkg -S "$NGINX_REAL" 2>/dev/null | head -1 | cut -d: -f1)"
[ -n "$OWNER" ] || OWNER="inconnu"
NGINX_VER="$(nginx_ver_of "$NGINX_BIN")"

collect_deb_pkgs
refresh_sctp_facts

case "$MODE" in
    check)    do_check ;;
    apply)    do_apply ;;
    rollback) do_rollback ;;
    *)        die 1 "ECHEC (configuration restauree)" "mode inconnu: $MODE" ;;
esac
