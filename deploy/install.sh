#!/usr/bin/env bash
# Installiert stratum im Demo-Betrieb unter WSL2 (Ubuntu oder Debian).
#
# Lädt das fertig gebaute Release (Binary und Weboberfläche), richtet
# PostgreSQL, YARA, nslookup, whois und prlimit ein, startet den Server und
# prüft am Ende alles einmal durch. Der Server lauscht nur auf 127.0.0.1;
# Windows erreicht ihn über die Localhost-Weiterleitung von WSL2.
#
# Aufruf als normaler Benutzer (nicht root), sudo wird abgefragt:
#   bash install.sh
#
# Demo-Betrieb: Anmeldung superadmin / superadmin, nicht für echte Fälle.

set -euo pipefail

VERSION="@VERSION@"
ARCHIV_SHA256="@ARCHIV_SHA256@"
REPO="yalmn/stratum-releases"
ARCHIV="stratum-${VERSION}-linux-x86_64.tar.gz"
PG_VERSION=17
PG_MINDESTENS=15
YARA_VERSION=4.5.5
YARA_SHA256=d38e30fd9c1e1c7921d1c4568262d94f5c2d6b5da139fe49572a43ffbc5c53f6
PORT="${STRATUM_PORT:-8080}"

ZIEL=/opt/stratum
KONFIG_DIR=/etc/stratum
DATEN="$HOME/stratum"

rot() { printf '\033[31m%s\033[0m\n' "$*"; }
gruen() { printf '\033[32m%s\033[0m\n' "$*"; }
gelb() { printf '\033[33m%s\033[0m\n' "$*"; }
schritt() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
abbruch() {
    rot "[!] $*"
    exit 1
}

# ---------------------------------------------------------------- Vorprüfung

schritt "Vorprüfung"
[ "$(id -u)" -ne 0 ] || abbruch "Bitte als normaler Benutzer starten, nicht als root (sudo wird bei Bedarf abgefragt)."
[ "$(uname -m)" = "x86_64" ] || abbruch "Nur x86_64 wird unterstützt, gefunden: $(uname -m)."
case "$VERSION" in @*) abbruch "Dieses install.sh stammt nicht aus einem Release (Version fehlt)." ;; esac

[ -r /etc/os-release ] || abbruch "/etc/os-release fehlt, Distribution nicht erkennbar."
# shellcheck disable=SC1091
. /etc/os-release
DISTRO="${ID:-unbekannt}"
CODENAME="${VERSION_CODENAME:-}"
case " $DISTRO ${ID_LIKE:-} " in
    *" ubuntu "* | *" debian "*) ;;
    *) abbruch "Distribution \"${PRETTY_NAME:-$DISTRO}\" wird nicht unterstützt. Unter Windows in PowerShell: wsl --install -d Ubuntu-24.04" ;;
esac
[ -n "$CODENAME" ] || abbruch "Codename der Distribution fehlt in /etc/os-release."
echo "Distribution: ${PRETTY_NAME:-$DISTRO}"

if grep -qi microsoft /proc/sys/kernel/osrelease 2>/dev/null; then
    echo "WSL: ja (${WSL_DISTRO_NAME:-Name unbekannt})"
else
    gelb "Hinweis: kein WSL erkannt. Die Installation läuft trotzdem, der Zugriff dann über http://127.0.0.1:${PORT}/ auf diesem Rechner."
fi

GLIBC="$(getconf GNU_LIBC_VERSION 2>/dev/null | awk '{print $2}')"
if [ -z "$GLIBC" ] || [ "$(printf '%s\n2.31\n' "$GLIBC" | sort -V | head -1)" != "2.31" ]; then
    abbruch "glibc 2.31 oder neuer nötig, gefunden: ${GLIBC:-keine}."
fi

if [ "$(ps -p 1 -o comm= 2>/dev/null)" = "systemd" ]; then
    echo "systemd: aktiv"
else
    echo "systemd: nicht aktiv (kein Problem, Dienste werden direkt gestartet)"
fi

sudo -v || abbruch "sudo ist nötig."
# sudo während langer Schritte (YARA bauen) wach halten.
while true; do
    sudo -n true
    sleep 50
done 2>/dev/null &
SUDO_WACH=$!
TMP="$(mktemp -d)"
trap 'kill "$SUDO_WACH" 2>/dev/null || true; rm -rf "$TMP"' EXIT

# ------------------------------------------------------------ Grundpakete

schritt "Grundpakete"
export DEBIAN_FRONTEND=noninteractive
sudo apt-get update -q
sudo apt-get install -y -q ca-certificates curl gnupg openssl tar util-linux bind9-dnsutils whois postgresql-common

# ------------------------------------------------------------- PostgreSQL

schritt "PostgreSQL ${PG_VERSION}"
pg_mit_pgdg() {
    sudo install -d /usr/share/postgresql-common/pgdg
    sudo curl -fsSL -o /usr/share/postgresql-common/pgdg/apt.postgresql.org.asc \
        https://www.postgresql.org/media/keys/ACCC4CF8.asc
    echo "deb [signed-by=/usr/share/postgresql-common/pgdg/apt.postgresql.org.asc] https://apt.postgresql.org/pub/repos/apt ${CODENAME}-pgdg main" |
        sudo tee /etc/apt/sources.list.d/pgdg.list >/dev/null
    sudo apt-get update -q && sudo apt-get install -y -q "postgresql-${PG_VERSION}"
}
if [ -d "/usr/lib/postgresql/${PG_VERSION}" ]; then
    echo "bereits installiert"
elif ! pg_mit_pgdg; then
    gelb "PostgreSQL ${PG_VERSION} aus apt.postgresql.org nicht installierbar, nehme die Version der Distribution."
    sudo rm -f /etc/apt/sources.list.d/pgdg.list
    sudo apt-get update -q
    sudo apt-get install -y -q postgresql
fi
PG_MAJOR="$(ls /usr/lib/postgresql | sort -V | tail -1)"
[ "${PG_MAJOR:-0}" -ge "$PG_MINDESTENS" ] || abbruch "PostgreSQL ${PG_MINDESTENS} oder neuer nötig, gefunden: ${PG_MAJOR:-keine}."

if ! pg_lsclusters -h | awk -v v="$PG_MAJOR" '$1 == v && $2 == "main"' | grep -q .; then
    sudo pg_createcluster "$PG_MAJOR" main
fi
sudo service postgresql start >/dev/null 2>&1 || true
sudo pg_ctlcluster "$PG_MAJOR" main start 2>/dev/null || true
PG_PORT="$(pg_lsclusters -h | awk -v v="$PG_MAJOR" '$1 == v && $2 == "main" {print $3}')"
for _ in $(seq 1 30); do
    pg_isready -q -h 127.0.0.1 -p "$PG_PORT" && break
    sleep 1
done
pg_isready -q -h 127.0.0.1 -p "$PG_PORT" || abbruch "PostgreSQL ${PG_MAJOR} antwortet nicht auf Port ${PG_PORT}."
echo "PostgreSQL ${PG_MAJOR} läuft auf 127.0.0.1:${PG_PORT}"

# Konto und Datenbank. Das Passwort bleibt bei erneuter Installation gleich.
sudo install -d -m 755 "$KONFIG_DIR"
if ! sudo test -s "$KONFIG_DIR/db_passwort"; then
    openssl rand -hex 24 | sudo tee "$KONFIG_DIR/db_passwort" >/dev/null
fi
sudo chown "$(id -un)": "$KONFIG_DIR/db_passwort"
sudo chmod 600 "$KONFIG_DIR/db_passwort"
DB_PW="$(cat "$KONFIG_DIR/db_passwort")"
# stratum legt bei der ersten Migration die Rolle stratum_app an und tritt ihr
# bei; dafür CREATEROLE, kein Superuser.
# Aus / heraus, sonst warnt psql über das für postgres unlesbare Verzeichnis.
(cd / && sudo -u postgres psql -q -p "$PG_PORT" -v ON_ERROR_STOP=1 -v pw="$DB_PW") <<'SQL' >/dev/null
SELECT 'CREATE ROLE stratum LOGIN CREATEROLE'
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'stratum') \gexec
ALTER ROLE stratum WITH LOGIN CREATEROLE PASSWORD :'pw';
SELECT 'CREATE DATABASE stratum OWNER stratum'
WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = 'stratum') \gexec
SQL
unset DB_PW
echo "Datenbank stratum bereit"

# ------------------------------------------------------------------- YARA

schritt "YARA ${YARA_VERSION%.*} oder neuer (Version 4)"
yara_passt() {
    local v
    v="$(/usr/bin/yara --version 2>/dev/null || true)"
    case "$v" in
        4.*) [ "$(printf '%s\n4.5.0\n' "$v" | sort -V | head -1)" = "4.5.0" ] ;;
        *) return 1 ;;
    esac
}
if ! yara_passt; then
    KANDIDAT="$(apt-cache policy yara 2>/dev/null | awk '/Candidate:/ {print $2}')"
    if [ -n "$KANDIDAT" ] && [ "$KANDIDAT" != "(none)" ] &&
        [ "$(printf '%s\n4.5.0\n' "${KANDIDAT#*:}" | sort -V | head -1)" = "4.5.0" ] &&
        [ "$(printf '%s\n5\n' "${KANDIDAT#*:}" | sort -V | head -1)" != "5" ]; then
        sudo apt-get install -y -q yara
    else
        echo "Paketquelle bietet ${KANDIDAT:-kein yara}, baue YARA ${YARA_VERSION} aus dem Quelltext"
        sudo apt-get install -y -q build-essential automake libtool pkg-config libssl-dev
        curl -fsSL -o "$TMP/yara.tar.gz" "https://github.com/VirusTotal/yara/archive/refs/tags/v${YARA_VERSION}.tar.gz"
        echo "${YARA_SHA256}  $TMP/yara.tar.gz" | sha256sum -c --quiet - ||
            abbruch "Prüfsumme des YARA-Quelltexts stimmt nicht."
        tar -xzf "$TMP/yara.tar.gz" -C "$TMP"
        (
            cd "$TMP/yara-${YARA_VERSION}"
            ./bootstrap.sh >/dev/null
            ./configure --prefix=/usr >/dev/null
            make -j"$(nproc)" >/dev/null
            sudo make install >/dev/null
        )
        sudo ldconfig
    fi
fi
yara_passt || abbruch "YARA 4.5 oder neuer (Version 4) unter /usr/bin/yara fehlt."
echo "YARA $(/usr/bin/yara --version)"

# ---------------------------------------------------------------- stratum

schritt "stratum ${VERSION}"
HIER="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "$HIER/$ARCHIV" ]; then
    echo "nutze vorhandenes Archiv $HIER/$ARCHIV"
    cp "$HIER/$ARCHIV" "$TMP/$ARCHIV"
else
    curl -fL --progress-bar -o "$TMP/$ARCHIV" \
        "https://github.com/${REPO}/releases/download/v${VERSION}/${ARCHIV}"
fi
echo "${ARCHIV_SHA256}  $TMP/$ARCHIV" | sha256sum -c --quiet - ||
    abbruch "Prüfsumme des stratum-Archivs stimmt nicht."

# Läuft schon ein Server, zuerst beenden.
if command -v stratum-demo >/dev/null 2>&1; then
    stratum-demo stop >/dev/null 2>&1 || true
fi
sudo rm -rf "$ZIEL/$VERSION"
sudo install -d "$ZIEL/$VERSION"
sudo tar -xzf "$TMP/$ARCHIV" -C "$ZIEL/$VERSION" --strip-components=1 --no-same-owner
sudo ln -sfn "$ZIEL/$VERSION" "$ZIEL/aktuell"
sudo ln -sfn "$ZIEL/aktuell/bin/stratum" /usr/local/bin/stratum
[ -f "$ZIEL/aktuell/oberflaeche/index.html" ] || abbruch "Weboberfläche fehlt im Archiv."

install -d -m 700 "$DATEN" "$DATEN/faelle" "$DATEN/faelle/DEMO-001" "$DATEN/jobs" "$DATEN/log"
sudo tee "$KONFIG_DIR/stratum.toml" >/dev/null <<EOF
# stratum, Demo-Installation (install.sh ${VERSION})
[datenbank]
url = "postgres://stratum@127.0.0.1:${PG_PORT}/stratum"
passwort_datei = "${KONFIG_DIR}/db_passwort"

[jobs]
ausgabe = "${DATEN}/jobs"

[server]
oberflaeche = "${ZIEL}/aktuell/oberflaeche"
EOF
sudo chmod 644 "$KONFIG_DIR/stratum.toml"

# Steuerskript: start, stop, status, log.
sudo tee /usr/local/bin/stratum-demo >/dev/null <<EOF
#!/usr/bin/env bash
# Startet und stoppt stratum im Demo-Betrieb (angelegt von install.sh).
set -uo pipefail
export STRATUM_KONFIG=${KONFIG_DIR}/stratum.toml
PORT=${PORT}
PG_MAJOR=${PG_MAJOR}
PG_PORT=${PG_PORT}
DATEN=${DATEN}
EOF
sudo tee -a /usr/local/bin/stratum-demo >/dev/null <<'EOF'
PID="$DATEN/log/server.pid"
LOG="$DATEN/log/server.log"

laeuft() { [ -f "$PID" ] && kill -0 "$(cat "$PID")" 2>/dev/null; }
bereit() { curl -fsS "http://127.0.0.1:$PORT/api/v1/status" 2>/dev/null; }

case "${1:-}" in
    start)
        if ! pg_isready -q -h 127.0.0.1 -p "$PG_PORT"; then
            echo "starte PostgreSQL $PG_MAJOR (sudo) ..."
            sudo pg_ctlcluster "$PG_MAJOR" main start || sudo service postgresql start
            for _ in $(seq 1 30); do pg_isready -q -h 127.0.0.1 -p "$PG_PORT" && break; sleep 1; done
        fi
        pg_isready -q -h 127.0.0.1 -p "$PG_PORT" || { echo "PostgreSQL antwortet nicht"; exit 1; }
        if laeuft; then
            echo "stratum läuft bereits (PID $(cat "$PID"))"
            exit 0
        fi
        nohup stratum server --worker --demo --adresse "127.0.0.1:$PORT" >>"$LOG" 2>&1 &
        echo $! >"$PID"
        for _ in $(seq 1 60); do bereit >/dev/null && break; sleep 1; laeuft || break; done
        if bereit >/dev/null; then
            echo "stratum läuft: http://localhost:$PORT/  (Anmeldung superadmin / superadmin)"
        else
            echo "stratum startet nicht, letzte Zeilen aus $LOG:"
            tail -n 20 "$LOG"
            exit 1
        fi
        ;;
    stop)
        if laeuft; then
            kill -INT "$(cat "$PID")"
            for _ in $(seq 1 30); do laeuft || break; sleep 1; done
            laeuft && kill "$(cat "$PID")"
        fi
        rm -f "$PID"
        echo "stratum gestoppt"
        ;;
    status)
        if laeuft && bereit >/dev/null; then
            echo "stratum läuft (PID $(cat "$PID")), http://localhost:$PORT/"
        else
            echo "stratum läuft nicht"
            exit 1
        fi
        ;;
    log)
        tail -n 100 -f "$LOG"
        ;;
    *)
        echo "Aufruf: stratum-demo start|stop|status|log"
        exit 2
        ;;
esac
EOF
sudo chmod 755 /usr/local/bin/stratum-demo

# ----------------------------------------------------------------- Start

schritt "Start"
stratum-demo start

# ----------------------------------------------------------- Healthcheck

schritt "Healthcheck"
FEHLER=0
pruefe() {
    local name="$1"
    shift
    if "$@" >/dev/null 2>&1; then
        gruen "  [ok]     $name"
    else
        rot "  [FEHLER] $name"
        FEHLER=$((FEHLER + 1))
    fi
}
BASIS="http://127.0.0.1:${PORT}"
STATUS="$(curl -fsS "$BASIS/api/v1/status" 2>/dev/null || true)"
pruefe "Binary ausführbar" stratum --help
pruefe "PostgreSQL ${PG_MAJOR} erreichbar" pg_isready -q -h 127.0.0.1 -p "$PG_PORT"
pruefe "API und Datenbank (/api/v1/status)" test -n "$STATUS"
pruefe "Demo-Betrieb aktiv" grep -q '"demo":true' <<<"$STATUS"
pruefe "Weboberfläche ausgeliefert" sh -c "curl -fsS '$BASIS/' | grep -q 'id=\"wurzel\"'"
TOKEN="$(curl -fsS -X POST -H 'Content-Type: application/json' \
    -d '{"name":"superadmin","passwort":"superadmin"}' "$BASIS/api/v1/sitzung" 2>/dev/null |
    sed -n 's/.*"token":"\([^"]*\)".*/\1/p')"
pruefe "Anmeldung superadmin / superadmin" test -n "$TOKEN"
ICH="$(curl -fsS -H "Authorization: Bearer $TOKEN" "$BASIS/api/v1/ich" 2>/dev/null || true)"
pruefe "kein Pflichtwechsel des Passworts" grep -q '"password_change_required":false' <<<"$ICH"
pruefe "Audit-Kette intakt" sh -c "curl -fsS -X POST -H 'Authorization: Bearer $TOKEN' '$BASIS/api/v1/audit/pruefen' | grep -q '\"fehler_gesamt\":0'"
[ -n "$TOKEN" ] && curl -fsS -X DELETE -H "Authorization: Bearer $TOKEN" "$BASIS/api/v1/sitzung" >/dev/null 2>&1 || true
pruefe "YARA $(/usr/bin/yara --version 2>/dev/null)" yara_passt
pruefe "nslookup (DNS)" /usr/bin/nslookup -version
pruefe "whois" /usr/bin/whois --version
pruefe "prlimit" /usr/bin/prlimit --version

DISTRO_NAME="${WSL_DISTRO_NAME:-<Distribution>}"
WIN_PFAD="\\\\wsl.localhost\\${DISTRO_NAME}${DATEN//\//\\}\\faelle"

echo
if [ "$FEHLER" -eq 0 ]; then
    gruen "Alle Prüfungen bestanden."
else
    rot "$FEHLER Prüfung(en) fehlgeschlagen. Log: $DATEN/log/server.log"
fi
cat <<EOF

  ==============================================================
    STRATUM ${VERSION}  DEMO-BETRIEB
    Nur zur Vorführung, nicht für echte Fallarbeit.
  ==============================================================

  Zugriff im Windows-Browser:  http://localhost:${PORT}/
  Anmeldung:                   superadmin / superadmin

  Image bereitstellen:
    1. Im Windows-Explorer öffnen:  ${WIN_PFAD}
    2. Das Image in den Ordner DEMO-001 kopieren (für weitere Fälle
       je Fall einen eigenen Ordner anlegen) (nicht von C:\\ aus analysieren, das ist
       über WSL deutlich langsamer).
    3. In stratum den Fall anlegen, Fallordner:
         ${DATEN}/faelle/DEMO-001
       dann unter Evidence das Image auswählen und analysieren.

  Steuerung in WSL:  stratum-demo start | stop | status | log
  Das WSL-Fenster während der Demo offen lassen. Nach einem Neustart
  von Windows oder WSL:  stratum-demo start

EOF
[ "$FEHLER" -eq 0 ]
