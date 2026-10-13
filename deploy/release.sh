#!/usr/bin/env bash
# Baut ein Release-Paket für Linux x86_64 (glibc 2.31 oder neuer):
# Binary, Weboberfläche und ein install.sh mit eingetragener Version und
# Prüfsumme. Ergebnis unter target/release-paket/<version>/.
#
#   deploy/release.sh 0.1.0-demo1
#
# Braucht cargo-zigbuild und zig im PATH (oder ZIG_DIR auf den Ordner mit
# dem zig-Binary), Node für die Weboberfläche.

set -euo pipefail

VERSION="${1:?Version angeben, z. B. 0.1.0-demo1}"
case "$VERSION" in
    *[!0-9A-Za-z.-]*) echo "Version nur aus Ziffern, Buchstaben, Punkt und Bindestrich" >&2; exit 1 ;;
esac
WURZEL="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ZIEL_TRIPLE=x86_64-unknown-linux-gnu
AUS="$WURZEL/target/release-paket/$VERSION"
NAME="stratum-${VERSION}-linux-x86_64"

if [ -n "${ZIG_DIR:-}" ]; then
    PATH="$ZIG_DIR:$PATH"
fi
command -v zig >/dev/null || { echo "zig fehlt (ZIG_DIR setzen)" >&2; exit 1; }

cd "$WURZEL"
[ -z "$(git status --porcelain)" ] || { echo "Arbeitsbaum nicht sauber, erst committen" >&2; exit 1; }
COMMIT="$(git rev-parse --short HEAD)"

echo "==> Binary ($ZIEL_TRIPLE, glibc 2.31)"
CARGO_TARGET_DIR="$WURZEL/target/linux" cargo zigbuild --release --locked \
    -p stratum-cli --target "${ZIEL_TRIPLE}.2.31"
BIN="$WURZEL/target/linux/$ZIEL_TRIPLE/release/stratum"

echo "==> Weboberfläche"
(cd stratum_frontend && npm ci --silent && npm run build --silent)

echo "==> Paket"
rm -rf "$AUS"
mkdir -p "$AUS/$NAME/bin"
cp "$BIN" "$AUS/$NAME/bin/stratum"
cp -R stratum_frontend/dist "$AUS/$NAME/oberflaeche"
cp LICENSE "$AUS/$NAME/LICENSE"
printf '%s (%s)\n' "$VERSION" "$COMMIT" >"$AUS/$NAME/VERSION"
# bsdtar (macOS) ohne Apple-Metadaten, sonst warnt GNU tar beim Entpacken.
TAR_OPT=()
if tar --version 2>/dev/null | grep -q bsdtar; then
    TAR_OPT=(--no-xattrs --no-mac-metadata)
fi
COPYFILE_DISABLE=1 tar "${TAR_OPT[@]}" -C "$AUS" -czf "$AUS/$NAME.tar.gz" "$NAME"
rm -rf "${AUS:?}/$NAME"
SUMME="$(shasum -a 256 "$AUS/$NAME.tar.gz" | awk '{print $1}')"

sed -e "s/@VERSION@/$VERSION/" -e "s/@ARCHIV_SHA256@/$SUMME/" deploy/install.sh >"$AUS/install.sh"
chmod 755 "$AUS/install.sh"
(cd "$AUS" && shasum -a 256 "$NAME.tar.gz" install.sh >SHA256SUMS)

echo
echo "Fertig: $AUS"
cat "$AUS/SHA256SUMS"
