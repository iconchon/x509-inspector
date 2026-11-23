#!/bin/sh
# Install X.509 Inspector for the current user (no root needed).
set -e
DIR="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$HOME/.local/bin" "$HOME/.local/share/applications"
install -m 755 "$DIR/x509-inspector" "$HOME/.local/bin/x509-inspector"
sed "s|^Exec=.*|Exec=$HOME/.local/bin/x509-inspector %F|" "$DIR/x509-inspector.desktop" > "$HOME/.local/share/applications/x509-inspector.desktop"
command -v update-desktop-database >/dev/null 2>&1 && update-desktop-database "$HOME/.local/share/applications" || true
echo "Terpasang: $HOME/.local/bin/x509-inspector"
echo "Butuh runtime WebKitGTK 4.1 (Debian/Ubuntu: sudo apt install libwebkit2gtk-4.1-0)"
