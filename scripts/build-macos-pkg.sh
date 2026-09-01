#!/usr/bin/env bash
# Build a macOS .pkg installer for abracadabra (B4).
# Requires: npm, tsc, pkgbuild, productbuild (Xcode CLT)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERSION="$(node -p "require('$ROOT/package.json').version")"
STAGE="$ROOT/build/pkg-stage"
PKG_ROOT="$STAGE/root"
IDENTIFIER="com.aarcadeghst.abracadabra"
OUT_DIR="$ROOT/build"
PKG_NAME="abracadabra-${VERSION}-macos.pkg"

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "macOS only" >&2
  exit 1
fi

echo "▸ building abracadabra $VERSION"
cd "$ROOT"
npm run build
npm run web:build
node scripts/ensure-platform.js

rm -rf "$STAGE"
mkdir -p "$PKG_ROOT/usr/local/lib/abracadabra" "$PKG_ROOT/usr/local/bin"

rsync -a \
  --exclude node_modules \
  --exclude .git \
  "$ROOT/dist" "$ROOT/web/dist" "$ROOT/assets" "$ROOT/skills" \
  "$ROOT/package.json" "$ROOT/README.md" "$ROOT/AGENTS.md" "$ROOT/LICENSE" \
  "$PKG_ROOT/usr/local/lib/abracadabra/"

cat > "$PKG_ROOT/usr/local/bin/abra" <<'WRAPPER'
#!/usr/bin/env bash
exec node "/usr/local/lib/abracadabra/dist/index.js" "$@"
WRAPPER
chmod 755 "$PKG_ROOT/usr/local/bin/abra"

COMPONENT="$OUT_DIR/abracadabra-component.pkg"
FINAL="$OUT_DIR/$PKG_NAME"

pkgbuild \
  --root "$PKG_ROOT" \
  --identifier "$IDENTIFIER" \
  --version "$VERSION" \
  --install-location "/" \
  "$COMPONENT"

productbuild \
  --package "$COMPONENT" \
  "$FINAL"

echo "✓ $FINAL"
echo "  upload to: cdn.aarcadeghst.com/releases/abracadabra/$VERSION/$PKG_NAME"
