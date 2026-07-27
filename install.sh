#!/bin/sh
# attestor installer for Linux and macOS.
#
#   curl -fsSL https://raw.githubusercontent.com/asinadarsh/attestor/main/install.sh | sh
#
# Installs into ~/.attestor/src, puts an `attestor` launcher on your PATH, and
# hands off to `attestor setup`. Nothing needs sudo and nothing is installed
# globally through npm.
#
# When run from a pipe (no terminal) the setup step only prints its plan and
# will not touch your MCP config — re-run `attestor setup` from a terminal, or
# pass ATTESTOR_YES=1 to accept the defaults unattended.
set -eu

REPO="${ATTESTOR_REPO:-https://github.com/asinadarsh/attestor.git}"
SRC="${ATTESTOR_SRC:-$HOME/.attestor/src}"
BIN_DIR="${ATTESTOR_BIN_DIR:-$HOME/.local/bin}"

say() { printf '%s\n' "$*"; }
die() { printf 'attestor: %s\n' "$*" >&2; exit 1; }

need() {
  command -v "$1" >/dev/null 2>&1 || die "$1 is required but not installed"
}

say "attestor installer"

# ---- prerequisites ---------------------------------------------------------
need git
command -v node >/dev/null 2>&1 || die "Node.js 24+ is required — https://nodejs.org/en/download"
NODE_MAJOR=$(node -p 'process.versions.node.split(".")[0]')
[ "$NODE_MAJOR" -ge 24 ] || die "Node $(node -v) is too old — attestor needs Node 24+ (https://nodejs.org/en/download)"
say "  node $(node -v)"

# ---- fetch or update -------------------------------------------------------
if [ -d "$SRC/.git" ]; then
  say "  updating $SRC"
  git -C "$SRC" pull --ff-only --quiet
else
  say "  cloning into $SRC"
  mkdir -p "$(dirname "$SRC")"
  git clone --depth 1 --quiet "$REPO" "$SRC"
fi

# ---- build (npm install runs the build via the prepare script) -------------
say "  installing dependencies"
( cd "$SRC" && npm install --silent --no-fund --no-audit )

CLI="$SRC/packages/attestor/dist/cli.js"
[ -f "$CLI" ] || die "build did not produce $CLI"

# ---- launcher on PATH ------------------------------------------------------
mkdir -p "$BIN_DIR"
cat > "$BIN_DIR/attestor" <<EOF
#!/bin/sh
exec "$(command -v node)" "$CLI" "\$@"
EOF
chmod 755 "$BIN_DIR/attestor"
say "  installed $BIN_DIR/attestor"

case ":$PATH:" in
  *":$BIN_DIR:"*) ;;
  *)
    say ""
    say "  $BIN_DIR is not on your PATH. Add it:"
    say "    echo 'export PATH=\"$BIN_DIR:\$PATH\"' >> ~/.profile && . ~/.profile"
    ;;
esac

# ---- hand off to the wizard ------------------------------------------------
say ""
if [ "${ATTESTOR_YES:-}" = "1" ]; then
  exec "$BIN_DIR/attestor" setup --yes
elif [ -t 0 ]; then
  exec "$BIN_DIR/attestor" setup
else
  # piped install: show what setup would do, but never rewrite a config
  # without someone actually agreeing to it
  "$BIN_DIR/attestor" setup || true
  say ""
  say "  Run 'attestor setup' from a terminal to finish, or re-run with ATTESTOR_YES=1."
fi
