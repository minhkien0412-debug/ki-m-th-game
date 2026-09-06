#!/usr/bin/env bash
#
# CyberArmy V10.7.15 - bootstrap for Kali / Debian / Ubuntu
#
# Creates an isolated virtualenv, installs dependencies, and runs the test
# suite as a self-check. It never contacts a target - it only sets the tool up.
#
# Usage:
#   ./setup.sh            # runtime deps (requirements.txt) + unittest self-check
#   ./setup.sh --dev      # tested/pinned deps (requirements-dev.txt) + pytest
#   ./setup.sh --apt      # first apt-get the system packages (needs sudo)
#   ./setup.sh --no-test  # skip the self-check
#
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_DIR="${REPO_DIR}/CyberArmyV10.7.15"
VENV_DIR="${REPO_DIR}/.venv"
DEV=0
RUN_TESTS=1
DO_APT=0

for arg in "$@"; do
  case "$arg" in
    --dev) DEV=1 ;;
    --no-test) RUN_TESTS=0 ;;
    --apt) DO_APT=1 ;;
    -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "Unknown option: $arg" >&2; exit 2 ;;
  esac
done

log() { printf '\033[1;36m[setup]\033[0m %s\n' "$*"; }
die() { printf '\033[1;31m[setup] ERROR:\033[0m %s\n' "$*" >&2; exit 1; }

[ -d "$APP_DIR" ] || die "Expected app directory not found: $APP_DIR"

if [ "$DO_APT" -eq 1 ]; then
  log "Installing system packages via apt (sudo)…"
  sudo apt-get update
  # build-essential + libxml2/libxslt headers cover a source build of lxml when
  # no wheel is available; python3-venv/pip are needed on a minimal Kali image.
  sudo apt-get install -y python3 python3-venv python3-pip \
      build-essential libxml2-dev libxslt1-dev
else
  log "Skipping apt. If venv/pip or lxml build fails, re-run with --apt, or:"
  log "  sudo apt-get install -y python3 python3-venv python3-pip build-essential libxml2-dev libxslt1-dev"
fi

command -v python3 >/dev/null 2>&1 || die "python3 not found (install it or run with --apt)"

PY_VER="$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
log "Python ${PY_VER} detected"
python3 -c 'import sys; raise SystemExit(0 if sys.version_info[:2] >= (3, 9) else 1)' \
  || die "Python 3.9+ required (found ${PY_VER})"

if [ ! -d "$VENV_DIR" ]; then
  log "Creating virtualenv at ${VENV_DIR}"
  python3 -m venv "$VENV_DIR" || die "venv creation failed (try: ./setup.sh --apt)"
fi
# shellcheck disable=SC1091
source "${VENV_DIR}/bin/activate"

log "Upgrading pip"
python -m pip install --quiet --upgrade pip

cd "$APP_DIR"
if [ "$DEV" -eq 1 ]; then
  log "Installing pinned dev dependencies (requirements-dev.txt)"
  python -m pip install -r requirements-dev.txt
else
  log "Installing runtime dependencies (requirements.txt)"
  python -m pip install -r requirements.txt
fi

log "Smoke check: $(python command_center.py --version)"

if [ "$RUN_TESTS" -eq 1 ]; then
  if [ "$DEV" -eq 1 ]; then
    log "Running test suite with pytest"
    python -m pytest -q
  else
    log "Running test suite with unittest"
    python -m unittest discover -s tests
  fi
else
  log "Skipping self-check (--no-test)"
fi

cat <<EOF

$(printf '\033[1;32m[setup] CyberArmy is ready.\033[0m')

Next steps:
  source ${VENV_DIR}/bin/activate
  cd ${APP_DIR}
  python command_center.py --config config.yaml --validate

Reminder: every active mode is fail-closed. Only test systems you are
explicitly authorized to test, and configure the relevant profile
(hackerone / local_lab / console_lab / integrity) before use.
EOF
