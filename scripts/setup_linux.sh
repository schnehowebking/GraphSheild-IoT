#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

if [[ "${1:-}" == "--install-system" ]]; then
  sudo apt-get update
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y openvswitch-switch iproute2 iperf3 tcpdump
fi

for tool in ovs-vsctl ovs-ofctl ip iperf3 tcpdump; do
  command -v "$tool" >/dev/null || { echo "Missing $tool. Run: bash scripts/setup_linux.sh --install-system"; exit 1; }
done

PYTHON_BIN="${PYTHON_BIN:-}"
if [[ -z "$PYTHON_BIN" ]]; then
  if command -v python3.13 >/dev/null; then
    PYTHON_BIN="$(command -v python3.13)"
  elif command -v pyenv >/dev/null && pyenv versions --bare | grep -q '^3\.13'; then
    PYTHON_BIN="$(pyenv prefix 3.13)/bin/python"
  else
    echo "Python 3.13 is required. Install a 3.13 release with pyenv, then rerun with PYTHON_BIN=/path/to/python."
    exit 1
  fi
fi

"$PYTHON_BIN" -c 'import sys; assert sys.version_info[:2] == (3,13), sys.version'
if [[ ! -d .venv ]]; then
  "$PYTHON_BIN" -m venv --copies .venv
fi
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install --only-binary=:all: -r requirements-lock.txt
sudo systemctl enable --now openvswitch-switch
.venv/bin/python scripts/verify_portable_runtime.py
echo "PASS: Linux runtime prepared in $(pwd)/.venv"
