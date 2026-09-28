#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
OUTPUT="${1:-results/actual_ovs_$(. /etc/os-release; echo "${ID}")_v1}"
TRIALS="${2:-30}"
sudo .venv/bin/python scripts/run_ovs_controller_trials.py --output "$OUTPUT" --trials "$TRIALS"
sudo chown -R "$(id -u):$(id -g)" "$OUTPUT"
.venv/bin/python scripts/verify_ovs_controller_trials.py "$OUTPUT"
