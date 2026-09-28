#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

HOST_ROLE="${1:-}"
case "$HOST_ROLE" in
  kali)
    BASE_SEED=53000
    DEFAULT_OUTPUT="results/actual_ovs_kali_confirmatory_v2"
    ;;
  ubuntu)
    BASE_SEED=63000
    DEFAULT_OUTPUT="results/actual_ovs_ubuntu_confirmatory_v2"
    ;;
  *)
    echo "Usage: bash scripts/run_ovs_confirmatory.sh <kali|ubuntu> [output-directory]" >&2
    exit 2
    ;;
esac

OUTPUT="${2:-$DEFAULT_OUTPUT}"
DEPLOYMENT="deployment_ovs_v2"
REGISTRY="configs/threshold_registry_ovs_v2.json"

test -f "$DEPLOYMENT/model.joblib"
test -f "$DEPLOYMENT/threshold_selection.json"

sudo .venv/bin/python scripts/run_ovs_controller_trials.py \
  --output "$OUTPUT" \
  --trials 30 \
  --base-seed "$BASE_SEED" \
  --max-attackers 4 \
  --deployment-dir "$DEPLOYMENT" \
  --threshold-registry "$REGISTRY" \
  --protocol-role confirmatory

sudo chown -R "$(id -u):$(id -g)" "$OUTPUT"
.venv/bin/python scripts/verify_ovs_controller_trials.py "$OUTPUT" \
  --deployment-dir "$DEPLOYMENT" \
  --threshold-registry "$REGISTRY" \
  --protocol configs/ovs_experiment_protocol_v2.json
