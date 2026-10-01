#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
echo "OS: $(. /etc/os-release; echo "$PRETTY_NAME")"
uname -r
free -h
df -h .
for tool in ovs-vsctl ovs-ofctl ip iperf3 tcpdump; do command -v "$tool"; done
systemctl is-active openvswitch-switch
sudo ovs-vsctl show
.venv/bin/python --version
.venv/bin/python scripts/verify_portable_runtime.py
